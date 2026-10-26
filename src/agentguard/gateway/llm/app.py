"""OpenAI- and Anthropic-compatible LLM API gateway.

Point an SDK's base URL at the gateway and add ``X-AgentGuard-Key``:

    OpenAI(base_url="https://agentguard.internal/v1", default_headers={"X-AgentGuard-Key": key})
    Anthropic(base_url="https://agentguard.internal", default_headers={"X-AgentGuard-Key": key})

Endpoints: ``POST /v1/chat/completions`` (incl. streaming), ``POST /v1/responses`` (non-streaming),
``POST /v1/messages`` (incl. streaming), ``GET /v1/models``. Upstream credentials
(``Authorization`` / ``x-api-key``) are forwarded to the provider and never logged.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections.abc import AsyncIterator, Mapping
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from agentguard import __version__
from agentguard.adapters import SeenSet, block_notice
from agentguard.adapters import anthropic_messages as am
from agentguard.adapters import openai_chat as oc
from agentguard.adapters import openai_responses as orp
from agentguard.core.approvals import ApprovalStatus, Approver, await_for
from agentguard.core.engine import Engine, GuardContext
from agentguard.core.provenance import ProvenanceLedger
from agentguard.core.types import Action, Decision, Reason, ToolCall
from agentguard.gateway.auth import Principal
from agentguard.gateway.config import LlmConfig

log = logging.getLogger(__name__)
MAX_BODY = 32 * 1024 * 1024
OPENAI_FORWARD = ("authorization", "openai-organization", "openai-project", "openai-beta")
ANTHROPIC_FORWARD = ("x-api-key", "authorization", "anthropic-version", "anthropic-beta")


def _session_id(principal: Principal, request: Request, body: Mapping[str, Any]) -> str:
    if sid := request.headers.get("x-agentguard-session"):
        return sid[:128]
    msgs = body.get("messages") or body.get("input") or []
    first = (
        next((m for m in msgs if isinstance(m, Mapping) and m.get("role") == "user"), None)
        if isinstance(msgs, list)
        else msgs
    )
    seed = json.dumps([principal.tenant_id, body.get("system"), first], default=str, sort_keys=True)
    return "ses_" + hashlib.sha256(seed.encode()).hexdigest()[:24]


class LlmGateway:
    def __init__(
        self,
        engine: Engine,
        auth: Any,
        cfg: LlmConfig,
        *,
        approver: Approver | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.engine = engine
        self.auth = auth
        self.cfg = cfg
        self.approver = approver
        self.client = client or httpx.AsyncClient(timeout=httpx.Timeout(cfg.timeout_seconds, connect=10.0))
        self.seen = SeenSet()

    # ------------------------------------------------------------------ helpers

    def _ctx(self, principal: Principal, sid: str) -> GuardContext:
        return GuardContext(ProvenanceLedger(sid), principal.tenant_id, principal.project_id, source="llm-gateway")

    async def _evaluate(self, ctx: GuardContext, call: ToolCall) -> Decision:
        d = await asyncio.to_thread(self.engine.evaluate, ctx, call)
        if d.action is not Action.REQUIRE_APPROVAL:
            return d
        if self.approver is None:
            d.action = Action.BLOCK
            d.reasons.append(Reason("NO_APPROVER", "approval required but no approver is configured"))
            return d
        timeout = self.engine.policy.settings.approvals.timeout_seconds
        d.approval_id = await asyncio.to_thread(self.approver.request, d, ctx, timeout)
        status = await await_for(self.approver, d.approval_id, timeout)
        approved = status is ApprovalStatus.APPROVED or (
            status is ApprovalStatus.EXPIRED and self.engine.policy.settings.approvals.on_timeout == "ALLOW"
        )
        d.action = Action.ALLOW if approved else Action.BLOCK
        d.reasons.append(Reason("APPROVAL", f"approval {status.value}", action=d.action))
        return d

    @staticmethod
    def _headers(request: Request, names: tuple[str, ...]) -> dict[str, str]:
        out = {k: v for k, v in request.headers.items() if k.lower() in names}
        out["content-type"] = "application/json"
        return out

    def _strict_error(self, decisions: list[Decision], provider: str) -> JSONResponse:
        blocked = [d for d in decisions if not d.allowed]
        msg = block_notice(blocked)
        detail = [{"tool": d.tool, "event_id": d.event_id, "reasons": [r.message for r in d.reasons]} for d in blocked]
        if provider == "anthropic":
            body: dict[str, Any] = {
                "type": "error",
                "error": {"type": "permission_error", "message": msg},
                "agentguard": detail,
            }
        else:
            body = {
                "error": {"message": msg, "type": "agentguard_blocked", "code": "tool_call_blocked"},
                "agentguard": detail,
            }
        return JSONResponse(body, status_code=403)

    @staticmethod
    def _meta_headers(decisions: list[Decision], start: float, upstream_ms: float) -> dict[str, str]:
        worst = Action.most_severe([d.action for d in decisions]) if decisions else Action.ALLOW
        overhead = (time.perf_counter() - start) * 1000 - upstream_ms
        h = {"x-agentguard-action": worst.value, "x-agentguard-overhead-ms": f"{max(overhead, 0):.2f}"}
        if decisions:
            h["x-agentguard-event-ids"] = ",".join(d.event_id for d in decisions)[:2000]
        return h

    async def _principal(self, request: Request) -> Principal | None:
        return await self.auth.authenticate(request.headers)  # type: ignore[no-any-return]

    async def _body(self, request: Request) -> dict[str, Any] | JSONResponse:
        raw = await request.body()
        if len(raw) > MAX_BODY:
            return JSONResponse({"error": {"message": "request too large"}}, status_code=413)
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            return JSONResponse({"error": {"message": "invalid JSON"}}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": {"message": "body must be a JSON object"}}, status_code=400)
        return body

    # ------------------------------------------------------------------ OpenAI chat completions

    async def chat_completions(self, request: Request) -> Response:
        start = time.perf_counter()
        principal = await self._principal(request)
        if principal is None:
            return JSONResponse(
                {"error": {"message": "invalid or missing X-AgentGuard-Key", "type": "unauthorized"}},
                status_code=401,
            )
        body = await self._body(request)
        if isinstance(body, JSONResponse):
            return body
        ctx = self._ctx(principal, _session_id(principal, request, body))
        messages = body.get("messages") or []
        results = await asyncio.to_thread(oc.ingest_messages, self.engine, ctx, messages, self.seen)
        body["messages"] = oc.sanitize_request(messages, results)
        url = f"{self.cfg.openai_base_url.rstrip('/')}/v1/chat/completions"
        headers = self._headers(request, OPENAI_FORWARD)
        t_up = time.perf_counter()

        if body.get("stream"):
            req = self.client.build_request("POST", url, headers=headers, json=body)
            resp = await self.client.send(req, stream=True)
            if resp.status_code != 200:
                raw = await resp.aread()
                await resp.aclose()
                return Response(raw, status_code=resp.status_code, media_type=resp.headers.get("content-type"))
            return StreamingResponse(
                self._openai_stream(resp, ctx),
                media_type="text/event-stream",
                headers={"x-agentguard-version": __version__},
            )

        resp = await self.client.post(url, headers=headers, json=body)
        upstream_ms = (time.perf_counter() - t_up) * 1000
        if resp.status_code != 200:
            return Response(resp.content, status_code=resp.status_code, media_type=resp.headers.get("content-type"))
        data = resp.json()
        decisions = {(ci, ti): await self._evaluate(ctx, c) for ci, ti, c in oc.response_tool_calls(data)}
        if any(not d.allowed for d in decisions.values()):
            if self.cfg.strict:
                return self._strict_error(list(decisions.values()), "openai")
            data = oc.rewrite_response(data, decisions)
        elif any(d.redacted_arguments is not None for d in decisions.values()):
            data = oc.rewrite_response(data, decisions)
        return JSONResponse(data, headers=self._meta_headers(list(decisions.values()), start, upstream_ms))

    async def _openai_stream(self, resp: httpx.Response, ctx: GuardContext) -> AsyncIterator[bytes]:
        buf = oc.StreamToolBuffer()
        held: list[dict[str, Any]] = []
        finished = False
        try:
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    if held:
                        for out in await self._openai_tail(held, buf, ctx, None):
                            yield out
                        held = []
                    yield b"data: [DONE]\n\n"
                    continue
                try:
                    chunk = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                is_final = any(c.get("finish_reason") for c in chunk.get("choices") or [])
                if finished:
                    yield f"data: {json.dumps(chunk)}\n\n".encode()
                    continue
                if buf.add_chunk(chunk) and not is_final:
                    held.append(chunk)
                    continue
                if is_final:
                    finished = True
                    for out in await self._openai_tail(held, buf, ctx, chunk):
                        yield out
                    held = []
                    continue
                yield f"data: {json.dumps(chunk)}\n\n".encode()
        finally:
            await resp.aclose()

    async def _openai_tail(
        self,
        held: list[dict[str, Any]],
        buf: oc.StreamToolBuffer,
        ctx: GuardContext,
        final: dict[str, Any] | None,
    ) -> list[bytes]:
        decisions = {k: await self._evaluate(ctx, c) for k, c in buf.tool_calls()}
        blocked = {k for k, d in decisions.items() if not d.allowed}
        out = []
        for chunk in held:
            f = oc.filter_chunk(chunk, blocked)
            if f is not None:
                out.append(f"data: {json.dumps(f)}\n\n".encode())
        if final is not None:
            if blocked:
                notice = block_notice([decisions[k] for k in sorted(blocked)])
                for choice in final.get("choices") or []:
                    ci = int(choice.get("index", 0))
                    if any(k[0] == ci for k in blocked):
                        choice.setdefault("delta", {})["content"] = "\n\n" + notice
                        if not any(k[0] == ci and k not in blocked for k in buf.calls):
                            choice["finish_reason"] = "stop"
            out.append(f"data: {json.dumps(final)}\n\n".encode())
        return out

    # ------------------------------------------------------------------ OpenAI responses

    async def responses(self, request: Request) -> Response:
        start = time.perf_counter()
        principal = await self._principal(request)
        if principal is None:
            return JSONResponse({"error": {"message": "invalid or missing X-AgentGuard-Key"}}, status_code=401)
        body = await self._body(request)
        if isinstance(body, JSONResponse):
            return body
        if body.get("stream"):
            return JSONResponse(
                {
                    "error": {
                        "message": "AgentGuard does not support streaming for /v1/responses yet; set stream=false",
                        "type": "invalid_request_error",
                    }
                },
                status_code=400,
            )
        if body.get("previous_response_id"):
            # The gateway cannot see server-side conversation state, so provenance would be incomplete.
            return JSONResponse(
                {
                    "error": {
                        "message": "AgentGuard requires the full input; previous_response_id/store-based "
                        "conversations are not supported",
                        "type": "invalid_request_error",
                    }
                },
                status_code=400,
            )
        ctx = self._ctx(principal, _session_id(principal, request, body))
        results = await asyncio.to_thread(
            orp.ingest, self.engine, ctx, body.get("instructions"), body.get("input"), self.seen
        )
        body["input"] = orp.sanitize_request(body.get("input"), results)
        t_up = time.perf_counter()
        resp = await self.client.post(
            f"{self.cfg.openai_base_url.rstrip('/')}/v1/responses",
            headers=self._headers(request, OPENAI_FORWARD),
            json=body,
        )
        upstream_ms = (time.perf_counter() - t_up) * 1000
        if resp.status_code != 200:
            return Response(resp.content, status_code=resp.status_code, media_type=resp.headers.get("content-type"))
        data = resp.json()
        decisions = {i: await self._evaluate(ctx, c) for i, c in orp.response_tool_calls(data)}
        if any(not d.allowed for d in decisions.values()) and self.cfg.strict:
            return self._strict_error(list(decisions.values()), "openai")
        if any(not d.allowed or d.redacted_arguments is not None for d in decisions.values()):
            data = orp.rewrite_response(data, decisions)
        return JSONResponse(data, headers=self._meta_headers(list(decisions.values()), start, upstream_ms))

    # ------------------------------------------------------------------ Anthropic messages

    async def messages(self, request: Request) -> Response:
        start = time.perf_counter()
        principal = await self._principal(request)
        if principal is None:
            return JSONResponse(
                {
                    "type": "error",
                    "error": {
                        "type": "authentication_error",
                        "message": "invalid or missing X-AgentGuard-Key",
                    },
                },
                status_code=401,
            )
        body = await self._body(request)
        if isinstance(body, JSONResponse):
            return body
        ctx = self._ctx(principal, _session_id(principal, request, body))
        messages = body.get("messages") or []
        results = await asyncio.to_thread(am.ingest, self.engine, ctx, body.get("system"), messages, self.seen)
        body["messages"] = am.sanitize_request(messages, results)
        url = f"{self.cfg.anthropic_base_url.rstrip('/')}/v1/messages"
        headers = self._headers(request, ANTHROPIC_FORWARD)
        t_up = time.perf_counter()
        if body.get("stream"):
            req = self.client.build_request("POST", url, headers=headers, json=body)
            resp = await self.client.send(req, stream=True)
            if resp.status_code != 200:
                raw = await resp.aread()
                await resp.aclose()
                return Response(raw, status_code=resp.status_code, media_type=resp.headers.get("content-type"))
            return StreamingResponse(self._anthropic_stream(resp, ctx), media_type="text/event-stream")
        resp = await self.client.post(url, headers=headers, json=body)
        upstream_ms = (time.perf_counter() - t_up) * 1000
        if resp.status_code != 200:
            return Response(resp.content, status_code=resp.status_code, media_type=resp.headers.get("content-type"))
        data = resp.json()
        decisions = {i: await self._evaluate(ctx, c) for i, c in am.response_tool_calls(data)}
        if any(not d.allowed for d in decisions.values()) and self.cfg.strict:
            return self._strict_error(list(decisions.values()), "anthropic")
        if any(not d.allowed or d.redacted_arguments is not None for d in decisions.values()):
            data = am.rewrite_response(data, decisions)
        return JSONResponse(data, headers=self._meta_headers(list(decisions.values()), start, upstream_ms))

    async def _anthropic_stream(self, resp: httpx.Response, ctx: GuardContext) -> AsyncIterator[bytes]:
        buf = am.StreamToolBuffer()
        event: str | None = None

        def fmt(ev: str, data: dict[str, Any]) -> bytes:
            return f"event: {ev}\ndata: {json.dumps(data)}\n\n".encode()

        try:
            async for line in resp.aiter_lines():
                if line.startswith("event:"):
                    event = line[6:].strip()
                    continue
                if not line.startswith("data:"):
                    continue
                try:
                    data = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
                ev = event or data.get("type", "")
                idx = buf.is_tool_event(ev, data)
                if idx is not None:
                    buf.events[idx].append((ev, data))
                    continue
                if ev == "message_delta" and buf.blocks:
                    decisions = {i: await self._evaluate(ctx, c) for i, c in buf.tool_calls()}
                    for i in sorted(buf.events):
                        d = decisions.get(i)
                        if d is None or d.allowed:
                            for e, x in buf.events[i]:
                                yield fmt(e, x)
                            continue
                        yield fmt(
                            "content_block_start",
                            {
                                "type": "content_block_start",
                                "index": i,
                                "content_block": {"type": "text", "text": ""},
                            },
                        )
                        yield fmt(
                            "content_block_delta",
                            {
                                "type": "content_block_delta",
                                "index": i,
                                "delta": {"type": "text_delta", "text": block_notice([d])},
                            },
                        )
                        yield fmt("content_block_stop", {"type": "content_block_stop", "index": i})
                    if (
                        decisions
                        and all(not d.allowed for d in decisions.values())
                        and (data.get("delta") or {}).get("stop_reason") == "tool_use"
                    ):
                        data["delta"]["stop_reason"] = "end_turn"
                    buf.events.clear()
                    buf.blocks.clear()
                yield fmt(ev, data)
        finally:
            await resp.aclose()

    async def models(self, request: Request) -> Response:
        principal = await self._principal(request)
        if principal is None:
            return JSONResponse({"error": {"message": "invalid or missing X-AgentGuard-Key"}}, status_code=401)
        if "x-api-key" in request.headers or "anthropic-version" in request.headers:
            url, names = f"{self.cfg.anthropic_base_url.rstrip('/')}/v1/models", ANTHROPIC_FORWARD
        else:
            url, names = f"{self.cfg.openai_base_url.rstrip('/')}/v1/models", OPENAI_FORWARD
        resp = await self.client.get(url, headers={k: v for k, v in request.headers.items() if k.lower() in names})
        return Response(resp.content, status_code=resp.status_code, media_type=resp.headers.get("content-type"))


def create_app(
    engine: Engine,
    auth: Any,
    cfg: LlmConfig,
    *,
    approver: Approver | None = None,
    client: httpx.AsyncClient | None = None,
) -> FastAPI:
    gw = LlmGateway(engine, auth, cfg, approver=approver, client=client)
    app = FastAPI(title="AgentGuard LLM gateway", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_api_route("/v1/chat/completions", gw.chat_completions, methods=["POST"])
    app.add_api_route("/v1/responses", gw.responses, methods=["POST"])
    app.add_api_route("/v1/messages", gw.messages, methods=["POST"])
    app.add_api_route("/v1/models", gw.models, methods=["GET"])
    app.add_api_route("/healthz", lambda: {"status": "ok", "version": __version__}, methods=["GET"])
    app.state.gateway = gw
    return app
