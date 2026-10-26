"""Streamable-HTTP MCP gateway.

Routes ``/servers/{name}/mcp`` to the configured upstream server URL. Supports JSON and SSE
responses, the server-initiated GET stream, DELETE session termination, and ``Mcp-Session-Id``
passthrough. Provenance sessions are keyed by (tenant, server, Mcp-Session-Id) so tenants never
share context.
"""

from __future__ import annotations

import json
import logging
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from agentguard.gateway.auth import Principal, StaticKeyAuth
from agentguard.gateway.mcp.interceptor import McpInterceptor, McpSession

log = logging.getLogger(__name__)

HOP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "upgrade",
    "x-agentguard-key",
    "x-agentguard-session",
    "authorization",
    "cookie",
}
MAX_BODY = 8 * 1024 * 1024


@dataclass
class Upstream:
    name: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    forward_authorization: bool = False
    interceptor: McpInterceptor | None = None


class SessionTable:
    def __init__(self, max_sessions: int = 10_000, ttl: float = 24 * 3600) -> None:
        self._d: OrderedDict[tuple[str, str, str], tuple[McpSession, float]] = OrderedDict()
        self.max, self.ttl = max_sessions, ttl

    def get(self, key: tuple[str, str, str], factory: Callable[[], McpSession]) -> McpSession:
        now = time.monotonic()
        item = self._d.get(key)
        if item is None or now - item[1] > self.ttl:
            item = (factory(), now)
        self._d[key] = (item[0], now)
        self._d.move_to_end(key)
        while len(self._d) > self.max:
            self._d.popitem(last=False)
        return item[0]

    def drop(self, key: tuple[str, str, str]) -> None:
        self._d.pop(key, None)


def _sse_events(lines: list[str]) -> tuple[str | None, str | None, str]:
    event_id = event = None
    data = []
    for ln in lines:
        if ln.startswith("id:"):
            event_id = ln[3:].strip()
        elif ln.startswith("event:"):
            event = ln[6:].strip()
        elif ln.startswith("data:"):
            data.append(ln[5:].lstrip(" "))
    return event_id, event, "\n".join(data)


def _format_sse(event_id: str | None, event: str | None, data: str) -> bytes:
    out = []
    if event_id is not None:
        out.append(f"id: {event_id}")
    if event is not None:
        out.append(f"event: {event}")
    out += [f"data: {line}" for line in data.split("\n")]
    return ("\n".join(out) + "\n\n").encode()


class McpHttpGateway:
    def __init__(
        self, upstreams: list[Upstream], auth: StaticKeyAuth | Any, *, client: httpx.AsyncClient | None = None
    ) -> None:
        self.upstreams = {u.name: u for u in upstreams}
        self.auth = auth
        self.client = client or httpx.AsyncClient(timeout=httpx.Timeout(30.0, read=None))
        self.sessions = SessionTable()

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/servers/{name}/mcp", self.handle, methods=["POST", "GET", "DELETE"]),
                Route("/healthz", lambda r: JSONResponse({"status": "ok"}), methods=["GET"]),
            ]
        )

    def _session(self, principal: Principal, up: Upstream, sid: str | None) -> McpSession:
        if up.interceptor is None:  # pragma: no cover - checked in handle()
            raise RuntimeError(f"upstream {up.name} has no interceptor")
        interceptor = up.interceptor
        key = (principal.tenant_id, up.name, sid or "-")
        return self.sessions.get(key, lambda: interceptor.new_session(principal.tenant_id, principal.project_id, sid))

    def _upstream_headers(self, request: Request, up: Upstream) -> dict[str, str]:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_HEADERS}
        if up.forward_authorization and "authorization" in request.headers:
            headers["authorization"] = request.headers["authorization"]
        headers.update(up.headers)
        return headers

    async def handle(self, request: Request) -> Response:
        principal = await self.auth.authenticate(request.headers)
        if principal is None:
            return JSONResponse({"error": "invalid or missing AgentGuard API key"}, status_code=401)
        up = self.upstreams.get(request.path_params["name"])
        if up is None or up.interceptor is None:
            return JSONResponse({"error": "unknown server"}, status_code=404)
        # Stateless (2026+) MCP has no Mcp-Session-Id; clients can scope provenance with X-AgentGuard-Session.
        sid = request.headers.get("mcp-session-id") or request.headers.get("x-agentguard-session")
        headers = self._upstream_headers(request, up)

        if request.method == "DELETE":
            r = await self.client.delete(up.url, headers=headers)
            self.sessions.drop((principal.tenant_id, up.name, sid or "-"))
            return Response(status_code=r.status_code)
        if request.method == "GET":
            return await self._proxy_stream("GET", up, headers, None, principal, sid)

        body = await request.body()
        if len(body) > MAX_BODY:
            return JSONResponse({"error": "request too large"}, status_code=413)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                status_code=400,
            )
        batch = isinstance(payload, list)
        msgs = [m for m in (payload if batch else [payload]) if isinstance(m, dict)]
        session = self._session(principal, up, sid)
        replies, forward = [], []
        for m in msgs:
            v = await up.interceptor.from_client(session, m)
            if v.reply is not None:
                replies.append(v.reply)
            if v.forward is not None:
                forward.append(v.forward)
        if not forward:
            return JSONResponse(replies if batch else replies[0], headers={"mcp-session-id": sid} if sid else None)
        if replies:
            # Mixed batch: answer locally-blocked requests inline with the upstream results.
            log.debug("mixed batch: %d blocked, %d forwarded", len(replies), len(forward))
        out_body = json.dumps(forward if batch else forward[0]).encode()
        return await self._proxy_stream("POST", up, headers, out_body, principal, sid, extra=replies)

    async def _proxy_stream(
        self,
        method: str,
        up: Upstream,
        headers: Mapping[str, str],
        body: bytes | None,
        principal: Principal,
        sid: str | None,
        extra: list[dict[str, Any]] | None = None,
    ) -> Response:
        req = self.client.build_request(method, up.url, headers=headers, content=body)
        resp = await self.client.send(req, stream=True)
        new_sid = resp.headers.get("mcp-session-id") or sid
        if new_sid and new_sid != sid:
            # Session established by this response: move pending state to the new key.
            old = self._session(principal, up, sid)
            self.sessions.get((principal.tenant_id, up.name, new_sid), lambda: old)
        session = self._session(principal, up, new_sid)
        out_headers = {
            k: v
            for k, v in resp.headers.items()
            if k.lower() in ("mcp-session-id", "content-type", "cache-control", "mcp-protocol-version")
        }
        ctype = resp.headers.get("content-type", "")
        interceptor = up.interceptor
        if interceptor is None:  # pragma: no cover - checked in handle()
            raise RuntimeError(f"upstream {up.name} has no interceptor")

        if ctype.startswith("text/event-stream"):

            async def gen() -> AsyncIterator[bytes]:
                try:
                    for m in extra or []:
                        yield _format_sse(None, "message", json.dumps(m))
                    buf: list[str] = []
                    async for line in resp.aiter_lines():
                        if line == "":
                            if buf:
                                eid, ev, data = _sse_events(buf)
                                buf = []
                                if data and (ev in (None, "message")):
                                    try:
                                        msg = json.loads(data)
                                        msg = (
                                            [interceptor.from_server(session, x) for x in msg]
                                            if isinstance(msg, list)
                                            else interceptor.from_server(session, msg)
                                        )
                                        data = json.dumps(msg)
                                    except json.JSONDecodeError:
                                        pass
                                yield _format_sse(eid, ev, data)
                            continue
                        buf.append(line)
                finally:
                    await resp.aclose()

            return StreamingResponse(gen(), status_code=resp.status_code, headers=out_headers)

        raw = await resp.aread()
        await resp.aclose()
        if ctype.startswith("application/json") and raw:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                return Response(raw, status_code=resp.status_code, headers=out_headers)
            if isinstance(msg, list):
                msg = [interceptor.from_server(session, x) for x in msg] + list(extra or [])
            else:
                msg = interceptor.from_server(session, msg)
                if extra:
                    msg = [msg, *extra]
            return Response(
                json.dumps(msg),
                status_code=resp.status_code,
                headers=out_headers,
                media_type="application/json",
            )
        return Response(raw, status_code=resp.status_code, headers=out_headers)
