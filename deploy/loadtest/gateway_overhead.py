"""Measure the LLM gateway's added latency (p50/p95) under concurrent load.

Starts a stub OpenAI-compatible upstream with a fixed delay, the real AgentGuard LLM gateway in
front of it, and fires concurrent chat-completion requests that contain a realistic agent
conversation (system + user + tool call + tool result). Overhead is read from the gateway's
``x-agentguard-overhead-ms`` header, which excludes upstream time.

    python deploy/loadtest/gateway_overhead.py --requests 2000 --concurrency 32 [--ml]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import statistics
import threading
import time

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from agentguard.core.engine import Engine
from agentguard.core.policy.loader import parse_policy
from agentguard.gateway.auth import StaticKeyAuth, hash_key
from agentguard.gateway.config import LlmConfig
from agentguard.gateway.llm.app import create_app

KEY = "ag_load_" + "x" * 32
PAGE = "Product comparison. Option A is reliable. Option B has a longer warranty. " * 12
COMPLETION = {
    "id": "c",
    "object": "chat.completion",
    "created": 1,
    "model": "stub",
    "choices": [
        {
            "index": 0,
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_2",
                        "type": "function",
                        "function": {
                            "name": "send_email",
                            "arguments": json.dumps({"to": "me@acme.com", "body": "Option B"}),
                        },
                    }
                ],
            },
        }
    ],
}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def serve(app: object, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", access_log=False))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    return server


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=1000)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--upstream-ms", type=float, default=50.0)
    ap.add_argument("--ml", action="store_true", help="enable the ONNX classifier (needs AGENTGUARD_MODEL_DIR)")
    ns = ap.parse_args()

    async def upstream_handler(_: Request) -> JSONResponse:
        await asyncio.sleep(ns.upstream_ms / 1000)
        return JSONResponse(COMPLETION)

    up_port, gw_port = free_port(), free_port()
    serve(Starlette(routes=[Route("/v1/chat/completions", upstream_handler, methods=["POST"])]), up_port)
    policy = parse_policy(f"""
settings: {{ detectors: {{ ml: {{ enabled: {str(ns.ml).lower()} }} }} }}
tools:
  read_web: {{ role: source, ref_arg: url }}
  send_email: {{ role: sink, risk: high, destination_args: [to] }}
""")
    app = create_app(
        Engine(policy),
        StaticKeyAuth({hash_key(KEY): {"tenant_id": "load"}}),
        LlmConfig(openai_base_url=f"http://127.0.0.1:{up_port}"),
    )
    serve(app, gw_port)

    overheads: list[float] = []
    totals: list[float] = []
    errors = 0

    async def worker(client: httpx.AsyncClient, n: int) -> None:
        nonlocal errors
        for i in range(n):
            body = {
                "model": "stub",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {
                        "role": "user",
                        "content": f"Compare the products on https://shop.example/p/{i} and email me@acme.com",
                    },
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "read_web",
                                    "arguments": json.dumps({"url": f"https://shop.example/p/{i}"}),
                                },
                            }
                        ],
                    },
                    {"role": "tool", "tool_call_id": "call_1", "content": PAGE + f" item {i}"},
                ],
            }
            t = time.perf_counter()
            r = await client.post(
                "/v1/chat/completions", json=body, headers={"x-agentguard-key": KEY, "x-agentguard-session": f"s{i}"}
            )
            totals.append((time.perf_counter() - t) * 1000)
            if r.status_code != 200:
                errors += 1
                continue
            overheads.append(float(r.headers["x-agentguard-overhead-ms"]))

    async def run() -> float:
        limits = httpx.Limits(max_connections=ns.concurrency * 2)
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{gw_port}", timeout=60, limits=limits) as client:
            await worker(client, 20)  # warm-up
            overheads.clear()
            totals.clear()
            start = time.perf_counter()
            per = ns.requests // ns.concurrency
            await asyncio.gather(*(worker(client, per) for _ in range(ns.concurrency)))
            return time.perf_counter() - start

    elapsed = asyncio.run(run())
    o = sorted(overheads)
    pct = lambda p: round(o[min(len(o) - 1, int(p * len(o)))], 2)  # noqa: E731
    print(
        json.dumps(
            {
                "requests": len(o),
                "errors": errors,
                "concurrency": ns.concurrency,
                "ml_layer": ns.ml,
                "throughput_rps": round(len(o) / elapsed, 1),
                "upstream_ms": ns.upstream_ms,
                "overhead_ms": {
                    "p50": pct(0.5),
                    "p95": pct(0.95),
                    "p99": pct(0.99),
                    "mean": round(statistics.fmean(o), 2),
                },
                "end_to_end_ms_p95": round(sorted(totals)[int(0.95 * len(totals))], 2),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
