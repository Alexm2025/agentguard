"""stdio MCP gateway: ``agentguard gateway mcp-stdio -- <server command...>``.

The MCP client launches AgentGuard instead of the server; AgentGuard launches the real server as a
child process and relays newline-delimited JSON-RPC in both directions through the interceptor.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sys
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from agentguard.gateway.mcp.interceptor import McpInterceptor, McpSession

log = logging.getLogger(__name__)
MAX_LINE = 64 * 1024 * 1024

WriteFn = Callable[[bytes], Awaitable[None]]


def _encode(msg: Any) -> bytes:
    return (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


async def relay(
    interceptor: McpInterceptor,
    session: McpSession,
    client_in: asyncio.StreamReader,
    client_out: WriteFn,
    server_in: WriteFn,
    server_out: asyncio.StreamReader,
) -> None:
    """Pump messages until either side closes."""
    out_lock = asyncio.Lock()
    tasks: set[asyncio.Task[None]] = set()

    async def to_client(data: bytes) -> None:
        async with out_lock:
            await client_out(data)

    async def handle_client(msg: dict[str, Any]) -> None:
        try:
            verdict = await interceptor.from_client(session, msg)
        except Exception:
            log.exception("interceptor failed on client message; failing closed")
            if "id" in msg:
                await to_client(
                    _encode(
                        {
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "error": {"code": -32603, "message": "AgentGuard internal error"},
                        }
                    )
                )
            return
        if verdict.reply is not None:
            await to_client(_encode(verdict.reply))
        if verdict.forward is not None:
            await server_in(_encode(verdict.forward))

    async def client_loop() -> None:
        while line := await client_in.readline():
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                await to_client(
                    _encode({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                )
                continue
            for m in msg if isinstance(msg, list) else [msg]:
                if isinstance(m, dict):
                    # Concurrent so a call waiting for approval does not block other traffic.
                    t = asyncio.create_task(handle_client(m))
                    tasks.add(t)
                    t.add_done_callback(tasks.discard)

    async def server_loop() -> None:
        while line := await server_out.readline():
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                log.warning("dropping non-JSON line from server")
                continue
            msgs = msg if isinstance(msg, list) else [msg]
            out = [interceptor.from_server(session, m) if isinstance(m, dict) else m for m in msgs]
            await to_client(_encode(out if isinstance(msg, list) else out[0]))

    c = asyncio.create_task(client_loop())
    s = asyncio.create_task(server_loop())
    done, pending = await asyncio.wait({c, s}, return_when=asyncio.FIRST_COMPLETED)
    if c in done and tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
        # Let the server finish answering forwarded requests.
        with contextlib.suppress(TimeoutError, asyncio.CancelledError):
            await asyncio.wait_for(s, timeout=5)
    for t in pending:
        t.cancel()


def stdin_reader(loop: asyncio.AbstractEventLoop) -> asyncio.StreamReader:
    """Feed our stdin into a StreamReader from a thread. ``connect_read_pipe`` does not work with
    anonymous pipes under the Windows proactor loop, and a thread works everywhere."""
    import threading

    reader = asyncio.StreamReader(limit=MAX_LINE)
    src = sys.stdin.buffer

    def pump() -> None:
        try:
            while line := src.readline():
                loop.call_soon_threadsafe(reader.feed_data, line)
        finally:
            loop.call_soon_threadsafe(reader.feed_eof)

    threading.Thread(target=pump, name="agentguard-stdin", daemon=True).start()
    return reader


async def run_stdio(
    interceptor: McpInterceptor,
    command: Sequence[str],
    *,
    tenant_id: str | None = None,
    project_id: str | None = None,
    env: dict[str, str] | None = None,
) -> int:
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=None,  # inherit: server logs go to our stderr
        env={**os.environ, **(env or {})},
        limit=MAX_LINE,
    )
    if proc.stdin is None or proc.stdout is None:  # pragma: no cover - guaranteed by PIPE
        raise RuntimeError("failed to open pipes to the MCP server")
    reader = stdin_reader(asyncio.get_running_loop())
    stdout = sys.stdout.buffer

    async def client_out(data: bytes) -> None:
        stdout.write(data)
        stdout.flush()

    stdin = proc.stdin

    async def server_in(data: bytes) -> None:
        stdin.write(data)
        await stdin.drain()

    session = interceptor.new_session(tenant_id, project_id)
    try:
        await relay(interceptor, session, reader, client_out, server_in, proc.stdout)
    finally:
        if proc.returncode is None:
            stdin.close()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except TimeoutError:
                proc.kill()
    return proc.returncode or 0
