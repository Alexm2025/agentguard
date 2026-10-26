"""``agentguard gateway ...`` commands."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Any

from agentguard.core.approvals import Approver
from agentguard.core.engine import Engine
from agentguard.core.events import EventSink, JsonlFileSink, LoggingSink
from agentguard.core.policy.loader import FilePolicyStore, PolicyStore
from agentguard.gateway.config import GatewayConfig, load_gateway_config

log = logging.getLogger("agentguard.gateway")


def build_engine(cfg: GatewayConfig) -> tuple[Engine, Approver | None]:
    sinks: list[EventSink] = [LoggingSink(only_actions={"BLOCK", "REQUIRE_APPROVAL", "REDACT"})]
    if cfg.events_file:
        sinks.append(JsonlFileSink(cfg.events_file))
    approver: Approver | None = None
    store: PolicyStore | None = FilePolicyStore(cfg.policy) if cfg.policy else None
    if cfg.control_plane.url:
        from agentguard.client import ControlPlaneApprover, ControlPlaneClient, ControlPlaneSink

        token = os.environ.get(cfg.control_plane.token_env)
        cp = ControlPlaneClient(cfg.control_plane.url, token)
        sinks.append(ControlPlaneSink(cp))
        approver = ControlPlaneApprover(cp)
        if store is None:
            store = cp.policy_store()
    return Engine(store, sinks=sinks), approver


def build_auth(cfg: GatewayConfig) -> Any:
    from agentguard.gateway.auth import ControlPlaneAuth, StaticKeyAuth

    if cfg.auth.mode == "none":
        log.warning("gateway authentication is DISABLED (auth.mode=none); use only for local development")
        return StaticKeyAuth(allow_anonymous=True)
    if cfg.auth.mode == "control_plane":
        if not cfg.control_plane.url:
            raise SystemExit("auth.mode=control_plane requires control_plane.url")
        token = os.environ.get(cfg.control_plane.token_env, "")
        return ControlPlaneAuth(cfg.control_plane.url, token)
    if not cfg.auth.keys:
        raise SystemExit("auth.mode=static requires at least one key under auth.keys (or auth.mode=none for local use)")
    return StaticKeyAuth(cfg.auth.keys)


def _cmd_mcp_stdio(ns: argparse.Namespace) -> int:
    from agentguard.gateway.mcp.interceptor import McpInterceptor, PinStore
    from agentguard.gateway.mcp.stdio import run_stdio

    command = ns.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("usage: agentguard gateway mcp-stdio [options] -- <server command>", file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="agentguard %(levelname)s %(message)s")
    cfg = load_gateway_config(ns.config)
    if ns.policy:
        cfg.policy = ns.policy
    if ns.events_file:
        cfg.events_file = ns.events_file
    engine, approver = build_engine(cfg)
    interceptor = McpInterceptor(
        engine,
        server_name=ns.name,
        approver=approver,
        pins=PinStore(ns.pins_file or cfg.pins_file),
        on_poisoned=cfg.mcp.on_poisoned_tool,
        on_changed=cfg.mcp.on_changed_tool,
    )
    return asyncio.run(run_stdio(interceptor, command, tenant_id=ns.tenant, project_id=ns.project))


def _cmd_mcp_http(ns: argparse.Namespace) -> int:
    import uvicorn

    from agentguard.gateway.mcp.http import McpHttpGateway, Upstream
    from agentguard.gateway.mcp.interceptor import McpInterceptor, PinStore

    logging.basicConfig(level=logging.INFO, format="agentguard %(levelname)s %(message)s")
    cfg = load_gateway_config(ns.config)
    if ns.policy:
        cfg.policy = ns.policy
    engine, approver = build_engine(cfg)
    pins = PinStore(cfg.pins_file)
    ups = [
        Upstream(
            s.name,
            s.url,
            s.headers,
            s.forward_authorization,
            McpInterceptor(
                engine,
                server_name=s.name,
                approver=approver,
                pins=pins,
                on_poisoned=cfg.mcp.on_poisoned_tool,
                on_changed=cfg.mcp.on_changed_tool,
            ),
        )
        for s in cfg.mcp.servers
    ]
    if not ups:
        raise SystemExit("no MCP servers configured (mcp.servers)")
    app = McpHttpGateway(ups, build_auth(cfg)).app()
    uvicorn.run(
        app,
        host=ns.host,
        port=ns.port,
        ssl_certfile=ns.ssl_certfile,
        ssl_keyfile=ns.ssl_keyfile,
        proxy_headers=False,
        server_header=False,
    )
    return 0


def _cmd_llm(ns: argparse.Namespace) -> int:
    import uvicorn

    from agentguard.gateway.llm.app import create_app

    logging.basicConfig(level=logging.INFO, format="agentguard %(levelname)s %(message)s")
    cfg = load_gateway_config(ns.config)
    if ns.policy:
        cfg.policy = ns.policy
    engine, approver = build_engine(cfg)
    app = create_app(engine, build_auth(cfg), cfg.llm, approver=approver)
    uvicorn.run(
        app,
        host=ns.host,
        port=ns.port,
        ssl_certfile=ns.ssl_certfile,
        ssl_keyfile=ns.ssl_keyfile,
        proxy_headers=False,
        server_header=False,
    )
    return 0


def _cmd_key_hash(ns: argparse.Namespace) -> int:
    from agentguard.gateway.auth import hash_key

    key = ns.key if ns.key != "-" else sys.stdin.readline().strip()
    print(hash_key(key))
    return 0


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    gw = sub.add_parser("gateway", help="run a gateway").add_subparsers(dest="gateway_cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--config", default=os.environ.get("AGENTGUARD_GATEWAY_CONFIG"))
        p.add_argument("--policy")

    s = gw.add_parser("mcp-stdio", help="wrap a stdio MCP server")
    common(s)
    s.add_argument("--name", default="mcp", help="server name used for tool pinning and events")
    s.add_argument("--pins-file")
    s.add_argument("--events-file")
    s.add_argument("--tenant")
    s.add_argument("--project")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(func=_cmd_mcp_stdio)

    for name, fn, port in (("mcp-http", _cmd_mcp_http, 8100), ("llm", _cmd_llm, 8200)):
        h = gw.add_parser(name, help=f"run the {name} gateway")
        common(h)
        h.add_argument("--host", default=os.environ.get("AGENTGUARD_HOST", "127.0.0.1"))
        h.add_argument("--port", type=int, default=int(os.environ.get("AGENTGUARD_PORT", port)))
        h.add_argument("--ssl-certfile", default=os.environ.get("AGENTGUARD_TLS_CERT"))
        h.add_argument("--ssl-keyfile", default=os.environ.get("AGENTGUARD_TLS_KEY"))
        h.set_defaults(func=fn)

    k = sub.add_parser("key", help="API key helpers").add_subparsers(dest="key_cmd", required=True)
    kh = k.add_parser("hash", help="print the SHA-256 digest of a key for static gateway auth")
    kh.add_argument("key", help="the key, or - to read from stdin")
    kh.set_defaults(func=_cmd_key_hash)
