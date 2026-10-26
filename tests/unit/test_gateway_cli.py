from __future__ import annotations

from pathlib import Path

import pytest

from agentguard.core.events import JsonlFileSink, LoggingSink
from agentguard.gateway.auth import StaticKeyAuth
from agentguard.gateway.cli import build_auth, build_engine
from agentguard.gateway.config import GatewayConfig, load_gateway_config


def test_gateway_uses_ingest_key_not_service_token(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentguard.client import ControlPlaneSink

    cfg = GatewayConfig.model_validate({"control_plane": {"url": "http://127.0.0.1:9"}})
    monkeypatch.delenv("AGENTGUARD_API_KEY", raising=False)
    monkeypatch.setenv("AGENTGUARD_SERVICE_TOKEN", "svc")
    engine, approver = build_engine(cfg)
    assert approver is None and not any(isinstance(s, ControlPlaneSink) for s in engine.sinks)

    monkeypatch.setenv("AGENTGUARD_API_KEY", "ag_live_" + "k" * 40)
    engine, approver = build_engine(cfg)
    sink = next(s for s in engine.sinks if isinstance(s, ControlPlaneSink))
    assert approver is not None
    assert sink.client._headers["x-agentguard-key"].startswith("ag_live_")  # never the service token
    sink.close()


def test_config_env_expansion_and_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAIL_TOKEN", "t0k")
    f = tmp_path / "g.yaml"
    f.write_text(
        "events_file: ev.jsonl\nauth: {mode: static, keys: {abc: {tenant_id: t}}}\n"
        "mcp: {servers: [{name: mail, url: 'http://x', headers: {Authorization: 'Bearer ${MAIL_TOKEN}'}}]}\n"
    )
    cfg = load_gateway_config(f)
    assert cfg.mcp.servers[0].headers["Authorization"] == "Bearer t0k"
    engine, _ = build_engine(cfg)
    assert any(isinstance(s, JsonlFileSink) for s in engine.sinks) and any(
        isinstance(s, LoggingSink) for s in engine.sinks
    )
    assert isinstance(build_auth(cfg), StaticKeyAuth)
    with pytest.raises(SystemExit):
        build_auth(GatewayConfig())  # static auth without keys is refused
    assert build_auth(GatewayConfig.model_validate({"auth": {"mode": "none"}})).allow_anonymous
