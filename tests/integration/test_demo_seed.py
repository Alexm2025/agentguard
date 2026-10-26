from __future__ import annotations

from agentguard.server.demo import seed
from tests.integration.conftest import Stack


async def test_seed_demo_runs_engine_and_is_idempotent(stack: Stack) -> None:
    n = await seed(stack.settings)
    assert n >= 6
    assert await seed(stack.settings) == 0
    admin = await stack.login()
    events = (await admin.get("/api/v1/events?type=tool_call&limit=100")).json()["events"]
    actions = {e["action"] for e in events}
    assert {"BLOCK", "ALLOW", "REQUIRE_APPROVAL"} <= actions
    blocked = [e for e in events if e["action"] == "BLOCK" and e["taint_chain"]]
    assert blocked and "send_email.to derived from read_web" in blocked[0]["taint_chain"][0]
    assert (await admin.get("/api/v1/approvals?status=pending")).json()
