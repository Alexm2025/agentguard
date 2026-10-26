"""Human-in-the-loop approval protocol.

An :class:`Approver` turns a REQUIRE_APPROVAL decision into ALLOW or BLOCK. Implementations:

* :class:`CallbackApprover` - a local function decides (CLI prompt, custom UI, tests)
* :class:`agentguard.client.ControlPlaneApprover` - creates an approval on the control plane and
  waits until someone resolves it in the dashboard, REST API, webhook or Slack
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from enum import StrEnum
from typing import Any, Protocol

from agentguard.core.engine import GuardContext
from agentguard.core.events import decision_event
from agentguard.core.types import Decision


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class Approver(Protocol):
    def request(self, decision: Decision, ctx: GuardContext, timeout: float) -> str: ...

    def status(self, approval_id: str) -> ApprovalStatus: ...


def wait_for(approver: Approver, approval_id: str, timeout: float, poll: float = 1.0) -> ApprovalStatus:
    deadline = time.monotonic() + timeout
    while True:
        st = approver.status(approval_id)
        if st is not ApprovalStatus.PENDING:
            return st
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return ApprovalStatus.EXPIRED
        time.sleep(min(poll, remaining))


async def await_for(
    approver: Approver,
    approval_id: str,
    timeout: float,  # noqa: ASYNC109 - polling deadline, not a cancellation scope
    poll: float = 1.0,
) -> ApprovalStatus:
    deadline = time.monotonic() + timeout
    while True:
        st = await asyncio.to_thread(approver.status, approval_id)
        if st is not ApprovalStatus.PENDING:
            return st
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return ApprovalStatus.EXPIRED
        await asyncio.sleep(min(poll, remaining))


class CallbackApprover:
    """Resolves approvals synchronously with a local callback ``fn(event_dict) -> bool``."""

    def __init__(self, fn: Callable[[dict[str, Any]], bool]) -> None:
        self.fn = fn
        self._results: dict[str, ApprovalStatus] = {}

    def request(self, decision: Decision, ctx: GuardContext, timeout: float) -> str:
        approval_id = f"apr_local_{decision.event_id}"
        ok = self.fn(decision_event(decision, context=ctx.meta()))
        self._results[approval_id] = ApprovalStatus.APPROVED if ok else ApprovalStatus.DENIED
        return approval_id

    def status(self, approval_id: str) -> ApprovalStatus:
        return self._results.get(approval_id, ApprovalStatus.EXPIRED)


def console_approver() -> CallbackApprover:
    """Ask on the terminal. Useful for local development."""

    def ask(event: dict[str, Any]) -> bool:
        print(f"\n[AgentGuard] approval required for {event['tool']}({event['arguments']})")
        for r in event["reasons"]:
            print(f"  - {r['message']}")
        for c in event["taint_chain"]:
            print(f"  * {c}")
        return input("Approve? [y/N] ").strip().lower() in ("y", "yes")

    return CallbackApprover(ask)
