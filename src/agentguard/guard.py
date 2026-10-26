"""High-level SDK facade.

>>> guard = Guard("agentguard.yaml")
>>> send_email = guard.wrap_tool(send_email)          # enforce policy on calls
>>> read_web = guard.wrap_tool(read_web)              # results are labelled tainted
>>> client = guard.wrap_openai(OpenAI())              # provenance from the conversation
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import inspect
import logging
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any, Literal, TypeVar, cast

from agentguard.core.approvals import ApprovalStatus, Approver, await_for, wait_for
from agentguard.core.engine import Engine, GuardContext, ResultDecision
from agentguard.core.errors import ApprovalDenied, ApprovalTimeout, ToolCallBlocked
from agentguard.core.events import EventSink
from agentguard.core.policy.loader import FilePolicyStore, PolicyStore
from agentguard.core.policy.model import Policy
from agentguard.core.provenance import ProvenanceLedger
from agentguard.core.types import Action, Decision, Reason, ToolCall

log = logging.getLogger(__name__)
F = TypeVar("F", bound=Callable[..., Any])
OnBlock = Literal["return", "raise"]

_current: contextvars.ContextVar[GuardContext | None] = contextvars.ContextVar("agentguard_context", default=None)


class Guard:
    def __init__(
        self,
        policy: str | Path | Policy | PolicyStore | None = None,
        *,
        engine: Engine | None = None,
        approver: Approver | None = None,
        sinks: list[EventSink] | None = None,
        on_block: OnBlock = "return",
        tenant_id: str | None = None,
        project_id: str | None = None,
        control_plane_url: str | None = None,
        api_key: str | None = None,
        **engine_kwargs: Any,
    ) -> None:
        sinks = list(sinks or [])
        if control_plane_url:
            from agentguard.client import ControlPlaneApprover, ControlPlaneClient, ControlPlaneSink

            cp = ControlPlaneClient(control_plane_url, api_key)
            sinks.append(ControlPlaneSink(cp))
            approver = approver or ControlPlaneApprover(cp)
            if policy is None:
                policy = cp.policy_store()
        if engine is None:
            if isinstance(policy, str | Path):
                store: PolicyStore | Policy | None = FilePolicyStore(policy)
            else:
                store = policy
            engine = Engine(store, sinks=sinks, **engine_kwargs)
        else:
            engine.sinks.extend(sinks)
        self.engine = engine
        self.approver = approver
        self.on_block: OnBlock = on_block
        self.tenant_id = tenant_id
        self.project_id = project_id
        self._default = GuardContext(tenant_id=tenant_id, project_id=project_id)

    # ------------------------------------------------------------------ sessions

    def context(self) -> GuardContext:
        return _current.get() or self._default

    @contextlib.contextmanager
    def session(
        self, session_id: str | None = None, *, system: str | None = None, user: str | None = None
    ) -> Iterator[GuardContext]:
        """Scope a fresh provenance ledger to the enclosed block (thread- and task-local)."""
        ctx = GuardContext(ProvenanceLedger(session_id), self.tenant_id, self.project_id)
        if system:
            ctx.ledger.add_system(system)
        if user:
            ctx.ledger.add_user(user)
        token = _current.set(ctx)
        try:
            yield ctx
        finally:
            _current.reset(token)

    def add_user(self, text: str) -> None:
        self.context().ledger.add_user(text)

    def add_system(self, text: str) -> None:
        self.context().ledger.add_system(text)

    # ------------------------------------------------------------------ decisions

    def _resolve_approval(self, decision: Decision, ctx: GuardContext, status: ApprovalStatus) -> Decision:
        if status is ApprovalStatus.APPROVED:
            decision.action = Action.ALLOW
            decision.reasons.append(Reason("APPROVED", "approved by a human reviewer", action=Action.ALLOW))
        elif status is ApprovalStatus.DENIED:
            decision.action = Action.BLOCK
            decision.reasons.append(Reason("DENIED", "denied by a human reviewer"))
        else:
            on_timeout = self.engine.policy.settings.approvals.on_timeout
            decision.action = Action.ALLOW if on_timeout == "ALLOW" else Action.BLOCK
            decision.reasons.append(Reason("APPROVAL_TIMEOUT", "approval timed out", action=decision.action))
        self.engine._emit(
            {
                "type": "approval_resolved",
                "id": decision.event_id,
                "approval_id": decision.approval_id,
                "status": status.value,
                "tool": decision.tool,
                **ctx.meta(),
            }
        )
        return decision

    def _prepare_approval(self, decision: Decision, ctx: GuardContext) -> float | None:
        if decision.action is not Action.REQUIRE_APPROVAL:
            return None
        if self.approver is None:
            decision.action = Action.BLOCK
            decision.reasons.append(Reason("NO_APPROVER", "approval required but no approver is configured"))
            return None
        timeout = self.engine.policy.settings.approvals.timeout_seconds
        decision.approval_id = self.approver.request(decision, ctx, timeout)
        return timeout

    def check(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        call_id: str | None = None,
        ctx: GuardContext | None = None,
    ) -> Decision:
        """Evaluate a tool call, waiting for approval if the policy requires it."""
        ctx = ctx or self.context()
        call = ToolCall(name, dict(arguments)) if call_id is None else ToolCall(name, dict(arguments), call_id)
        decision = self.engine.evaluate(ctx, call)
        timeout = self._prepare_approval(decision, ctx)
        if timeout is not None:
            if self.approver is None or decision.approval_id is None:  # pragma: no cover - set above
                raise RuntimeError("approval requested without an approver")
            status = wait_for(self.approver, decision.approval_id, timeout)
            self._resolve_approval(decision, ctx, status)
        return decision

    async def acheck(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        call_id: str | None = None,
        ctx: GuardContext | None = None,
    ) -> Decision:
        import asyncio

        ctx = ctx or self.context()
        call = ToolCall(name, dict(arguments)) if call_id is None else ToolCall(name, dict(arguments), call_id)
        decision = await asyncio.to_thread(self.engine.evaluate, ctx, call)
        timeout = await asyncio.to_thread(self._prepare_approval, decision, ctx)
        if timeout is not None:
            if self.approver is None or decision.approval_id is None:  # pragma: no cover - set above
                raise RuntimeError("approval requested without an approver")
            status = await await_for(self.approver, decision.approval_id, timeout)
            self._resolve_approval(decision, ctx, status)
        return decision

    def record_result(
        self,
        name: str,
        result: Any,
        *,
        arguments: Mapping[str, Any] | None = None,
        call_id: str | None = None,
        ctx: GuardContext | None = None,
    ) -> ResultDecision:
        return self.engine.inspect_result(ctx or self.context(), name, result, arguments=arguments, call_id=call_id)

    def _blocked(self, decision: Decision, on_block: OnBlock) -> str:
        if on_block == "raise":
            if any(r.code == "DENIED" for r in decision.reasons):
                raise ApprovalDenied(decision)
            if any(r.code == "APPROVAL_TIMEOUT" for r in decision.reasons):
                raise ApprovalTimeout(decision)
            raise ToolCallBlocked(decision)
        return decision.agent_message()

    # ------------------------------------------------------------------ tool wrapping

    def wrap_tool(self, fn: F, *, name: str | None = None, on_block: OnBlock | None = None) -> F:
        """Enforce policy before ``fn`` runs and label its result. Works for sync and async tools.

        When a call is blocked the wrapper returns an explanatory string to the agent (default) or
        raises :class:`ToolCallBlocked` (``on_block="raise"``).
        """
        tool_name: str = name or str(getattr(fn, "__name__", "tool"))
        mode: OnBlock = on_block or self.on_block
        sig = _signature(fn)

        def bind(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
            if sig is None:
                return {**{f"arg{i}": a for i, a in enumerate(args)}, **kwargs}
            bound = sig.bind_partial(*args, **kwargs)
            return {k: v for k, v in bound.arguments.items() if k not in ("self", "cls")}

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def awrapper(*args: Any, **kwargs: Any) -> Any:
                arguments = bind(args, kwargs)
                decision = await self.acheck(tool_name, arguments)
                if not decision.allowed:
                    return self._blocked(decision, mode)
                if decision.action is Action.REDACT and decision.redacted_arguments is not None:
                    kwargs, args = _rebind(sig, decision.redacted_arguments, args, kwargs)
                result = await fn(*args, **kwargs)
                return self.record_result(tool_name, result, arguments=arguments, call_id=decision.call_id).content

            return cast(F, awrapper)

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            arguments = bind(args, kwargs)
            decision = self.check(tool_name, arguments)
            if not decision.allowed:
                return self._blocked(decision, mode)
            if decision.action is Action.REDACT and decision.redacted_arguments is not None:
                kwargs, args = _rebind(sig, decision.redacted_arguments, args, kwargs)
            result = fn(*args, **kwargs)
            return self.record_result(tool_name, result, arguments=arguments, call_id=decision.call_id).content

        return cast(F, wrapper)

    def tool(self, fn: F | None = None, *, name: str | None = None, on_block: OnBlock | None = None) -> Any:
        """Decorator form of :meth:`wrap_tool`."""
        if fn is None:
            return lambda f: self.wrap_tool(f, name=name, on_block=on_block)
        return self.wrap_tool(fn, name=name, on_block=on_block)

    # ------------------------------------------------------------------ framework helpers

    def wrap_openai(self, client: Any, *, mode: Literal["rewrite", "raise"] = "rewrite") -> Any:
        from agentguard.sdk.openai import wrap_openai

        return wrap_openai(client, self, mode=mode)

    def wrap_anthropic(self, client: Any, *, mode: Literal["rewrite", "raise"] = "rewrite") -> Any:
        from agentguard.sdk.anthropic import wrap_anthropic

        return wrap_anthropic(client, self, mode=mode)


def _signature(fn: Callable[..., Any]) -> inspect.Signature | None:
    try:
        return inspect.signature(fn)
    except (TypeError, ValueError):
        return None


def _rebind(
    sig: inspect.Signature | None, redacted: Mapping[str, Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> tuple[dict[str, Any], tuple[Any, ...]]:
    if sig is None:
        return {k: v for k, v in redacted.items() if not k.startswith("arg")}, args
    bound = sig.bind_partial(*args, **kwargs)
    for k, v in redacted.items():
        if k in bound.arguments:
            bound.arguments[k] = v
    return dict(bound.kwargs), tuple(bound.args)
