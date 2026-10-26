"""Exceptions raised to agent code."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.core.types import Decision


class AgentGuardError(Exception):
    """Base class for AgentGuard errors."""


class PolicyError(AgentGuardError):
    """Policy file is invalid."""


class ToolCallBlocked(AgentGuardError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.agent_message())
        self.decision = decision


class ApprovalDenied(ToolCallBlocked):
    pass


class ApprovalTimeout(ToolCallBlocked):
    pass
