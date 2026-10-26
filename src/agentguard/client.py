"""Client for the AgentGuard control plane, used by the SDK and the gateways.

* :class:`ControlPlaneSink` - batches events and ships them in a background thread (bounded
  queue; when full, the oldest events are dropped and counted, never blocking the agent).
* :class:`ControlPlaneApprover` - creates approvals and polls their status.
* :class:`ControlPlanePolicyStore` - fetches the active policy and hot-reloads new revisions;
  keeps the last good policy if the control plane is unreachable.
"""

from __future__ import annotations

import atexit
import logging
import os
import queue
import threading
import time
from typing import Any

import httpx

from agentguard import __version__
from agentguard.core.approvals import ApprovalStatus
from agentguard.core.engine import GuardContext
from agentguard.core.errors import PolicyError
from agentguard.core.events import decision_event
from agentguard.core.policy.loader import PolicyStore, default_policy, parse_policy
from agentguard.core.types import Decision

log = logging.getLogger(__name__)


class ControlPlaneError(Exception):
    pass


class ControlPlaneClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        key = api_key or os.environ.get("AGENTGUARD_API_KEY")
        if not key:
            raise ControlPlaneError("an API key is required (api_key=... or AGENTGUARD_API_KEY)")
        self._headers = {"x-agentguard-key": key, "user-agent": f"agentguard/{__version__}"}
        self.http = client or httpx.Client(timeout=timeout)

    def _req(self, method: str, path: str, **kw: Any) -> Any:
        r = self.http.request(method, f"{self.base_url}/api/v1{path}", headers=self._headers, **kw)
        if r.status_code >= 400:
            raise ControlPlaneError(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else None

    def post_events(self, events: list[dict[str, Any]]) -> int:
        return int(self._req("POST", "/events", json={"events": events})["accepted"])

    def create_approval(self, event: dict[str, Any], timeout_seconds: float) -> str:
        return str(self._req("POST", "/approvals", json={"event": event, "timeout_seconds": timeout_seconds})["id"])

    def approval_status(self, approval_id: str) -> str:
        return str(self._req("GET", f"/approvals/{approval_id}")["status"])

    def active_policy(self) -> dict[str, Any] | None:
        try:
            return self._req("GET", "/policies/active")  # type: ignore[no-any-return]
        except ControlPlaneError as exc:
            if "-> 404" in str(exc):
                return None
            raise

    def policy_store(self, interval: float = 30.0) -> ControlPlanePolicyStore:
        return ControlPlanePolicyStore(self, interval)


class ControlPlaneSink:
    def __init__(
        self,
        client: ControlPlaneClient,
        *,
        batch_size: int = 100,
        flush_interval: float = 2.0,
        max_queue: int = 10_000,
    ) -> None:
        self.client = client
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max_queue)
        self.dropped = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="agentguard-events", daemon=True)
        self._thread.start()
        atexit.register(self.close)

    def emit(self, event: dict[str, Any]) -> None:
        while True:
            try:
                self.q.put_nowait(event)
                return
            except queue.Full:
                try:
                    self.q.get_nowait()
                    self.dropped += 1
                except queue.Empty:
                    pass

    def _drain(self) -> list[dict[str, Any]]:
        batch: list[dict[str, Any]] = []
        while len(batch) < self.batch_size:
            try:
                batch.append(self.q.get_nowait())
            except queue.Empty:
                break
        return batch

    def _send(self, batch: list[dict[str, Any]]) -> None:
        for attempt in range(3):
            try:
                self.client.post_events(batch)
                return
            except (httpx.HTTPError, ControlPlaneError) as exc:
                log.warning("event upload failed (attempt %d): %s", attempt + 1, exc)
                time.sleep(0.5 * 2**attempt)
        self.dropped += len(batch)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self.flush_interval)
            while batch := self._drain():
                self._send(batch)

    def flush(self) -> None:
        while batch := self._drain():
            self._send(batch)

    def close(self) -> None:
        self._stop.set()
        self.flush()


class ControlPlaneApprover:
    def __init__(self, client: ControlPlaneClient) -> None:
        self.client = client

    def request(self, decision: Decision, ctx: GuardContext, timeout: float) -> str:
        return self.client.create_approval(decision_event(decision, context=ctx.meta()), timeout)

    def status(self, approval_id: str) -> ApprovalStatus:
        try:
            return ApprovalStatus(self.client.approval_status(approval_id))
        except (httpx.HTTPError, ControlPlaneError, ValueError) as exc:
            log.warning("approval status check failed: %s", exc)
            return ApprovalStatus.PENDING


class ControlPlanePolicyStore(PolicyStore):
    def __init__(self, client: ControlPlaneClient, interval: float = 30.0) -> None:
        self.client = client
        self.interval = interval
        self._checked = 0.0
        self._digest: str | None = None
        self.last_error: str | None = None
        super().__init__(default_policy())
        self.refresh()

    def refresh(self) -> bool:
        self._checked = time.monotonic()
        try:
            data = self.client.active_policy()
        except (httpx.HTTPError, ControlPlaneError) as exc:
            self.last_error = str(exc)
            log.warning("could not fetch policy from control plane; keeping revision %s", self._policy.revision)
            return False
        if data is None or data.get("digest") == self._digest:
            return False
        try:
            policy = parse_policy(data["yaml"])
        except PolicyError as exc:
            self.last_error = str(exc)
            log.error("control plane returned an invalid policy: %s", exc)
            return False
        self._digest = data.get("digest")
        self.set(policy)
        log.info("policy %s revision %s loaded from control plane", policy.name, policy.revision)
        return True

    def get(self) -> Any:
        if time.monotonic() - self._checked >= self.interval:
            # Refresh in the background so policy checks never wait on the network.
            self._checked = time.monotonic()
            threading.Thread(target=self.refresh, daemon=True).start()
        return super().get()
