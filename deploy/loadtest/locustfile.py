"""Locust load test for a deployed LLM gateway.

    AGENTGUARD_KEY=ag_live_... OPENAI_API_KEY=sk-... locust -f deploy/loadtest/locustfile.py --host https://agentguard.internal

Each simulated user replays an agent turn (user request, a web read, a tool result) and asks the
model for the next step. The gateway's own overhead is reported as a custom metric from the
``x-agentguard-overhead-ms`` response header, separately from end-to-end latency.
"""

from __future__ import annotations

import json
import os
import random

from locust import HttpUser, between, events, task

MODEL = os.environ.get("AGENTGUARD_LOAD_MODEL", "gpt-4.1-mini")
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "parameters": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}},
        },
    },
]


class AgentTurn(HttpUser):
    wait_time = between(0.5, 2)

    def on_start(self) -> None:
        self.client.headers.update(
            {
                "x-agentguard-key": os.environ["AGENTGUARD_KEY"],
                "authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            }
        )

    @task
    def chat(self) -> None:
        n = random.randint(1, 10_000)
        body = {
            "model": MODEL,
            "tools": TOOLS,
            "max_tokens": 64,
            "messages": [
                {"role": "user", "content": f"Summarize https://shop.example/p/{n} and email me@acme.com"},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {
                                "name": "read_web",
                                "arguments": json.dumps({"url": f"https://shop.example/p/{n}"}),
                            },
                        }
                    ],
                },
                {
                    "role": "tool",
                    "tool_call_id": "c1",
                    "content": "Option A is reliable. Option B has a longer warranty.",
                },
            ],
        }
        with self.client.post("/v1/chat/completions", json=body, name="chat.completions", catch_response=True) as r:
            overhead = r.headers.get("x-agentguard-overhead-ms")
            if overhead:
                events.request.fire(
                    request_type="AG",
                    name="gateway overhead",
                    response_time=float(overhead),
                    response_length=0,
                    exception=None,
                    context={},
                )
