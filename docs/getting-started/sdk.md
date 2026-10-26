# Python SDK

## Guard your tools

```python
from agentguard import Guard

guard = Guard("agentguard.yaml")     # Guard() uses the built-in default policy

@guard.tool
def read_web(url: str) -> str:       # results are labelled untrusted and scanned
    ...

@guard.tool
def send_email(to: str, body: str) -> str:   # calls are evaluated before they run
    ...

with guard.session(system="You are a helpful assistant.", user="Summarize example.com and email me@acme.com"):
    page = read_web("https://example.com")
    send_email("me@acme.com", summarize(page))
```

A blocked call does not run. By default the wrapper returns an explanation to the agent; pass
`on_block="raise"` to get a `ToolCallBlocked` exception instead. Async tools work the same way.

## Guard the model client

Wrapping the client rebuilds provenance from the exact messages sent to the model and evaluates
every tool call in the response, so you do not need `guard.session(...)`:

=== "OpenAI"

    ```python
    from openai import OpenAI
    client = guard.wrap_openai(OpenAI())
    resp = client.chat.completions.create(model="gpt-4.1", messages=messages, tools=tools)
    ```

    Supported: `chat.completions.create` (including `stream=True`) and `responses.create`.
    Async clients work. Helpers that cannot be guarded (`.parse()`, `.stream()`) raise
    `AgentGuardError` rather than run unprotected.

=== "Anthropic"

    ```python
    from anthropic import Anthropic
    client = guard.wrap_anthropic(Anthropic())
    msg = client.messages.create(model="claude-sonnet-5-5", max_tokens=1024, messages=messages, tools=tools)
    ```

    Supported: `messages.create` including `stream=True`. `messages.stream()` raises.

Blocked tool calls are removed from the response and replaced with an explanatory message
(`mode="rewrite"`, default), or raise (`mode="raise"`).

## Approvals

`REQUIRE_APPROVAL` decisions wait for a human:

```python
from agentguard.core.approvals import console_approver
guard = Guard("agentguard.yaml", approver=console_approver())          # ask on the terminal
guard = Guard(control_plane_url="https://agentguard.internal",          # or the dashboard / Slack
              api_key="ag_live_...")
```

With a control plane, the policy is fetched from it (and hot-reloaded), events are shipped in the
background, and approvals appear in the dashboard queue.
