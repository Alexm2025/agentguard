# LLM API gateway

Protect an agent without touching its code: point its SDK at AgentGuard.

```bash
agentguard gateway llm --config gateway.yaml --port 8200 --workers 4
```

=== "OpenAI SDK"

    ```python
    client = OpenAI(base_url="https://agentguard.internal/v1",
                    default_headers={"X-AgentGuard-Key": "ag_live_..."})
    ```

=== "Anthropic SDK"

    ```python
    client = Anthropic(base_url="https://agentguard.internal",
                       default_headers={"X-AgentGuard-Key": "ag_live_..."})
    ```

| Endpoint | Notes |
|---|---|
| `POST /v1/chat/completions` | including `stream=true` |
| `POST /v1/messages` | including `stream=true` |
| `POST /v1/responses` | non-streaming; requires the full `input` (no `previous_response_id`) |
| `GET /v1/models` | passthrough |

The provider credentials (`Authorization`, `x-api-key`) are forwarded upstream and never logged.

**How blocking looks to the agent.** Blocked tool calls are removed from the response and an
explanation is added to the assistant message. With `llm.strict: true` the gateway answers `403`
instead. Every response carries `x-agentguard-action`, `x-agentguard-event-ids` and
`x-agentguard-overhead-ms`.

The gateway rebuilds provenance from each request's message list, so it is stateless and scales
horizontally.
