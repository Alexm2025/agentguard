# REST API

Base path `/api/v1`. Authenticate with an API key (`X-AgentGuard-Key: ag_live_…` or
`Authorization: Bearer ag_live_…`) or a dashboard session cookie plus `X-CSRF-Token` for
state-changing requests. Outside production, interactive OpenAPI docs are served at `/api/docs`.

Resources of another organization always return `404`.

| Method | Path | Permission |
|---|---|---|
| POST | `/auth/login` · `/auth/logout` | — |
| GET | `/auth/me` | any |
| POST | `/auth/introspect` | service token (gateways) |
| GET · PATCH | `/org` · `/org/settings` | viewer · admin |
| GET · POST · PATCH · DELETE | `/members`, `/members/{user_id}` | admin |
| GET · POST | `/projects` | viewer · admin |
| GET · POST · DELETE | `/api-keys`, `/api-keys/{id}` | admin |
| POST | `/policies/validate` | viewer |
| GET · POST | `/policies` | viewer · admin |
| GET | `/policies/active` | `ingest` key or viewer |
| GET | `/policies/{id}` | viewer |
| POST | `/policies/{id}/versions`, `/policies/{id}/activate/{revision}` | admin |
| POST | `/events` (batch ≤ 500) | `ingest` |
| GET | `/events?action=&type=&tool=&session_id=&before=&limit=`, `/events/{id}` | `read` / viewer |
| POST | `/events/{id}/false-positive` | analyst |
| GET | `/false-positives` | viewer |
| POST | `/approvals` | `ingest` |
| GET | `/approvals?status=`, `/approvals/{id}` | viewer (status polling: `ingest`) |
| POST | `/approvals/{id}/resolve` | analyst or `approve` |
| POST | `/approvals/{id}/webhook-resolve` | signed token |
| GET | `/metrics/summary?hours=` | viewer |
| GET | `/audit`, `/audit/export`, `/audit/verify` | admin |
| GET | `/roles` | any |

Health endpoints: `GET /healthz` (process) and `GET /readyz` (database).

## Example: ship events

```bash
curl -X POST https://agentguard.internal/api/v1/events \
  -H "x-agentguard-key: $INGEST_KEY" -H "content-type: application/json" \
  -d '{"events": [{"id": "evt_1", "type": "tool_call", "tool": "send_email", "action": "BLOCK"}]}'
```

The organization always comes from the key, never from the payload; secrets in payloads are masked
again on the server.
