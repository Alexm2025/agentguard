# Configuration

Control-plane variables also accept a `*_FILE` form (for example `AGENTGUARD_SECRET_KEY_FILE`) that
reads the value from a file, for Docker and Kubernetes secrets.

## Control plane

| Variable | Default | Notes |
|---|---|---|
| `AGENTGUARD_ENV` | `development` | `production` requires a secret key and enables secure cookies |
| `AGENTGUARD_DATABASE_URL` | `sqlite+aiosqlite:///./agentguard.db` | Postgres: `postgresql+psycopg://user:pass@host/db` |
| `AGENTGUARD_REDIS_URL` | unset | Redis-backed rate limiting across replicas |
| `AGENTGUARD_SECRET_KEY` | random (dev only) | ≥ 32 chars; signs CSRF and webhook tokens |
| `AGENTGUARD_SERVICE_TOKEN` | unset | bearer token gateways use for key introspection |
| `AGENTGUARD_PUBLIC_URL` | `http://localhost:8000` | links in webhooks, Slack, OIDC redirects |
| `AGENTGUARD_ALLOWED_ORIGINS` | empty | comma-separated CORS origins |
| `AGENTGUARD_SESSION_TTL_HOURS` | `12` | |
| `AGENTGUARD_BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` | unset | first org + admin when the database has no users |
| `AGENTGUARD_EVENT_RETENTION_DAYS` | `90` | used by `agentguard server prune` |
| `AGENTGUARD_TRUST_PROXY_HEADERS` | `false` | honour `X-Forwarded-For` behind a trusted proxy |
| `AGENTGUARD_HOST` / `AGENTGUARD_PORT` | `127.0.0.1` / `8000` | |
| `AGENTGUARD_TLS_CERT` / `AGENTGUARD_TLS_KEY` | unset | serve TLS directly |

## SDK and gateways

| Variable | Notes |
|---|---|
| `AGENTGUARD_API_KEY` | ingest-scoped key for events, approvals and policy fetch |
| `AGENTGUARD_CONTROL_PLANE_URL` | control plane base URL |
| `AGENTGUARD_POLICY` | local policy file (gateways) |
| `AGENTGUARD_GATEWAY_CONFIG` | gateway YAML (see below) |
| `AGENTGUARD_WORKERS` | LLM gateway worker processes |
| `AGENTGUARD_MODEL_DIR` | classifier directory; when set, no other location is searched |
| `AGENTGUARD_JUDGE_API_KEY` / `AGENTGUARD_JUDGE_BASE_URL` | LLM judge credentials (fallback: `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`) |

## Gateway file

```yaml
policy: ./agentguard.yaml
pins_file: ./.agentguard-pins.json     # MCP tool-definition pins
events_file: ./events.jsonl            # optional local event log
auth:
  mode: static                         # static | control_plane | none (development only)
  keys: { "<sha256 of key>": { tenant_id: acme, project_id: support-bot } }
control_plane: { url: https://agentguard.internal, token_env: AGENTGUARD_SERVICE_TOKEN }
mcp:
  on_poisoned_tool: remove
  on_changed_tool: remove
  servers:
    - { name: github, url: https://api.githubcopilot.com/mcp/, headers: { Authorization: "Bearer ${GITHUB_TOKEN}" } }
llm: { openai_base_url: https://api.openai.com, anthropic_base_url: https://api.anthropic.com, strict: false }
```

`${VAR}` is expanded from the environment, so secrets stay out of the file.

## Enterprise (`ee/`)

| Variable | Feature |
|---|---|
| `AGENTGUARD_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_ORG_SLUG`, `_DEFAULT_ROLE`, `_ROLE_CLAIM`, `_ROLE_MAP`, `_ALLOWED_DOMAINS` | SSO |
| `AGENTGUARD_PLATFORM_ADMINS` | who may create organizations |
| `AGENTGUARD_SIEM_SYSLOG` (`udp://`, `tcp://`, `tls://`), `_SYSLOG_CA`, `_WEBHOOK_URL`, `_WEBHOOK_SECRET`, `_MIN_ACTION` | SIEM export |
| `AGENTGUARD_SLACK_BOT_TOKEN`, `_SIGNING_SECRET`, `_CHANNEL`, `_APPROVER_IDS` | Slack approvals |
