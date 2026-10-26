# Control plane

```bash
export AGENTGUARD_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
export AGENTGUARD_BOOTSTRAP_ADMIN_EMAIL=admin@example.com
export AGENTGUARD_BOOTSTRAP_ADMIN_PASSWORD='a-long-password'
agentguard server run --migrate          # http://127.0.0.1:8000
agentguard server seed-demo              # optional: demo sessions for a first look
```

SQLite is the default; use `AGENTGUARD_DATABASE_URL=postgresql+psycopg://...` and
`AGENTGUARD_REDIS_URL` in production.

## Dashboard

- **Events** - live feed with a 24-hour summary. Each blocked call shows its *attack path*: the
  untrusted source, the argument derived from it, the tool, and the decision.
- **Approvals** - pending requests with Approve / Deny; history with who decided and through
  which channel.
- **Policies** - editor with live validation; every save is a new, auditable revision.
- **Metrics** - blocks, approval rate, false-positive reports, decision latency.
- **Settings** - scoped API keys (shown once, stored hashed), members, audit-log verification.

## Roles

| Role | Can |
|---|---|
| viewer | read events, approvals, policies, metrics |
| analyst | + resolve approvals, report false positives |
| admin | + edit policies, manage keys and members, read the audit log |

API keys carry scopes instead of roles: `ingest` (SDKs and gateways), `read`, `approve`,
`gateway`, `admin`.
