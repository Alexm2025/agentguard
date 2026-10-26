# Approvals

A `REQUIRE_APPROVAL` decision pauses the call until a person decides, or the timeout passes
(`settings.approvals.timeout_seconds`, then `on_timeout: BLOCK` by default).

| Channel | How |
|---|---|
| Dashboard | **Approvals** page, Approve / Deny with an optional note |
| REST API | `POST /api/v1/approvals/{id}/resolve {"decision": "approve"}` (analyst or `approve` scope) |
| Webhook | AgentGuard POSTs `approval.created` signed with your secret (`x-agentguard-signature` = HMAC-SHA256 of `"{timestamp}.{body}"`). The payload contains single-purpose signed `approve_token` / `deny_token`; POST one to `resolve_url` to decide. |
| Slack (`ee/`) | an interactive message with buttons; only Slack users listed in `AGENTGUARD_SLACK_APPROVER_IDS` can decide |
| Local | `CallbackApprover(fn)` or `console_approver()` in the SDK |

Every resolution is written to the audit log with who decided, when and through which channel.

## Configure the webhook

```bash
curl -X PATCH https://agentguard.internal/api/v1/org/settings \
  -H "x-agentguard-key: $ADMIN_KEY" -H "content-type: application/json" \
  -d '{"approval_webhook_url": "https://ops.example/agentguard", "approval_webhook_secret": "…"}'
```
