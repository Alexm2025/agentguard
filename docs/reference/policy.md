# Policy guide

Policies are YAML, validated against a JSON Schema ([full reference](policy-schema.md)) and
hot-reloaded (file mtime or control-plane revision). An invalid edit is logged and the last good
policy stays active.

```yaml
version: 1
extends: default          # layer over the built-in default policy (use `none` to start empty)
name: support-bot
revision: 3

settings:
  fail_mode: closed       # engine errors block; `open` allows up to fail_open_max_risk
  approvals: { timeout_seconds: 300, on_timeout: BLOCK }

tools:
  search_docs:  { role: source, risk: low }
  read_ticket:  { role: source, risk: low, ref_arg: ticket_id, result: { on_injection: REDACT } }
  lookup_customer: { role: source, trusted_output: true }        # internal DB: results are trusted
  send_email:
    role: sink
    risk: high
    destination_args: [to]
    destinations:
      - { arg: to, kind: email, allow: ["*@acme.com"], on_violation: REQUIRE_APPROVAL }
    rate_limit: { max_calls: 20, per_seconds: 3600, scope: session }
    dlp: { patterns: [credit_card, us_ssn], on_match: REDACT }
  issue_refund: { role: sink, risk: critical, action: REQUIRE_APPROVAL }
  "github_*":   { role: sink, risk: medium }                      # glob keys

dlp_patterns:
  - { id: internal_ticket, regex: "TCK-\\d{6}", validator: none }

rules:
  - id: no-external-share
    tools: ["share_*"]
    when: { args: [{ path: email, not_matches: "@acme\\.com$" }] }
    action: BLOCK
    message: documents may only be shared inside ACME
  - id: allow-status-page
    tools: [http_post]
    when: { args: [{ path: url, matches: "^https://status\\.acme\\.com/" }] }
    action: ALLOW
    override: true        # wins over every other rule
```

## How a decision is made

1. Resolve the tool: exact key, then the first matching glob, then `settings.unknown_tool`
   (`role: sink, risk: medium` by default).
2. Collect reasons from: `tools.<name>.action`, DLP, destination rules, rate limits, the LLM judge,
   and every rule whose `tools` / `roles` / `min_risk` match and whose `when` conditions all hold.
3. An `ALLOW` rule with `override: true` that matches wins outright.
4. Otherwise the most severe action wins: `BLOCK` > `REQUIRE_APPROVAL` > `REDACT` > `ALLOW`.

## `when` conditions

| Condition | True when |
|---|---|
| `tainted_context: true` | any tainted content is in context |
| `tainted_args: [to, url] / any / destination` | those arguments are *derived* from tainted content |
| `taint_kinds: [entity, decoded]` | …restricted to these match kinds |
| `injection_detected: true` | a detector flagged tainted content in this session |
| `dlp: [aws_access_key] / any` | those DLP patterns matched the arguments |
| `destination_violation: true` | a destination rule was violated |
| `args: [{path, matches, not_matches, equals, in, min_len, max_len}]` | every argument condition holds |
| `judge_flagged: true` | the LLM judge flagged the call |

## Built-in DLP patterns

`aws_access_key`, `aws_secret_key`, `github_token`, `anthropic_key`, `openai_key`, `slack_token`,
`stripe_key`, `google_api_key`, `private_key`, `jwt`, `agentguard_key`, `password_assignment`
(entropy-checked), `credit_card` (Luhn), `iban` (mod-97), `us_ssn` (area/group/serial rules),
`email_address`, `phone_number`.

## Tools

```bash
agentguard policy init > agentguard.yaml       # start from the default policy
agentguard policy validate agentguard.yaml
agentguard policy schema > policy.schema.json  # for editor autocompletion
```
