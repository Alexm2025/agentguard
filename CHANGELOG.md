# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Plain-language console: a Home screen with a one-line status, an activity feed that describes every
  decision in everyday words with clear icons, and a step-by-step story for each stopped action.
- **Needs your OK** screen with large Allow / Don't allow buttons.
- **Protection rules** page: five on/off switches, fail-mode and approval-timeout choices; saves a new
  revision of the live policy, so changes can be undone in the advanced editor.
- Add teammates (email, role, temporary password) from the Team & keys page.
- Copy buttons on the Connect page; light theme by default, dark theme follows the system.

### Changed
- Sign-in now lands on Home. Technical details (attack path, detectors, arguments) are folded under
  "Technical details" on each event.

## [0.1.0] - 2026-10-27

### Added
- Core engine: provenance ledger, taint matcher (exact, substring, entity, decoded, fuzzy, shingle,
  optional semantic), declarative YAML policies with JSON Schema validation, `extends`, versioning
  and hot reload; DLP patterns with validators; destination allowlists; rate limits; fail-closed /
  fail-open handling.
- Detectors: heuristic rules (multilingual, encoded payloads, Unicode tag smuggling), ONNX
  ELECTRA-small classifier with a reproducible training pipeline, optional LLM judge.
- Python SDK: `Guard`, `@guard.tool`, wrappers for OpenAI (chat, streaming, Responses, async),
  Anthropic (messages, streaming, async), LangChain, LlamaIndex and the OpenAI Agents SDK.
- MCP gateway (stdio and streamable HTTP) with tool-description poisoning detection and rug-pull
  pinning.
- LLM API gateway compatible with OpenAI and Anthropic, including streaming; `--workers`.
- Control plane: REST API, RBAC (admin/analyst/viewer), scoped API keys, CSRF-protected sessions,
  approvals (dashboard, API, signed webhooks), hash-chained audit log, metrics, Alembic migrations.
- Dashboard: live events, attack-path view, approval queue, policy editor with live validation.
- Enterprise (`ee/`): OIDC SSO, multi-organization admin, SIEM export (syslog/CEF, webhook), Slack
  approvals.
- Deployment: Dockerfile (non-root), docker-compose stack, Helm chart, Render blueprint, CI and
  release workflows, load tests.
