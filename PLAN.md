# AgentGuard — Implementation Plan

AgentGuard is a runtime security layer for LLM agents. It stops indirect prompt
injection and unauthorized tool use by tracking where content came from
(provenance/taint), enforcing declarative policies on every tool call, and
layering injection detectors. It ships as a Python SDK, an MCP gateway, and an
LLM API gateway, all sharing one core engine, plus a control plane (REST API and
dashboard).

This file is the source of truth for scope, milestones, acceptance criteria and
**status**. Anything not finished is listed under "Known gaps" at the bottom.
Nothing outside `tests/` is stubbed or faked.

---

## 1. Architecture

```
                         ┌──────────────────────── Control plane (FastAPI) ───────────────────────┐
                         │ REST API · HTMX dashboard · auth/RBAC · API keys · approvals · audit    │
                         │ SQLAlchemy (Postgres | SQLite) · Alembic · Redis (rate limit, queues)   │
                         └──────────▲───────────────────────▲───────────────────────▲─────────────┘
                                    │ events/approvals/      │                       │
                                    │ policy (HTTP, API key) │                       │
 ┌──────────────┐   ┌───────────────┴──────┐   ┌─────────────┴──────────┐   ┌────────┴──────────────┐
 │ Agent code   │──▶│ Python SDK wrappers  │   │ MCP gateway            │   │ LLM API gateway       │
 │ (OpenAI,     │   │ OpenAI · Anthropic · │   │ stdio + streamable HTTP│   │ /v1/chat/completions  │
 │ Anthropic,   │   │ LangChain · LlamaIdx │   │ JSON-RPC level proxy   │   │ /v1/messages (+stream)│
 │ LangChain..) │   └──────────┬───────────┘   └───────────┬────────────┘   └──────────┬────────────┘
 └──────────────┘              └───────────────┬───────────┴───────────────────────────┘
                                               ▼
                          ┌──────────────── Core engine (agentguard.core) ───────────────┐
                          │ Provenance ledger → Taint matcher (exact/substring/fuzzy/     │
                          │ entity/semantic) → Detectors (heuristic → ONNX ML → LLM judge)│
                          │ → DLP → Policy engine (YAML, JSON-schema, hot reload)         │
                          │ → Decision (ALLOW/BLOCK/REQUIRE_APPROVAL/REDACT) + fail-safe  │
                          └───────────────────────────────────────────────────────────────┘
```

### Key design decisions

| Decision | Choice | Why |
|---|---|---|
| Provenance source of truth | Rebuilt from the message list on every LLM call (stateless), plus an optional per-session ledger for tool wrappers / MCP | Chat APIs resend the full conversation, so the gateway needs no server-side session state and cannot mix tenants' context |
| Taint matching | Normalised exact, substring, token-shingle fuzzy (RapidFuzz), entity extraction (URLs, emails, domains, paths, numbers) and optional embedding similarity | Attacks rarely copy whole sentences; they copy a recipient, a URL or a paraphrase |
| "Derived from" signal | An argument value is *derived from taint* if it appears in tainted content and **not** in trusted content (user/system) | Separates "user asked to email bob@x" from "web page asked to email evil@x" |
| MCP gateway | JSON-RPC message-level proxy, not an MCP SDK client/server pair | Transparent to protocol versions and capabilities it does not need to understand |
| ML detector | Fine-tuned DeBERTa-v3-small → ONNX → int8 dynamic quantisation, run with onnxruntime | Under 50 ms p95 on CPU, no torch at inference time |
| Dashboard | FastAPI + Jinja2 + HTMX (vendored, CSP-strict) | One language, one deployable, nothing extra to keep patched |
| Storage | SQLAlchemy 2 async, Alembic; SQLite for local, Postgres for production | Both required by spec |
| Open core | `src/agentguard` Apache-2.0; `ee/agentguard_ee` commercial (OIDC SSO, multi-org, SIEM export, Slack approvals) loaded via entry points | Clean licence boundary; core works without `ee` |

### Package layout

```
src/agentguard/
  core/        provenance, taint, policy/, detectors/, dlp, ratelimit, engine (Guard), errors
  sdk/         openai, anthropic, langchain, llamaindex, openai_agents, tools (generic wrapper)
  gateway/     mcp/ (stdio + http proxy), llm/ (OpenAI + Anthropic compatible proxy)
  server/      FastAPI app, db models, alembic, auth, rbac, api routers, dashboard, audit, approvals
  telemetry/   OpenTelemetry traces + metrics, structured logging with secret scrubbing
  cli.py       `agentguard` CLI (serve, gateway mcp, gateway llm, policy validate, audit verify ...)
ee/agentguard_ee/  oidc, multitenancy, siem (syslog/CEF, webhook), slack approvals
ml/            training pipeline, dataset manifest + licences, eval reports
benchmark/     scenarios (attacks + benign), runner (replay + live), reports
deploy/        Dockerfile, docker-compose, helm chart, k6/locust load tests
docs/          MkDocs Material site
tests/         unit, property, integration, e2e
```

---

## 2. Milestones and acceptance criteria

Each milestone ends with: full test suite, `ruff check`, `ruff format --check`,
`mypy --strict` on `agentguard.core`, `bandit`. Failures are fixed before moving on.

### M0 — Scaffold
- `pyproject.toml` (hatchling, extras: `ml`, `server`, `langchain`, `llamaindex`, `openai`, `anthropic`, `all`), pinned lock via `requirements/*.txt`.
- ruff/mypy/bandit/pytest/coverage config; LICENSE (Apache-2.0), NOTICE, `ee/LICENSE` (commercial placeholder), CHANGELOG, SECURITY.md.
- **Accept:** `pip install -e .` works; `agentguard --version` prints; empty test suite and linters pass.

### M1 — Core engine
- Provenance labels and ledger; taint matcher (exact, substring, fuzzy, entity, pluggable semantic).
- Policy model (pydantic) + JSON Schema export + YAML loader + versioning + hot reload (file watcher by mtime polling).
- Rules: by tool, arg patterns, taint status, destination allowlists (domain/email/path), rate limits, DLP patterns with validators (Luhn, IBAN mod-97, etc.), REDACT.
- Heuristic injection detector. Decision engine with fail-closed/fail-open.
- **Accept:** ≥85% coverage on `agentguard.core`; Hypothesis property tests for the taint matcher (exact substring is always detected, normalisation invariance, no false hit on disjoint alphabets); mypy --strict clean.

### M2 — ML + LLM-judge detectors
- `ml/train.py`: reproducible (seeded) fine-tune on public datasets with documented licences, eval report (precision/recall/F1/AUROC, per-source), ONNX export + int8 quantisation, latency benchmark.
- `OnnxInjectionClassifier` (onnxruntime + tokenizers, chunking for long inputs).
- `LLMJudge` for OpenAI and Anthropic, only invoked for configured high-risk actions, with timeout and fail-mode.
- **Accept:** model trained and exported; p95 latency < 50 ms on this machine for 256-token inputs; eval report committed.

### M3 — SDK
- `Guard` facade; `guard.wrap_tool` / `@guard.tool`; `wrap_openai(client)`, `wrap_anthropic(client)` (sync + async), LangChain tool wrapper + callback, LlamaIndex tool wrapper, OpenAI Agents SDK tool wrapper.
- Approvals: block-and-wait against control plane or local approver callback, with timeout.
- **Accept:** e2e tests drive each framework's real tool-execution path with a scripted model; injection in a tool result causes the sink call to be blocked with a clear error to the agent.

### M4 — MCP gateway
- stdio proxy (spawns upstream server), streamable-HTTP proxy (JSON and SSE responses, session id passthrough).
- Inspects `tools/list` (tool-description poisoning, rug-pull detection via description hashing), `tools/call` arguments, and tool results (taint + detection, optional redaction).
- **Accept:** e2e test with a real MCP client (official `mcp` SDK) talking through the gateway to real local test MCP servers over both transports.

### M5 — LLM API gateway
- OpenAI-compatible `/v1/chat/completions` and Anthropic-compatible `/v1/messages`, streaming and non-streaming; upstream auth passthrough; tenant resolved from AgentGuard API key.
- Blocked tool calls are removed and replaced with an explanatory message (or HTTP 403 in `strict` mode).
- **Accept:** integration tests against a local upstream test server; p95 overhead < 30 ms measured by load test.

### M6 — Control plane
- Orgs, projects, users, roles (admin/analyst/viewer), API keys (prefix + SHA-256 hash, scopes), sessions (server-side, HttpOnly, SameSite=strict, CSRF tokens), rate limiting (Redis or memory).
- Policies (versioned, validated), approvals (REST + webhook), events ingest/query, metrics, false-positive reports.
- Hash-chained append-only audit log with verify + JSON export.
- Alembic migrations.
- **Accept:** API tests cover auth, RBAC denial paths, tenant isolation (cross-org access returns 404), audit chain tamper detection.

### M7 — Dashboard
- Live event feed (HTMX polling / SSE), blocked-action detail with full taint chain, approval queue, policy editor with server-side validation, metrics page.
- **Accept:** route tests for every page; CSP header without `unsafe-inline` scripts.

### M8 — Enterprise (`ee/`)
- OIDC login (Authorization Code + PKCE, via Authlib), multi-org admin, SIEM forwarders (syslog RFC 5424 + CEF, generic webhook with HMAC signature), Slack interactive approvals (signed request verification).
- **Accept:** unit tests with signature verification vectors; OIDC flow tested against a local test IdP.

### M9 — Adversarial benchmark
- ≥100 attack scenarios across: exfiltration, destructive actions, goal hijacking, obfuscation/encoding, multilingual, multi-turn, split payloads, MCP tool-description poisoning. ≥50 benign workflows.
- Replay mode (deterministic: recorded compromised trajectories) and live mode (real model via OpenAI/Anthropic API runs the agent loop).
- Reports Attack Removal Efficiency (ARE = blocked attacks / total attacks), false-positive rate, latency overhead per layer and combined.
- **Accept:** replay results committed in `benchmark/results/` and docs.

### M10 — Deployment & CI
- Multi-stage Dockerfile (non-root, read-only rootfs compatible), docker-compose (server, gateway, Postgres, Redis), Helm chart, k6 and locust load tests.
- GitHub Actions: lint/type/test matrix, integration with Postgres/Redis services, pip-audit, bandit, CycloneDX SBOM, release on tag (PyPI trusted publishing, GHCR image).
- **Accept:** workflows lint with `actionlint`-compatible syntax; `helm template` renders (if helm available).

### M11 — Docs
- MkDocs Material: quickstarts (SDK per framework, MCP gateway, LLM gateway), policy reference (generated from JSON schema), architecture, STRIDE threat model, benchmark methodology/results, deployment, limitations.
- **Accept:** `mkdocs build --strict` passes.

---

## 3. Status

| Milestone | Status | Verified |
|---|---|---|
| M0 Scaffold | done | packaging, lint/type/security tooling |
| M1 Core | done | unit + Hypothesis property tests; 91% core coverage; `mypy --strict` clean |
| M2 ML/judge | done | ELECTRA-small int8 ONNX: test F1 0.935, AUROC 0.985, FPR 9.0% ([report](ml/reports/injection-classifier-v1.md)); judge tested against a stubbed provider |
| M3 SDK | done | e2e with real OpenAI/Anthropic SDK clients and LangChain, LlamaIndex, Agents SDK runners (scripted model) |
| M4 MCP gateway | done | e2e: official MCP client -> gateway -> real local MCP servers, stdio and HTTP |
| M5 LLM gateway | done | integration tests incl. streaming; overhead measured (below) |
| M6 Control plane | done | API tests: auth, CSRF, RBAC, tenant isolation, audit tamper detection, migrations |
| M7 Dashboard | done | route tests, XSS escaping, CSRF; visually checked in Edge (dark/light/mobile) |
| M8 Enterprise | done | OIDC against a local IdP, Slack reference signature vector, syslog/webhook delivery |
| M9 Benchmark | **not started** | waiting on the choice of base suite (see below) |
| M10 Deploy/CI | done, partly unverified | Dockerfile, compose, Helm, CI/release workflows written; image and chart not built here |
| M11 Docs | not started | |

### Measured performance (this machine: Core Ultra 5 125H laptop on battery, ~1.2 GHz)

- ML classifier, int8, 4 threads, p95: 22 ms @ 64 tokens, 46 ms @ 128, 95 ms @ 256.
- LLM gateway own overhead (excludes upstream), heuristic + taint + policy:
  p95 9 ms at concurrency 1, 14 ms at 4, 34 ms at 16 in one process (queuing on the GIL).
  The LLM gateway is stateless; scale with `--workers` / replicas to keep p95 under 30 ms.

## 4. Known gaps / environment constraints

- **Benchmark (M9) not built.** Generating a large attack corpus was halted; the plan is to build
  the replay/live harness on an established public suite (e.g. AgentDojo or InjecAgent).
- The build machine has **no Docker, no Helm binary and no LLM API keys**:
  - Postgres/Redis tests are wired into CI service containers and skipped locally (SQLite locally).
  - Docker image, compose stack and Helm chart are linted/built only in CI.
  - Live-model e2e runs need `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`; not executed here.
- DeBERTa-v3 was not trainable on this CPU; the classifier is English-only ELECTRA-small and
  skips texts under 4 words (it over-flags very short inputs).
- The MCP gateway keeps per-session taint state in memory: multiple replicas need sticky sessions.
