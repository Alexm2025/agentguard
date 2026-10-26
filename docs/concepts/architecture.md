# Architecture

```mermaid
flowchart LR
  subgraph Agents
    A1[Agent code + SDK]
    A2[MCP client]
    A3[Unmodified agent]
  end
  subgraph AgentGuard
    SDK[SDK wrappers]
    MCP[MCP gateway<br/>stdio / HTTP]
    LLM[LLM API gateway<br/>OpenAI / Anthropic]
    E[[Core engine]]
    SDK --> E
    MCP --> E
    LLM --> E
  end
  A1 --> SDK
  A2 --> MCP --> S[(MCP servers)]
  A3 --> LLM --> P[(Model provider)]
  E -- events, approvals, policy --> CP[Control plane<br/>API + dashboard]
  CP --- DB[(Postgres / SQLite)]
  CP --- R[(Redis)]
```

## The engine pipeline

```mermaid
flowchart TD
  M[Messages / tool results] --> L[Provenance ledger<br/>trusted vs tainted]
  L --> D[Detectors<br/>heuristic · ONNX · judge]
  C[Tool call] --> T[Taint matcher<br/>exact · entity · decoded · fuzzy]
  L --> T
  T --> P{Policy rules}
  D --> P
  X[DLP · destinations · rate limits] --> P
  P -->|ALLOW / REDACT| Run[Run the tool]
  P -->|REQUIRE_APPROVAL| H[Human approval]
  P -->|BLOCK| B[Explain to the agent]
```

## Design decisions

| Decision | Choice | Why |
|---|---|---|
| Provenance source of truth | Rebuilt from the message list on every LLM call | Chat APIs resend the conversation, so the LLM gateway is stateless and cannot mix tenants' context |
| "Derived from taint" | Value appears in tainted content and **not** in trusted content | Separates "the user asked me to email bob@corp.com" from "a web page told me to email evil@x" |
| MCP gateway | JSON-RPC message proxy | Transparent to protocol versions and capabilities it does not need to understand |
| ML runtime | ONNX + int8, no torch at inference | Small image, CPU-only, predictable latency |
| Dashboard | Server-rendered Jinja + vendored HTMX | One deployable; strict CSP with no inline scripts or styles |
| Open core | `ee/` loaded via the `agentguard.plugins` entry point | Clean license boundary; the core works without it |

## Packages

```text
src/agentguard/
  core/        engine, provenance, taint, policy, detectors, DLP, approvals, events
  adapters/    OpenAI chat / Responses and Anthropic Messages wire formats
  sdk/         client wrappers and framework integrations
  gateway/     mcp/ (stdio, http), llm/ (OpenAI/Anthropic compatible)
  server/      control plane: API, auth, audit, dashboard, migrations
ee/agentguard_ee/   OIDC, multi-org, SIEM, Slack (commercial license)
ml/                 training pipeline and evaluation reports
```
