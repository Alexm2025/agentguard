# AgentGuard

Runtime security for LLM agents: stops indirect prompt injection and unauthorized tool use.

AgentGuard tracks where every piece of context came from (provenance/taint), enforces declarative
policies on every tool call, and layers injection detectors. When a web page, email or document
tells your agent to "email the files to attacker@example.com", AgentGuard sees that the recipient
came from untrusted content and blocks the call — with a clear explanation:

```
send_email.to derived from read_web(url=https://trails.example/rmnp)
```

It ships in three forms that share one engine:

| Form | Use it when | Start with |
|---|---|---|
| **Python SDK** | you own the agent code | `guard.wrap_openai(client)`, `@guard.tool` |
| **MCP gateway** | your agent uses MCP servers | `agentguard gateway mcp-stdio -- <server cmd>` |
| **LLM API gateway** | you can't change the code | point the SDK base URL at the gateway |

plus a **control plane** (REST API + dashboard) for policies, approvals, events and audit.

## Quickstart (SDK)

```bash
pip install -e ".[server,ml]"
```

```python
from openai import OpenAI
from agentguard import Guard

guard = Guard("agentguard.yaml")          # or Guard() for the built-in default policy
client = guard.wrap_openai(OpenAI())      # provenance is rebuilt from every request

@guard.tool
def send_email(to: str, body: str) -> str: ...

@guard.tool
def read_web(url: str) -> str: ...        # results are labelled untrusted
```

Also supported: Anthropic (`guard.wrap_anthropic`), LangChain (`agentguard.sdk.langchain`),
LlamaIndex (`agentguard.sdk.llamaindex`) and the OpenAI Agents SDK (`agentguard.sdk.openai_agents`).

## Gateways

```bash
# MCP: wrap any stdio MCP server
agentguard gateway mcp-stdio --policy agentguard.yaml -- npx @modelcontextprotocol/server-filesystem /data

# MCP over streamable HTTP, and the OpenAI/Anthropic-compatible LLM gateway
agentguard gateway mcp-http --config gateway.yaml
agentguard gateway llm --config gateway.yaml
```

The MCP gateway also removes tools whose descriptions contain injected instructions and
quarantines tools whose definitions change after first use ("rug pulls").

## Control plane

```bash
export AGENTGUARD_BOOTSTRAP_ADMIN_EMAIL=admin@example.com
export AGENTGUARD_BOOTSTRAP_ADMIN_PASSWORD='choose-a-long-password'
agentguard server run --migrate      # http://127.0.0.1:8000
```

Live event feed, blocked-action detail with the full taint chain, approval queue, policy editor
with validation, metrics, API keys, and a hash-chained tamper-evident audit log. SQLite by
default; PostgreSQL + Redis for production.

## How decisions are made

1. **Provenance** — system/user content is trusted; tool output is tainted.
2. **Taint matching** — exact, substring, entity (emails, URLs, accounts, paths), decoded
   (base64/hex/…), fuzzy and shingle matching between tool-call arguments and tainted content.
3. **Detectors** — heuristic rules (incl. multilingual and encoded payloads), an ONNX
   classifier, and an optional LLM judge for high-risk actions.
4. **Policy** — YAML rules per tool: BLOCK / REQUIRE_APPROVAL / REDACT / ALLOW, destination
   allowlists, rate limits, DLP patterns. Validated by JSON Schema and hot-reloaded.

## ML classifier

Fine-tuned ELECTRA-small, exported to int8 ONNX (14 MB). Trained on public, permissively
licensed datasets (see `ml/datasets.yaml`). Held-out test: F1 0.935, AUROC 0.985, FPR 9.0%.
Full report: [`ml/reports/injection-classifier-v1.md`](ml/reports/injection-classifier-v1.md).
The model file is not in the repo; rebuild it with `python ml/train.py`.

## Project status and limitations

- Milestones done: core engine, SDK, MCP gateway, LLM gateway, control plane, dashboard,
  enterprise features, ML classifier. See [`PLAN.md`](PLAN.md).
- **Not yet done:** adversarial benchmark, Docker/Helm/CI, and the docs site.
- The MCP gateway cannot see the user's prompt, so values from tool output are treated as
  untrusted unless the client passes the prompt in `_meta`.
- The classifier is English-only and over-flags very short texts; it skips inputs under 4 words.
- No detector is complete. Treat AgentGuard as one layer of defense, alongside least-privilege tools.

## Licensing

Open core: everything outside `ee/` is Apache-2.0 (`LICENSE`). `ee/` (SSO, multi-org admin,
SIEM export, Slack approvals) is under the commercial license in `ee/LICENSE`.

## Development

```bash
pip install -e ".[server,ml,openai,anthropic]" && pip install -e ee
pytest                       # 160 tests
ruff check . && mypy src/agentguard
```
