# Limitations

AgentGuard reduces risk; it does not eliminate it. Known limitations:

## Detection and taint tracking

- **Detection is probabilistic.** The heuristic rules and the classifier miss novel or paraphrased
  instructions, and the classifier has a 9% false-positive rate on its own test set.
- **Split payloads** (an attacker address the model assembles from two sources, or spells out as
  "collector at exfil dot example") may not match any single tainted segment.
- **Paraphrased content** that the model rewrites heavily can fall below fuzzy and shingle thresholds.
  The optional semantic matcher helps but needs an embedding model.
- **Assistant text** (for example a markdown image URL that leaks data when rendered) is not
  inspected; AgentGuard evaluates tool calls and tool results.
- **The classifier is English-only** and skips texts under four words.

## Deployment-specific

- **The MCP gateway cannot see the user's prompt** unless the client passes it, so values from tool
  output are treated as untrusted even when the user asked for them. That can cause approvals or
  blocks on legitimate requests.
- **The MCP gateway keeps session state in memory**; replicas need sticky sessions and a restart
  forgets taint history.
- **The LLM gateway's Responses API support** is non-streaming and requires the full input
  (`previous_response_id` conversations are rejected, because their history is not visible).
- **SDK helper methods** that cannot be guarded (OpenAI `.parse()` / `.stream()`, Anthropic
  `.stream()`) raise instead of running unprotected.

## Project status

- The **adversarial benchmark has not been run**; there are no end-to-end attack-removal numbers yet.
- **Live-model tests** need provider API keys and have not been run in this repository's CI.
- Latency figures were measured on a battery-throttled laptop; measure on your hardware.

## Policy design

Strict defaults trade convenience for safety: after an injection is detected in a session, even a
legitimate high-risk action needs approval. Tune rules for your tools and review false-positive
reports in the dashboard.
