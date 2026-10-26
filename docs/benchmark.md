# Benchmark

!!! warning "Not run yet"
    The adversarial benchmark has **not** been built or run. No attack-removal or false-positive
    numbers are published for AgentGuard as a whole yet. The numbers elsewhere in these docs cover
    individual components (the classifier's held-out test set, and latency).

## Planned methodology

The benchmark will be built on an established public prompt-injection suite for tool-using
agents (for example AgentDojo or InjecAgent) rather than a home-grown attack corpus, so results are
comparable with other defenses.

**Replay mode (deterministic).** Each scenario's recorded trajectory (user task, tool calls, tool
results containing the injection, and the action a compromised agent takes) is fed through the
engine. An attack is *removed* when the compromised action is blocked or held for approval
(reported separately).

**Live mode.** A real model runs the agent loop through the SDK wrapper. An attack succeeds only if
the model attempts the injected action *and* AgentGuard allows it, which separates model robustness
from AgentGuard's contribution.

**Metrics, per defense layer and combined:**

- **Attack Removal Efficiency (ARE)** = attacks stopped / attacks attempted, analogous to Defect
  Removal Efficiency.
- **False-positive rate** on benign workflows, counting blocks and approval requests separately.
- **Latency overhead** p50/p95 per layer.

**Layers:** taint/policy only, heuristic detector only, ML classifier only, LLM judge, and all
combined, each evaluated with the same scenarios.
