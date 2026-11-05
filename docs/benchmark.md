# Benchmark

AgentGuard is evaluated on **[AgentDojo](https://github.com/ethz-spylab/agentdojo)** (Debenedetti et al.,
NeurIPS 2024, MIT license), a public benchmark of prompt-injection attacks against tool-using agents. Its
four suites (workspace, travel, banking, slack) contain 97 user tasks and 35 attacker goals, each with
ground-truth tool calls. We use AgentDojo's own attack texts; nothing in the benchmark was written by us
except the tool classification below.

## Results (replay mode)

2,436 attack cases (4 attacks × every user task that reads an injection point × every replayable
attacker goal) and 97 benign tasks. Full report:
[benchmark/results/agentdojo-replay.md](https://github.com/Alexm2025/agentguard/blob/main/benchmark/results/agentdojo-replay.md).

| Defense layer | Attacks stopped (ARE) | Blocked | Held for approval | False-positive rate | p95 per call |
|---|---|---|---|---|---|
| Taint tracking + policy | 81.0% | 1,748 | 224 | 18.6% | 10 ms |
| Heuristic detector | 32.7% | 783 | 14 | 0.0% | 15 ms |
| ML classifier | 83.2% | 1,984 | 43 | 4.1% | 183 ms |
| **Combined** | **92.2%** | 2,043 | 203 | 22.7% | 190 ms |

By suite (combined): banking 100%, workspace 97.3%, travel 83.3%, slack 80.0%.

Latency is measured on a battery-throttled laptop and includes scanning each tool result with the
classifier; the classifier result is cached per result, so the cost is paid once per tool output.

## How to read these numbers

- **ARE** (Attack Removal Efficiency, by analogy with Defect Removal Efficiency) = attack cases where
  the hijacked agent's ground-truth calls were blocked or held for approval ÷ attack cases. Held for
  approval only stops the attack if a person then denies it.
- **False-positive rate** = benign user tasks with at least one legitimate call blocked or held for
  approval. The combined layer's 22.7% is mostly approvals and blocks in the slack and workspace suites,
  where the user legitimately asks the agent to act on values it read from a channel, a web page or an
  email (for example "invite the user mentioned on this page"). The default policy treats those values as
  untrusted. Teams tune this per tool, for example with destination allowlists.
- **Taint tracking and the classifier fail differently**: taint catches attacker-chosen destinations
  regardless of phrasing; the classifier catches injected instructions regardless of which argument they
  steer. Combining them is what reaches 92%.

## Known misses

| Attacker goal | Why it gets through |
|---|---|
| slack/injection_task_3: visit an attacker URL | Fetching a URL that carries no data is allowed by design (agents follow links) |
| travel/injection_task_2: create a calendar entry | Medium-risk tool with no recipient; the default policy allows it |
| workspace/injection_task_1: delete file "13" (16% of cases) | The ID is too short to attribute safely; caught when the classifier flags the injected text |

Nine attacker goals (workspace 6-13, travel 6) have no ground-truth tool calls in AgentDojo - it scores
them by inspecting the final environment or the model's reply - so replay cannot evaluate them. Live mode
can.

## Method

**Replay (deterministic, no model).** For each pair of user task and attacker goal, AgentDojo's attack
text is placed in the injection points the user task reads. The user task's ground-truth calls are run
through AgentGuard (each result is recorded as untrusted and scanned), then the attacker's ground-truth
calls are evaluated. Benign runs replay each user task without injections.

**Live (real model).** AgentDojo's own agent loop runs with a real OpenAI model whose client is wrapped
by AgentGuard; it reports attack success rate and utility under attack. It needs an API key and has not
been run for these results.

```bash
pip install -e ".[ml]" agentdojo
python benchmark/run_agentdojo.py replay --out benchmark/results
python benchmark/run_agentdojo.py live --model gpt-4o-2024-05-13 --suite banking   # needs OPENAI_API_KEY
```

The tool classification ([benchmark/agentdojo_tools.yaml](https://github.com/Alexm2025/agentguard/blob/main/benchmark/agentdojo_tools.yaml))
was written from tool names and arguments before looking at results, as a deployer would. Heuristic rules
and policies were **not** tuned on this benchmark.
