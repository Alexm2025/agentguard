# Performance

All numbers below were measured on the development machine: an **Intel Core Ultra 5 125H laptop
running on battery at ~1.2 GHz** (Windows, Balanced power plan). Expect better results on server
CPUs; rerun the scripts on your hardware before relying on them.

## LLM gateway overhead

`deploy/loadtest/gateway_overhead.py` runs the real gateway in front of a stub upstream with a
50 ms delay and sends agent conversations (system, user, tool call, ~900-character tool result).
Overhead comes from the `x-agentguard-overhead-ms` header and excludes upstream time. Heuristic
detector + taint + policy; ML layer off.

| Concurrency (one process) | p50 | p95 | p99 |
|---|---|---|---|
| 1 | 7.3 ms | 9.0 ms | 10.7 ms |
| 4 | 7.3 ms | 14.2 ms | 18.8 ms |
| 16 | 24.3 ms | 33.5 ms | 39.7 ms |

The per-request cost is about 7 ms; at 16 concurrent requests in one process, time is spent
queuing for the interpreter. The 30 ms p95 target therefore needs more than one process at that
load: the LLM gateway is stateless, so use `--workers` and replicas.

```bash
python deploy/loadtest/gateway_overhead.py --requests 2000 --concurrency 16 [--ml]
```

For a deployed gateway with a real provider, use `deploy/loadtest/locustfile.py`; it reports the
gateway overhead as a separate metric.

## ML classifier

int8 ONNX, batch 1, 4 intra-op threads:

| Input | p50 | p95 |
|---|---|---|
| 64 tokens | 16 ms | 22 ms |
| 128 tokens | 37 ms | 46 ms |
| 256 tokens | 67 ms | 95 ms |
| 512 tokens (2 windows) | 130 ms | 167 ms |

Each distinct tool result is scanned once (results are cached by content hash), so the cost is paid
when a result arrives, not on every later tool call.
