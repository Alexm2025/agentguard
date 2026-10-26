# Detectors

Detectors score tainted content (tool results, MCP tool descriptions) for injected instructions.
Results are cached by content hash, so each result is scanned once per process.

| Layer | What it is | Cost |
|---|---|---|
| `heuristic` | weighted regex rules combined with noisy-OR; multilingual phrasings; decodes base64, hex, percent-encoding, ROT13 and Unicode tag smuggling and rescans | < 1 ms |
| `ml` | ELECTRA-small classifier, int8 ONNX, sliding windows over long inputs | ~20-50 ms per 128-token window on a laptop CPU |
| `judge` | an LLM asked whether a high-risk call serves the user's task | one model call; only for configured risk levels in tainted context |

```yaml
settings:
  detectors:
    heuristic: { enabled: true, threshold: 0.5 }
    ml: { enabled: true, model: auto, threshold: 0.875, min_words: 4 }
    judge: { enabled: false, provider: openai, model: gpt-4.1-mini, min_risk: high, on_block: BLOCK }
    scan_tool_descriptions: true
```

## How detections become decisions

A detection does not block on its own. Policy rules use it:

- `injection_detected: true` with `min_risk: critical` → BLOCK destructive actions while injected
  text is in context.
- With `tainted_args: any` on high-risk sinks → BLOCK.
- Otherwise on high-risk sinks → REQUIRE_APPROVAL.

Tool results can also be handled directly: `result.on_injection: REDACT` removes flagged passages
and adds a warning; `BLOCK` withholds the whole result from the model.

## The judge is advisory

The judge sees attacker-controlled text, so its verdict can only *add* a block; it never turns
another rule's BLOCK into ALLOW. If it errors on a high-risk call with `fail_mode: closed`, the call
is blocked.
