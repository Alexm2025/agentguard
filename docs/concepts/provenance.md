# Provenance and taint

## Labels

Every piece of context is a *segment* in a per-session ledger:

| Origin | Label |
|---|---|
| system, developer, user | **trusted** |
| tool result | **tainted**, unless the tool is configured with `trusted_output: true` |
| assistant | tainted if any tainted segment came before it (the model may have been steered) |

## Matching tool-call arguments

For each argument value (nested values are flattened to dotted paths such as `recipients.0`), the
matcher looks for evidence in tainted segments, cheapest check first:

| Kind | Fires when |
|---|---|
| `exact` / `substring` | the normalized value equals or occurs in a segment (min 8 chars) |
| `contains` | the value embeds a whole tainted segment |
| `entity:*` | an email, URL, domain, IP, path or long number in the value occurs in a segment |
| `decoded:*` | the same, after base64 / hex / percent / Unicode-tag decoding (of the value *or* the segment) |
| `fuzzy` | RapidFuzz partial ratio ≥ 88 (values ≥ 24 chars) |
| `shingle` | ≥ 60% of the value's word 3-grams occur in the segment |
| `semantic` | embedding cosine similarity (optional, needs an embedder) |

Normalization folds case, strips zero-width and bidi characters, applies NFKC, and folds
Cyrillic/Greek look-alikes in mixed-script words (`pаypal` → `paypal`).

A match is **derived** when the same evidence does *not* also appear in trusted content. Only
derived matches trigger the `tainted_args` rule conditions, and they produce the taint chain shown
in events and the dashboard:

```text
send_email.to derived from read_web(url=https://trails.example/rmnp) (entity:email, score=1.00)
```

## Destination arguments

`tainted_args: destination` selects arguments that say *where* data goes: anything listed in a
tool's `destination_args` or `destinations`, plus conventional names (`to`, `cc`, `url`,
`webhook`, `channel`, `account`, `iban`, `path`, `repo`, …). The default policy blocks high-risk
sinks whose destination is derived from taint.

## Known gaps

Split payloads (an attacker address assembled by the model from two sources) and paraphrased
instructions can evade taint matching; the detectors and policy rules that react to *injection in
context* are the backstop. See [Limitations](../limitations.md).
