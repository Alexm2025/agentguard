# Evaluation report: injection-classifier-v1

- Base model: `google/electra-small-discriminator` @ `fa8239aadc09`
- Shipped weights: **int8** (14.1 MB). Threshold chosen on validation for FPR <= 2%: **0.875**
- Dataset digest: `27f9f8c882d43aed8a1d302fd98d877a908bd07920412c9b00a2f68ab7b05c7e` (sizes: {'train': 13789, 'validation': 1718, 'test': 1731})

## Test set (held out)

| weights | threshold | precision | recall | F1 | FPR | AUROC |
|---|---|---|---|---|---|---|
| fp32 | 0.5 | 0.895 | 0.968 | 0.930 | 0.098 | 0.985 |
| fp32 | 0.64 | 0.903 | 0.966 | 0.934 | 0.090 | 0.985 |
| int8 | 0.5 | 0.880 | 0.970 | 0.923 | 0.114 | 0.985 |
| int8 | 0.875 | 0.904 | 0.968 | 0.935 | 0.090 | 0.985 |

## Per-source accuracy (shipped weights, chosen threshold)

| source | n | positives | accuracy |
|---|---|---|---|
| deepset | 68 | 27 | 0.926 |
| gandalf | 101 | 101 | 0.990 |
| hard_negative | 80 | 0 | 0.562 |
| indirect_aug | 624 | 312 | 0.917 |
| jailbreak_classification | 199 | 66 | 0.965 |
| multilingual_injections | 98 | 98 | 1.000 |
| spml | 397 | 200 | 0.982 |
| squad | 164 | 0 | 0.988 |

## CPU latency (batch 1, onnxruntime, 4 intra-op threads, 18 logical CPUs)

| input | p50 ms | p95 ms | max ms |
|---|---|---|---|
| 64_tokens | 16.35 | 22.47 | 25.84 |
| 128_tokens | 37.16 | 46.34 | 52.64 |
| 256_tokens | 67.21 | 94.8 | 105.45 |
| 512_tokens_2_chunks | 130.01 | 167.1 | 185.37 |

## Caveats

- Most public datasets contain *direct* prompt injections and jailbreaks. Indirect injections are
  approximated by embedding held-out injections in Wikipedia paragraphs (`indirect_aug`). Real
  tool outputs (HTML, email threads, JSON) differ; see the adversarial benchmark for end-to-end numbers.
- Hard negatives are template-generated and split by template, so they test generalisation to
  unseen phrasings only weakly.
- The base model is English-centric; multilingual recall relies partly on the heuristic layer.
