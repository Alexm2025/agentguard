# ML classifier

A fine-tuned **ELECTRA-small discriminator** (Apache-2.0, 14M parameters) exported to ONNX and
quantized to int8 (14 MB). It runs with onnxruntime and the `tokenizers` library, with no PyTorch
at inference time.

## Results (held-out test set)

| Weights | Threshold | Precision | Recall | F1 | FPR | AUROC |
|---|---|---|---|---|---|---|
| int8 (shipped) | 0.875 | 0.904 | 0.968 | 0.935 | 0.090 | 0.985 |

The threshold was chosen on the validation split for FPR ≤ 2%; on the test split the FPR came
out at 9.0%, driven mostly by the template-based hard negatives (56% accuracy). Full report with
per-source accuracy and latency:
[ml/reports/injection-classifier-v1.md](https://github.com/Alexm2025/agentguard/blob/main/ml/reports/injection-classifier-v1.md).

## Training data

Only sources with explicit permissive licenses, each pinned to an exact Hugging Face revision
(`ml/datasets.yaml`):

| Source | License | Role |
|---|---|---|
| deepset/prompt-injections | Apache-2.0 | injections and benign queries |
| jackhhao/jailbreak-classification | Apache-2.0 | jailbreaks; benign persona prompts as hard negatives |
| yanismiraoui/prompt_injections | Apache-2.0 | multilingual injections |
| Lakera/gandalf_ignore_instructions | MIT | "ignore instructions" attacks |
| reshabhs/SPML_Chatbot_Prompt_Injection | MIT | chatbot injections |
| rajpurkar/squad (paragraphs) | CC-BY-SA-4.0 | benign documents and carriers for indirect-injection augmentation |

Two candidate datasets with no declared license were excluded. Whether CC-BY-SA share-alike
extends to trained weights is legally unsettled; review before redistributing the weights.

Indirect injection is approximated by embedding held-out injections into Wikipedia paragraphs,
with matched benign insertions so the model cannot learn "inserted text" as the signal. Hard
negatives are split by template so no template appears in more than one split.

## Reproduce

```bash
pip install -e ".[train]"
python ml/train.py --out ml/artifacts/injection-classifier-v1     # seeded; records the dataset digest
```

## Why not DeBERTa-v3?

It was the first choice, but on the available CPU its disentangled-attention backward pass was
impractically slow (one training step did not finish in 10 minutes). DistilBERT-multilingual trained
but missed the latency budget (p95 128 ms at 128 tokens on the same machine). ELECTRA-small is
English-only, so multilingual coverage relies on the heuristic layer.

## Known issue

v1 over-flags very short texts ("hello" scores 0.998). The ML layer skips inputs under
`min_words` (default 4); the heuristic layer still scans them.
