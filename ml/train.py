"""Fine-tune, export and evaluate the AgentGuard injection classifier.

    python ml/train.py --out ml/artifacts/injection-classifier-v1

Produces ``model.onnx`` (int8 if quantisation costs < 1 F1 point, else fp32), ``tokenizer.json``,
``agentguard.json`` (metadata) and ``ml/reports/<name>.{json,md}``. Everything is seeded; the
dataset digest is recorded so a rebuild can be verified.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

import data as data_mod  # noqa: E402
from agentguard.core.detectors.ml import OnnxInjectionClassifier  # noqa: E402


def fetch_base_model(base: dict) -> str:  # type: ignore[type-arg]
    """Download the pinned base model once into ml/.cache/base and load it offline afterwards
    (online loading makes extra Hub calls that can hang)."""
    from huggingface_hub import snapshot_download

    os.environ.setdefault("HF_HUB_DISABLE_XET", "1")
    target = HERE / ".cache" / "base" / base["repo"].split("/")[-1]
    return str(
        snapshot_download(base["repo"], revision=base["revision"], allow_patterns=base.get("files"), local_dir=target)
    )


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)


def batches(enc: list[list[int]], labels: list[int], bs: int, rng: random.Random, shuffle: bool):  # type: ignore[no-untyped-def]
    idx = list(range(len(enc)))
    if shuffle:
        rng.shuffle(idx)
    # Bucket by length inside mega-batches: big CPU speed-up with dynamic padding.
    mega = bs * 50
    order: list[int] = []
    for i in range(0, len(idx), mega):
        order += sorted(idx[i : i + mega], key=lambda j: len(enc[j]))
    chunks = [order[i : i + bs] for i in range(0, len(order), bs)]
    if shuffle:
        rng.shuffle(chunks)
    for ch in chunks:
        width = max(len(enc[j]) for j in ch)
        ids = torch.zeros((len(ch), width), dtype=torch.long)
        mask = torch.zeros((len(ch), width), dtype=torch.long)
        for r, j in enumerate(ch):
            ids[r, : len(enc[j])] = torch.tensor(enc[j])
            mask[r, : len(enc[j])] = 1
        yield ids, mask, torch.tensor([labels[j] for j in ch])


@torch.no_grad()
def predict_torch(model, enc, labels, bs=64):  # type: ignore[no-untyped-def]
    model.eval()
    probs = np.zeros(len(enc))
    rng = random.Random(0)
    idx_order = list(range(len(enc)))
    # predict in original order
    for start in range(0, len(enc), bs):
        sl = idx_order[start : start + bs]
        width = max(len(enc[j]) for j in sl)
        ids = torch.zeros((len(sl), width), dtype=torch.long)
        mask = torch.zeros((len(sl), width), dtype=torch.long)
        for r, j in enumerate(sl):
            ids[r, : len(enc[j])] = torch.tensor(enc[j])
            mask[r, : len(enc[j])] = 1
        logits = model(input_ids=ids, attention_mask=mask).logits
        probs[start : start + len(sl)] = torch.softmax(logits, -1)[:, 1].numpy()
    del rng
    return probs


def metrics(y: np.ndarray, p: np.ndarray, thr: float) -> dict[str, float]:
    pred = (p >= thr).astype(int)
    prec, rec, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    neg = y == 0
    fpr = float((pred[neg] == 1).mean()) if neg.any() else 0.0
    out = {"precision": float(prec), "recall": float(rec), "f1": float(f1), "fpr": fpr, "n": len(y)}
    if len(set(y.tolist())) == 2:
        out["auroc"] = float(roc_auc_score(y, p))
    return out


def per_source(examples, p, thr):  # type: ignore[no-untyped-def]
    groups: dict[str, list[int]] = defaultdict(list)
    for i, e in enumerate(examples):
        groups[e.source].append(i)
    out = {}
    for src, ids in sorted(groups.items()):
        y = np.array([examples[i].label for i in ids])
        pred = (p[ids] >= thr).astype(int)
        acc = float((pred == y).mean())
        out[src] = {"n": len(ids), "positives": int(y.sum()), "accuracy": round(acc, 4)}
    return out


def pick_threshold(y: np.ndarray, p: np.ndarray, max_fpr: float) -> float:
    """Highest-recall threshold whose validation FPR stays under ``max_fpr``."""
    best_thr, best_rec = 0.99, -1.0
    for thr in np.linspace(0.05, 0.995, 190):
        m = metrics(y, p, float(thr))
        if m["fpr"] <= max_fpr and m["recall"] > best_rec:
            best_thr, best_rec = float(thr), m["recall"]
    return round(best_thr, 3)


def latency(clf: OnnxInjectionClassifier, tokens: int, n: int = 200) -> dict[str, float]:
    words = ("lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor " * 200).split()
    text = " ".join(words[: int(tokens * 0.75)])
    for _ in range(10):
        clf.predict_proba(text)
    times = []
    for _ in range(n):
        t = time.perf_counter()
        clf.predict_proba(text)
        times.append((time.perf_counter() - t) * 1000)
    times.sort()
    return {
        "p50_ms": round(times[n // 2], 2),
        "p95_ms": round(times[int(n * 0.95)], 2),
        "max_ms": round(times[-1], 2),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "artifacts" / "injection-classifier-v1"))
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--bs", type=int, default=16)
    ap.add_argument("--lr", type=float, default=5e-5)
    ap.add_argument("--max-length", type=int, default=128)
    ap.add_argument("--freeze-embeddings", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--seed", type=int, default=13)
    ap.add_argument("--max-fpr", type=float, default=0.02)
    ap.add_argument("--limit", type=int, default=0, help="debug: cap training examples")
    ap.add_argument("--eval-limit", type=int, default=0, help="debug: cap validation/test examples")
    args = ap.parse_args()

    from onnxruntime.quantization import QuantType, quantize_dynamic
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        get_linear_schedule_with_warmup,
    )

    set_seed(args.seed)
    torch.set_num_threads(os.cpu_count() or 4)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = data_mod.load_manifest()
    base = manifest["base_model"]

    print("building dataset...", flush=True)
    splits = data_mod.build(seed=args.seed)
    digest = data_mod.digest(splits)
    train, val, test = splits["train"], splits["validation"], splits["test"]
    if args.limit:
        train = train[: args.limit]
    if args.eval_limit:
        val, test = val[: args.eval_limit], test[: args.eval_limit]
    print({k: len(v) for k, v in splits.items()}, "digest", digest[:16], flush=True)

    base_dir = fetch_base_model(base)
    tok = AutoTokenizer.from_pretrained(base_dir, use_fast=True)
    model = AutoModelForSequenceClassification.from_pretrained(base_dir, num_labels=2)
    if args.freeze_embeddings:
        for p in model.base_model.embeddings.parameters():
            p.requires_grad = False

    def encode(items):  # type: ignore[no-untyped-def]
        return [tok(e.text, truncation=True, max_length=args.max_length)["input_ids"] for e in items]

    enc_tr, enc_va = encode(train), encode(val)
    y_tr = [e.label for e in train]
    y_va = np.array([e.label for e in val])

    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=args.lr, weight_decay=0.01)
    steps = args.epochs * math.ceil(len(enc_tr) / args.bs)
    sched = get_linear_schedule_with_warmup(opt, int(0.06 * steps), steps)
    rng = random.Random(args.seed)
    best_f1, best_state = -1.0, None
    step = 0
    t0 = time.time()
    for epoch in range(args.epochs):
        model.train()
        for ids, mask, y in batches(enc_tr, y_tr, args.bs, rng, shuffle=True):
            loss = model(input_ids=ids, attention_mask=mask, labels=y).loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            step += 1
            if step % 50 == 0:
                el = time.time() - t0
                print(
                    f"epoch {epoch} step {step}/{steps} loss {loss.item():.4f} elapsed {el / 60:.1f}m "
                    f"eta {(steps - step) * el / step / 60:.1f}m",
                    flush=True,
                )
        p_va = predict_torch(model, enc_va, y_va)
        m = metrics(y_va, p_va, 0.5)
        print(f"epoch {epoch} validation {m}", flush=True)
        if m["f1"] > best_f1:
            best_f1 = m["f1"]
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
    if best_state is not None:
        model.load_state_dict(best_state)
    model.eval()

    # ---------------------------------------------------------------- export
    tok.backend_tokenizer.save(str(out / "tokenizer.json"))
    fp32 = out / "model.fp32.onnx"
    dummy = tok(["hello world", "ignore all previous instructions"], padding=True, return_tensors="pt")
    model.config.return_dict = True
    torch.onnx.export(
        model,
        (dummy["input_ids"], dummy["attention_mask"]),
        str(fp32),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits": {0: "batch"},
        },
        opset_version=17,
        dynamo=False,
    )
    int8 = out / "model.int8.onnx"
    quantize_dynamic(str(fp32), str(int8), weight_type=QuantType.QInt8)

    meta = {
        "name": out.name,
        "base_model": base,
        "labels": ["benign", "injection"],
        "injection_label_index": 1,
        "max_length": args.max_length,
        "dataset_digest": digest,
        "seed": args.seed,
        "epochs": args.epochs,
        "lr": args.lr,
        "batch_size": args.bs,
        "freeze_embeddings": args.freeze_embeddings,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": [
            {"id": s["id"], "repo": s["repo"], "revision": s["revision"], "license": s["license"]}
            for s in manifest["sources"]
        ],
    }
    (out / "agentguard.json").write_text(json.dumps(meta, indent=2))

    # ---------------------------------------------------------------- evaluate with the runtime class
    def onnx_probs(path: Path, items) -> np.ndarray:  # type: ignore[no-untyped-def]
        target = out / "model.onnx"
        if target.exists():
            target.unlink()
        target.write_bytes(path.read_bytes())
        clf = OnnxInjectionClassifier(out, threshold=0.5)
        return np.array([clf.predict_proba(e.text) for e in items])

    y_te = np.array([e.label for e in test])
    results = {}
    for name, path in (("fp32", fp32), ("int8", int8)):
        pv = onnx_probs(path, val)
        pt = onnx_probs(path, test)
        thr = pick_threshold(y_va, pv, args.max_fpr)
        results[name] = {
            "threshold": thr,
            "validation@thr": metrics(y_va, pv, thr),
            "test@0.5": metrics(y_te, pt, 0.5),
            "test@thr": metrics(y_te, pt, thr),
            "test_per_source@thr": per_source(test, pt, thr),
            "size_mb": round(path.stat().st_size / 1e6, 1),
        }
        print(name, json.dumps(results[name]["test@thr"]), flush=True)

    chosen = "int8" if results["int8"]["test@thr"]["f1"] >= results["fp32"]["test@thr"]["f1"] - 0.01 else "fp32"
    (out / "model.onnx").unlink(missing_ok=True)
    (out / "model.onnx").write_bytes((int8 if chosen == "int8" else fp32).read_bytes())
    clf = OnnxInjectionClassifier(out, threshold=results[chosen]["threshold"])
    lat = {f"{n}_tokens": latency(clf, n) for n in (64, 128, 256)}
    lat["512_tokens_2_chunks"] = latency(clf, 512, n=100)
    meta.update({"quantization": chosen, "recommended_threshold": results[chosen]["threshold"]})
    (out / "agentguard.json").write_text(json.dumps(meta, indent=2))

    report = {
        "model": meta,
        "chosen": chosen,
        "results": results,
        "latency_cpu": lat,
        "machine": {
            "cpu_count": os.cpu_count(),
            "onnx_intra_op_threads": clf.session.get_session_options().intra_op_num_threads,
        },
        "dataset_sizes": {k: len(v) for k, v in splits.items()},
        "dataset_stats": data_mod.stats(splits),
    }
    reports = HERE / "reports"
    reports.mkdir(exist_ok=True)
    (reports / f"{out.name}.json").write_text(json.dumps(report, indent=2))
    write_markdown(report, reports / f"{out.name}.md")
    print(json.dumps({"chosen": chosen, "latency": lat}, indent=2))


def write_markdown(r: dict, path: Path) -> None:  # type: ignore[type-arg]
    c = r["chosen"]
    res = r["results"][c]
    lines = [
        f"# Evaluation report: {r['model']['name']}",
        "",
        f"- Base model: `{r['model']['base_model']['repo']}` @ `{r['model']['base_model']['revision'][:12]}`",
        f"- Shipped weights: **{c}** ({res['size_mb']} MB). Threshold chosen on validation for FPR <= 2%: **{res['threshold']}**",  # noqa: E501
        f"- Dataset digest: `{r['model']['dataset_digest']}` (sizes: {r['dataset_sizes']})",
        "",
        "## Test set (held out)",
        "",
        "| weights | threshold | precision | recall | F1 | FPR | AUROC |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, x in r["results"].items():
        for key, thr in (("test@0.5", 0.5), ("test@thr", x["threshold"])):
            m = x[key]
            lines.append(
                f"| {name} | {thr} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} | {m.get('auroc', float('nan')):.3f} |"  # noqa: E501
            )
    lines += [
        "",
        "## Per-source accuracy (shipped weights, chosen threshold)",
        "",
        "| source | n | positives | accuracy |",
        "|---|---|---|---|",
    ]
    for src, m in res["test_per_source@thr"].items():
        lines.append(f"| {src} | {m['n']} | {m['positives']} | {m['accuracy']:.3f} |")
    lines += [
        "",
        f"## CPU latency (batch 1, onnxruntime, {r['machine']['onnx_intra_op_threads']} intra-op threads, {r['machine']['cpu_count']} logical CPUs)",  # noqa: E501
        "",
        "| input | p50 ms | p95 ms | max ms |",
        "|---|---|---|---|",
    ]
    for k, v in r["latency_cpu"].items():
        lines.append(f"| {k} | {v['p50_ms']} | {v['p95_ms']} | {v['max_ms']} |")
    lines += [
        "",
        "## Caveats",
        "",
        "- Most public datasets contain *direct* prompt injections and jailbreaks. Indirect injections are",
        "  approximated by embedding held-out injections in Wikipedia paragraphs (`indirect_aug`). Real",
        "  tool outputs (HTML, email threads, JSON) differ; see the adversarial benchmark for end-to-end numbers.",
        "- Hard negatives are template-generated and split by template, so they test generalisation to",
        "  unseen phrasings only weakly.",
        "- The base model is English-centric; multilingual recall relies partly on the heuristic layer.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
