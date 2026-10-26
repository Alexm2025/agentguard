"""ONNX prompt-injection classifier (CPU, no torch at inference time).

The model directory produced by ``ml/train.py`` contains:

* ``model.onnx``          int8-quantised sequence classifier
* ``tokenizer.json``      Hugging Face fast tokenizer
* ``agentguard.json``     metadata: labels, injection label index, max_length, training data digest
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_MODEL_NAME = "injection-classifier-v1"


def default_model_dirs() -> list[Path]:
    if env := os.environ.get("AGENTGUARD_MODEL_DIR"):
        return [Path(env)]  # explicit setting: no fallbacks
    dirs: list[Path] = []
    cache = Path(os.environ.get("AGENTGUARD_CACHE_DIR", Path.home() / ".cache" / "agentguard"))
    dirs.append(cache / "models" / DEFAULT_MODEL_NAME)
    dirs.append(Path.cwd() / "ml" / "artifacts" / DEFAULT_MODEL_NAME)
    return dirs


def resolve_model_dir(model: str = "auto") -> Path | None:
    candidates = default_model_dirs() if model == "auto" else [Path(model)]
    for d in candidates:
        if (d / "model.onnx").is_file() and (d / "tokenizer.json").is_file():
            return d
    return None


class OnnxInjectionClassifier:
    name = "ml"

    def __init__(
        self,
        model_dir: str | Path,
        threshold: float = 0.85,
        max_chunks: int = 16,
        intra_op_threads: int | None = None,
        min_words: int = 4,
    ) -> None:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self._np = np
        self.model_dir = Path(model_dir)
        self.threshold = threshold
        self.max_chunks = max_chunks
        self.min_words = min_words
        meta_path = self.model_dir / "agentguard.json"
        self.meta: dict[str, Any] = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        self.max_length = int(self.meta.get("max_length", 128))
        self.positive_index = int(self.meta.get("injection_label_index", 1))

        self.tokenizer = Tokenizer.from_file(str(self.model_dir / "tokenizer.json"))
        self.tokenizer.no_padding()
        self.tokenizer.enable_truncation(self.max_length, stride=self.max_length // 4)

        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.intra_op_num_threads = intra_op_threads or min(4, os.cpu_count() or 1)
        opts.inter_op_num_threads = 1
        self.session = ort.InferenceSession(
            str(self.model_dir / "model.onnx"), sess_options=opts, providers=["CPUExecutionProvider"]
        )
        self._inputs = {i.name for i in self.session.get_inputs()}
        self._lock = threading.Lock()

    @classmethod
    def from_settings(cls, model: str, threshold: float, min_words: int = 4) -> OnnxInjectionClassifier | None:
        d = resolve_model_dir(model)
        if d is None:
            return None
        return cls(d, threshold=threshold, min_words=min_words)

    def _encode(self, text: str) -> tuple[Any, Any]:
        np = self._np
        enc = self.tokenizer.encode(text)
        windows = [enc, *enc.overflowing][: self.max_chunks]
        width = max(len(w.ids) for w in windows)
        ids = np.zeros((len(windows), width), dtype=np.int64)
        mask = np.zeros((len(windows), width), dtype=np.int64)
        for i, w in enumerate(windows):
            ids[i, : len(w.ids)] = w.ids
            mask[i, : len(w.ids)] = w.attention_mask
        return ids, mask

    def predict_proba(self, text: str) -> float:
        np = self._np
        ids, mask = self._encode(text)
        feeds = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self._inputs:
            feeds["token_type_ids"] = np.zeros_like(ids)
        feeds = {k: v for k, v in feeds.items() if k in self._inputs}
        with self._lock:
            (logits,) = self.session.run(None, feeds)[:1]
        logits = logits - logits.max(axis=-1, keepdims=True)
        probs = np.exp(logits) / np.exp(logits).sum(axis=-1, keepdims=True)
        return float(probs[:, self.positive_index].max())

    def score(self, text: str) -> tuple[float, tuple[str, ...]]:
        # v1 over-flags very short texts (e.g. "hello" scores 0.998); the heuristic layer still scans them.
        if len(text.split()) < self.min_words:
            return 0.0, ()
        p = self.predict_proba(text)
        return round(p, 4), (("ml_classifier",) if p >= self.threshold else ())
