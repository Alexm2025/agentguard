"""Taint matcher: decides whether tool-call arguments were derived from tainted content.

A value counts as *derived from taint* when it matches a tainted segment and does **not** also
appear in trusted content (system prompt, developer instructions, user messages). That is what
separates "the user asked me to email bob@corp.com" from "a web page told me to email
attacker@evil.example".

Matching layers, cheapest first:

* ``exact``      normalised value equals the segment
* ``substring``  normalised value (>= ``min_substring_len``) occurs in the segment
* ``contains``   the value embeds a whole tainted segment (e.g. a document pasted into a body)
* ``entity``     an email / URL / domain / IP / path / long number in the value occurs in the segment
* ``decoded``    the same checks after base64 / hex / percent / unicode-tag decoding of the value
* ``fuzzy``      RapidFuzz partial ratio over normalised text
* ``shingle``    word 3-gram containment, robust to small insertions and reordering
* ``semantic``   embedding cosine similarity (only when an :class:`Embedder` is configured)
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from rapidfuzz import fuzz

from agentguard.core import entities
from agentguard.core.normalize import decode_candidates, normalize, shingles, words
from agentguard.core.types import Segment, TaintMatch


class Embedder(Protocol):
    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


@dataclass(frozen=True, slots=True)
class TaintConfig:
    min_substring_len: int = 8
    min_contains_len: int = 40
    fuzzy_min_len: int = 24
    fuzzy_threshold: float = 88.0
    shingle_n: int = 3
    shingle_min_tokens: int = 6
    shingle_containment: float = 0.6
    semantic_threshold: float = 0.82
    semantic_min_len: int = 32
    semantic_chunk_chars: int = 400
    max_segment_chars: int = 200_000
    decode: bool = True
    trusted_margin: float = 5.0
    entity_kinds: frozenset[str] = frozenset({"email", "url", "domain", "ip", "path", "number"})


def flatten_arguments(arguments: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(dotted.path, string_value)`` for every scalar leaf of a JSON-like structure."""
    if isinstance(arguments, Mapping):
        for key, value in arguments.items():
            yield from flatten_arguments(value, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(arguments, list | tuple):
        for i, value in enumerate(arguments):
            yield from flatten_arguments(value, f"{prefix}.{i}" if prefix else str(i))
    elif isinstance(arguments, bool) or arguments is None:
        return
    elif isinstance(arguments, str | int | float):
        yield prefix or "$", str(arguments)


def path_matches(selector: str, path: str) -> bool:
    """``to`` matches ``to`` and ``to.0``; ``*`` segments match one level; ``**``/``any`` match all."""
    from fnmatch import fnmatchcase

    if selector in ("*", "**", "any"):
        return True
    return selector == path or path.startswith(selector + ".") or fnmatchcase(path, selector)


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _chunks(text: str, size: int) -> list[str]:
    if len(text) <= size:
        return [text]
    step = size // 2
    return [text[i : i + size] for i in range(0, len(text) - step, step)]


def _with_decoded(text: str, decode: bool) -> str:
    """Append decoded forms of encoded payloads (base64, hex, %-encoding, Unicode tags) so a value
    the model decoded from tainted content still matches its source."""
    if not decode:
        return text
    extra = [d for _enc, d in decode_candidates(text)]
    return "\n".join([text, *extra])


class _Corpus:
    """Pre-normalised view of a set of segments, built once per evaluation."""

    def __init__(self, segments: Sequence[Segment], config: TaintConfig) -> None:
        self.segments = list(segments)
        texts = [_with_decoded(s.text[: config.max_segment_chars], config.decode) for s in self.segments]
        self.norm = [normalize(t) for t in texts]
        self.entities = [entities.extract(t) for t in texts]
        self._shingles: dict[int, set[tuple[str, ...]]] = {}
        self._n = config.shingle_n
        self.joined = "\n".join(self.norm)
        self.all_entities = frozenset().union(*self.entities) if self.entities else frozenset()

    def shingles(self, i: int) -> set[tuple[str, ...]]:
        if i not in self._shingles:
            self._shingles[i] = shingles(words(self.norm[i]), self._n)
        return self._shingles[i]


class TaintMatcher:
    def __init__(self, config: TaintConfig | None = None, embedder: Embedder | None = None) -> None:
        self.config = config or TaintConfig()
        self.embedder = embedder
        self._embed_cache: dict[str, list[list[float]]] = {}

    def match(
        self,
        arguments: Mapping[str, Any],
        tainted: Sequence[Segment],
        trusted: Sequence[Segment] = (),
    ) -> list[TaintMatch]:
        if not tainted:
            return []
        t_corpus = _Corpus(tainted, self.config)
        tr_corpus = _Corpus(trusted, self.config)
        best: dict[tuple[str, str], TaintMatch] = {}
        for path, value in flatten_arguments(arguments):
            for m in self._match_value(path, value, t_corpus, tr_corpus):
                key = (m.arg_path, m.segment_id)
                cur = best.get(key)
                # Prefer matches that are attributable to taint only, then higher scores.
                if cur is None or (m.derived, m.score) > (cur.derived, cur.score):
                    best[key] = m
        return sorted(best.values(), key=lambda m: (not m.derived, -m.score, m.arg_path))

    # ------------------------------------------------------------------ internals

    def _match_value(self, path: str, value: str, t: _Corpus, tr: _Corpus) -> Iterator[TaintMatch]:
        cfg = self.config
        nv = normalize(value)
        if len(nv) < 3:
            return
        value_entities = {e for e in entities.extract(value) if e.kind in cfg.entity_kinds}
        decoded = decode_candidates(value) if cfg.decode else []
        nv_words = words(nv)
        nv_shingles = shingles(nv_words, cfg.shingle_n) if len(nv_words) >= cfg.shingle_min_tokens else set()

        for i, seg in enumerate(t.segments):
            ns = t.norm[i]
            if not ns:
                continue
            label = seg.label

            def emit(kind: str, score: float, evidence: str, in_trusted: bool) -> TaintMatch:
                return TaintMatch(path, seg.id, label, kind, score, evidence[:200], in_trusted)  # noqa: B023

            if nv == ns:
                yield emit("exact", 1.0, value, nv in tr.joined)
                continue
            if len(nv) >= cfg.min_substring_len and nv in ns:
                yield emit("substring", 1.0, value, nv in tr.joined)
                continue
            if len(ns) >= cfg.min_contains_len and ns in nv:
                yield emit("contains", 1.0, seg.text, ns in tr.joined)
                continue

            for ent in value_entities & t.entities[i]:
                yield emit(f"entity:{ent.kind}", 1.0, ent.value, ent in tr.all_entities)

            for enc, text in decoded:
                nd = normalize(text)
                if len(nd) >= cfg.min_substring_len and (nd in ns or (len(ns) >= cfg.min_contains_len and ns in nd)):
                    yield emit(f"decoded:{enc}", 1.0, text, False)
                for ent in entities.extract(text) & t.entities[i]:
                    yield emit(f"decoded:{enc}:entity:{ent.kind}", 1.0, ent.value, ent in tr.all_entities)

            if len(nv) >= cfg.fuzzy_min_len:
                score = fuzz.partial_ratio(nv, ns, score_cutoff=cfg.fuzzy_threshold)
                if score:
                    tr_score = fuzz.partial_ratio(nv, tr.joined) if tr.joined else 0.0
                    yield emit("fuzzy", score / 100.0, value, tr_score >= score - cfg.trusted_margin)
                    continue

            if nv_shingles:
                seg_sh = t.shingles(i)
                overlap = len(nv_shingles & seg_sh) / len(nv_shingles)
                if overlap >= cfg.shingle_containment:
                    tr_overlap = max(
                        (len(nv_shingles & tr.shingles(j)) / len(nv_shingles) for j in range(len(tr.segments))),
                        default=0.0,
                    )
                    yield emit("shingle", overlap, value, tr_overlap >= overlap - cfg.trusted_margin / 100)
                    continue

            if self.embedder is not None and len(nv) >= cfg.semantic_min_len:
                sim = self._semantic(nv, seg, ns)
                if sim >= cfg.semantic_threshold:
                    tr_sim = max(
                        (self._semantic(nv, s, tr.norm[j]) for j, s in enumerate(tr.segments)),
                        default=0.0,
                    )
                    yield emit("semantic", sim, value, tr_sim >= sim - 0.02)

    def _semantic(self, nv: str, seg: Segment, ns: str) -> float:
        if self.embedder is None:
            return 0.0
        if seg.id not in self._embed_cache:
            self._embed_cache[seg.id] = self.embedder.embed(_chunks(ns, self.config.semantic_chunk_chars))
            if len(self._embed_cache) > 2048:
                self._embed_cache.pop(next(iter(self._embed_cache)))
        [vec] = self.embedder.embed([nv])
        return max((_cosine(vec, c) for c in self._embed_cache[seg.id]), default=0.0)
