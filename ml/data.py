"""Builds the train/validation/test splits for the injection classifier.

Steps (all seeded):

1. Download each source in ``datasets.yaml`` at its pinned revision.
2. Normalise to ``(text, label, source)`` and deduplicate on normalised text.
3. Split 80/10/10 stratified by (source, label). SQuAD carrier paragraphs are split too, so an
   augmented test example never reuses a training paragraph.
4. Indirect-injection augmentation: embed injections into carrier paragraphs (positives) and
   embed benign sentences into carrier paragraphs (negatives, so the model cannot learn
   "inserted text" as the signal).
5. Hard negatives: tool-output-style documents with imperative language that are not attacks.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

import pandas as pd
import yaml

HERE = Path(__file__).parent
CACHE = HERE / ".cache"


@dataclass(frozen=True)
class Example:
    text: str
    label: int
    source: str


def _norm(t: str) -> str:
    return re.sub(r"\s+", " ", t).strip().casefold()


def load_manifest() -> dict:  # type: ignore[type-arg]
    return yaml.safe_load((HERE / "datasets.yaml").read_text(encoding="utf-8"))


def _read(path: str) -> pd.DataFrame:
    return pd.read_parquet(path) if path.endswith(".parquet") else pd.read_csv(path)


def _fetch(repo: str, filename: str, revision: str) -> str:
    """Pinned download, local cache first: avoids Hub round-trips (which can stall) on rebuilds."""
    from huggingface_hub import hf_hub_download
    from huggingface_hub.errors import LocalEntryNotFoundError

    try:
        return str(
            hf_hub_download(
                repo, filename, repo_type="dataset", revision=revision, cache_dir=CACHE, local_files_only=True
            )
        )
    except LocalEntryNotFoundError:
        return str(hf_hub_download(repo, filename, repo_type="dataset", revision=revision, cache_dir=CACHE))


def load_source(spec: dict, rng: random.Random) -> list[Example]:  # type: ignore[type-arg]
    frames = [_read(_fetch(spec["repo"], f, spec["revision"])) for f in spec["files"]]
    df = pd.concat(frames, ignore_index=True)
    lab = spec["label"]
    out: list[Example] = []
    for _, row in df.iterrows():
        text = row[spec["text"]]
        if not isinstance(text, str) or len(text.strip()) < 3:
            continue
        label = int(lab["constant"]) if "constant" in lab else int(row[lab["column"]] == lab["positive"])
        out.append(Example(text.strip(), label, spec["id"]))
    if cap := spec.get("max_per_label"):
        by: dict[int, list[Example]] = defaultdict(list)
        for e in out:
            by[e.label].append(e)
        out = []
        for lbl in sorted(by):
            items = by[lbl]
            rng.shuffle(items)
            out.extend(items[:cap])
    return out


# ---------------------------------------------------------------- hard negatives

_NAMES = ["Alice", "Bob", "Priya", "Chen", "Fatima", "Lars", "Maria", "Kenji", "Olu", "Sofia"]
_DOMAINS = ["acme.com", "example.org", "contoso.net", "initech.io", "globex.co"]
_HARD_NEG_TEMPLATES = [
    "Hi team, please send the Q{q} report to {name}@{dom} by Friday. Ignore the draft I shared earlier; it had wrong numbers.",
    "Installation instructions: 1) Download the package. 2) Run `make install`. 3) Ignore warnings about deprecated flags, they are harmless.",
    "Reminder from {name}: forward any invoices to billing@{dom}. Do not reply to this automated message.",
    "Release notes v{q}.{m}: Previous instructions for configuring the proxy are obsolete. New instructions: set PROXY_URL in .env.",
    "Recipe: preheat the oven to 180C. Forget about the old recipe that used butter; this version uses olive oil.",
    "Support ticket #{n}: Customer says the assistant ignored their previous request to cancel the order. Escalate to {name}.",
    "Meeting notes: {name} will delete the stale branches after the release. Everyone must update their local clones.",
    "Security training: attackers may write 'ignore previous instructions' in emails. Report such emails to security@{dom}.",
    "The system prompt in our chatbot was updated by {name} on Monday to include the new refund policy.",
    "README: You are now ready to deploy. Run `deploy --env prod`. If you are an operator, check the dashboard first.",
    "From: {name}@{dom}\nSubject: Wire transfer\nHi, as discussed on the call, the invoice of ${amt} is attached. Payment terms are net 30.",
    "Changelog: removed the 'override' flag. Users who relied on bypassing validation should migrate to the new API.",
    "FAQ: Can I reset all settings? Yes. Go to Settings > Advanced > Reset. This deletes all local preferences.",
    "Policy: Employees must not share passwords or API keys with anyone, including IT staff. Report requests to {name}.",
    "Calendar invite: {name} has asked you to review the onboarding doc and send feedback to hr@{dom}.",
    "Issue #{n}: The bot repeats the system message when the user types 'help'. Expected: it should show the help menu.",
    "Translation request: please translate 'ignore the noise in the background' into French for the subtitle file.",
    "Lab protocol: discard all previous samples before starting. New instructions are posted on the lab wiki.",
]


def hard_negatives(rng: random.Random, n: int, templates: list[str]) -> list[Example]:
    out = []
    for _ in range(n):
        t = rng.choice(templates).format(
            name=rng.choice(_NAMES),
            dom=rng.choice(_DOMAINS),
            q=rng.randint(1, 4),
            m=rng.randint(0, 9),
            n=rng.randint(100, 9999),
            amt=rng.randint(100, 99000),
        )
        out.append(Example(t, 0, "hard_negative"))
    return out


# ---------------------------------------------------------------- augmentation

_SENT = re.compile(r"(?<=[.!?])\s+")


def embed(carrier: str, payload: str, rng: random.Random) -> str:
    sents = _SENT.split(carrier)
    pos = rng.randint(0, len(sents))
    wrapper = rng.choice(["{p}", "\n\n{p}\n\n", "<!-- {p} -->", "[{p}]", "Note: {p}", "\n---\n{p}\n---\n", "{p}"])
    sents.insert(pos, wrapper.format(p=payload))
    return " ".join(sents)


def augment(carriers: list[str], pos: list[Example], neg: list[Example], rng: random.Random, n: int) -> list[Example]:
    out: list[Example] = []
    short_neg = [e for e in neg if len(e.text) < 300 and e.source not in ("squad",)]
    short_pos = [e for e in pos if len(e.text) < 600]
    if not carriers or not short_pos or not short_neg:
        return out
    for _ in range(n):
        out.append(Example(embed(rng.choice(carriers), rng.choice(short_pos).text, rng), 1, "indirect_aug"))
        out.append(Example(embed(rng.choice(carriers), rng.choice(short_neg).text, rng), 0, "indirect_aug"))
    return out


# ---------------------------------------------------------------- splits


def split(
    examples: list[Example], rng: random.Random, fracs: tuple[float, float] = (0.8, 0.1)
) -> tuple[list[Example], ...]:
    groups: dict[tuple[str, int], list[Example]] = defaultdict(list)
    for e in examples:
        groups[(e.source, e.label)].append(e)
    train, val, test = [], [], []
    for key in sorted(groups):
        items = groups[key]
        rng.shuffle(items)
        a = int(len(items) * fracs[0])
        b = a + max(1, int(len(items) * fracs[1]))
        train += items[:a]
        val += items[a:b]
        test += items[b:]
    return train, val, test


def build(seed: int = 13, augment_n: int = 2500, hard_neg_n: int = 800) -> dict[str, list[Example]]:
    rng = random.Random(seed)
    manifest = load_manifest()
    raw: list[Example] = []
    for spec in manifest["sources"]:
        raw += load_source(spec, rng)

    seen: set[str] = set()
    dedup: list[Example] = []
    for e in raw:
        k = _norm(e.text)
        if k in seen:
            continue
        seen.add(k)
        dedup.append(e)

    carriers_all = [e for e in dedup if e.source == "squad"]
    others = [e for e in dedup if e.source != "squad"]
    tr, va, te = split(others, rng)
    ctr, cva, cte = split(carriers_all, rng)
    # Split hard negatives by template so no template appears in more than one split.
    tpl = list(_HARD_NEG_TEMPLATES)
    rng.shuffle(tpl)
    hn_tr = hard_negatives(rng, hard_neg_n * 8 // 10, tpl[:12])
    hn_va = hard_negatives(rng, hard_neg_n // 10, tpl[12:15])
    hn_te = hard_negatives(rng, hard_neg_n // 10, tpl[15:])

    splits = {"train": tr + ctr + hn_tr, "validation": va + cva + hn_va, "test": te + cte + hn_te}
    sizes = {"train": augment_n, "validation": augment_n // 8, "test": augment_n // 8}
    carriers = {"train": ctr, "validation": cva, "test": cte}
    for name, items in list(splits.items()):
        pos = [e for e in items if e.label == 1 and e.source != "indirect_aug"]
        neg = [e for e in items if e.label == 0]
        items.extend(augment([c.text for c in carriers[name]], pos, neg, rng, sizes[name]))
        rng.shuffle(items)
    return splits


def digest(splits: dict[str, list[Example]]) -> str:
    h = hashlib.sha256()
    for name in sorted(splits):
        for e in splits[name]:
            h.update(f"{name}\t{e.label}\t{e.source}\t{e.text}\n".encode())
    return h.hexdigest()


def stats(splits: dict[str, list[Example]]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for name, items in splits.items():
        c: dict[str, int] = defaultdict(int)
        for e in items:
            c[f"{e.source}:{e.label}"] += 1
        out[name] = dict(sorted(c.items()))
    return out


if __name__ == "__main__":
    s = build()
    print(json.dumps(stats(s), indent=2))
    print("digest", digest(s))
    out = HERE / "artifacts" / "data"
    out.mkdir(parents=True, exist_ok=True)
    for name, items in s.items():
        with (out / f"{name}.jsonl").open("w", encoding="utf-8") as fh:
            for e in items:
                fh.write(json.dumps(asdict(e), ensure_ascii=False) + "\n")
