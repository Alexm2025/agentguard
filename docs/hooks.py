"""MkDocs hook: generate the policy schema reference from the code so it never drifts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentguard.core.policy.loader import policy_json_schema


def _rows(schema: dict[str, Any], defs: dict[str, Any]) -> list[str]:
    out = []
    for name, prop in schema.get("properties", {}).items():
        ref = prop.get("$ref") or next((x.get("$ref") for x in prop.get("anyOf", []) if "$ref" in x), None)
        typ = (
            ref.split("/")[-1]
            if ref
            else prop.get("type")
            or " | ".join(str(x.get("type") or x.get("$ref", "").split("/")[-1]) for x in prop.get("anyOf", []))
        )
        if "enum" in prop:
            typ = " | ".join(f"`{v}`" for v in prop["enum"])
        default = prop.get("default", "")
        desc = (prop.get("description") or "").replace("\n", " ")
        out.append(
            f"| `{name}` | {typ} | `{json.dumps(default)}` | {desc} |"
            if default != ""
            else f"| `{name}` | {typ} | | {desc} |"
        )
    return out


def on_pre_build(config: Any) -> None:
    schema = policy_json_schema()
    defs = schema.get("$defs", {})
    lines = [
        "# Policy schema",
        "",
        "Generated from the code at build time (`agentguard policy schema` prints the full JSON Schema).",
        "",
        "## Policy (top level)",
        "",
        "| Field | Type | Default | Description |",
        "|---|---|---|---|",
        *_rows(schema, defs),
    ]
    for name in sorted(defs):
        d = defs[name]
        if "properties" not in d:
            if "enum" in d:
                lines += ["", f"## {name}", "", "One of: " + ", ".join(f"`{v}`" for v in d["enum"])]
            continue
        lines += [
            "",
            f"## {name}",
            "",
            (d.get("description") or "").strip(),
            "",
            "| Field | Type | Default | Description |",
            "|---|---|---|---|",
            *_rows(d, defs),
        ]
    lines += ["", "## Raw JSON Schema", "", "```json", json.dumps(schema, indent=2), "```", ""]
    target = Path(config["docs_dir"]) / "reference" / "policy-schema.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines)
    if not target.exists() or target.read_text(encoding="utf-8") != text:
        target.write_text(text, encoding="utf-8")
