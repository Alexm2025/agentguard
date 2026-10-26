"""``agentguard`` command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from agentguard import __version__

Handler = Callable[[argparse.Namespace], int]
_COMMANDS: dict[str, Handler] = {}


def _cmd_policy_validate(ns: argparse.Namespace) -> int:
    import yaml

    from agentguard.core.policy.loader import validate_policy_data

    rc = 0
    for path in ns.files:
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            print(f"{path}: error: {exc}", file=sys.stderr)
            rc = 1
            continue
        errors = validate_policy_data(data)
        if errors:
            rc = 1
            for e in errors:
                print(f"{path}: {e}", file=sys.stderr)
        else:
            print(f"{path}: ok")
    return rc


def _cmd_policy_schema(ns: argparse.Namespace) -> int:
    from agentguard.core.policy.loader import policy_json_schema

    print(json.dumps(policy_json_schema(), indent=2))
    return 0


def _cmd_policy_init(ns: argparse.Namespace) -> int:
    from agentguard.core.policy.loader import default_policy_text

    sys.stdout.write(default_policy_text())
    return 0


def _cmd_scan(ns: argparse.Namespace) -> int:
    from agentguard.core.engine import Engine

    text = Path(ns.file).read_text(encoding="utf-8") if ns.file else sys.stdin.read()
    engine = Engine()
    out = [
        {
            "detector": d.detector,
            "score": d.score,
            "flagged": d.flagged,
            "rules": list(d.rules),
            "latency_ms": round(d.latency_ms, 2),
        }
        for d in engine.inspect_text(text)
    ]
    print(json.dumps(out, indent=2))
    return 1 if any(d["flagged"] for d in out) else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentguard", description="Runtime security for LLM agents")
    p.add_argument("--version", action="version", version=f"agentguard {__version__}")
    sub = p.add_subparsers(dest="command")

    pol = sub.add_parser("policy", help="policy tools").add_subparsers(dest="policy_cmd", required=True)
    v = pol.add_parser("validate", help="validate policy files")
    v.add_argument("files", nargs="+")
    v.set_defaults(func=_cmd_policy_validate)
    pol.add_parser("schema", help="print the policy JSON schema").set_defaults(func=_cmd_policy_schema)
    pol.add_parser("init", help="print the default policy").set_defaults(func=_cmd_policy_init)

    s = sub.add_parser("scan", help="scan text (file or stdin) for prompt injection")
    s.add_argument("file", nargs="?")
    s.set_defaults(func=_cmd_scan)

    for register in _EXTENSIONS:
        register(sub)
    return p


_EXTENSIONS: list[Callable[[argparse._SubParsersAction[argparse.ArgumentParser]], None]] = []


def main(argv: Sequence[str] | None = None) -> int:
    _load_extensions()
    parser = build_parser()
    ns = parser.parse_args(argv)
    if not getattr(ns, "func", None):
        parser.print_help()
        return 2
    return int(ns.func(ns))


def _load_extensions() -> None:
    """Commands from optional components register themselves if their deps are installed."""
    if _EXTENSIONS:
        return
    import importlib

    for mod in ("agentguard.gateway.cli", "agentguard.server.cli", "agentguard.ml_cli"):
        try:
            m = importlib.import_module(mod)
        except ImportError:
            continue
        _EXTENSIONS.append(m.register)


if __name__ == "__main__":
    raise SystemExit(main())
