"""The Docker build's model download refuses anything whose checksum does not match."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import tarfile
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "fetch_model.py"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("fetch_model", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"weights"
        info = tarfile.TarInfo("injection-classifier-v1/model.onnx")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _serve(monkeypatch: pytest.MonkeyPatch, mod: Any, payload: bytes) -> None:
    monkeypatch.setattr(mod.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(payload))


def test_extracts_when_checksum_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load()
    payload = _archive()
    _serve(monkeypatch, mod, payload)
    mod.main("https://example.test/m.tar.gz", hashlib.sha256(payload).hexdigest(), tmp_path)
    assert (tmp_path / "injection-classifier-v1" / "model.onnx").read_bytes() == b"weights"


def test_rejects_wrong_checksum_and_plain_http(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load()
    _serve(monkeypatch, mod, _archive())
    with pytest.raises(SystemExit, match="checksum mismatch"):
        mod.main("https://example.test/m.tar.gz", "0" * 64, tmp_path)
    assert not any(tmp_path.iterdir())
    with pytest.raises(SystemExit, match="https"):
        mod.main("http://example.test/m.tar.gz", "0" * 64, tmp_path)
