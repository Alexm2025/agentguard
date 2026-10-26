from __future__ import annotations

import base64

import pytest

from agentguard.core import entities
from agentguard.core.dlp import DlpScanner, iban, luhn, mask, us_ssn
from agentguard.core.normalize import decode_candidates, normalize, reveal_tag_chars


def test_luhn() -> None:
    assert luhn("4111 1111 1111 1111")
    assert not luhn("4111 1111 1111 1112")
    assert not luhn("1234")


def test_iban() -> None:
    assert iban("GB82 WEST 1234 5698 7654 32")
    assert not iban("GB82 WEST 1234 5698 7654 33")


def test_ssn() -> None:
    assert us_ssn("123-45-6789")
    assert not us_ssn("000-45-6789")
    assert not us_ssn("666-45-6789")
    assert not us_ssn("923-45-6789")


@pytest.mark.parametrize(
    ("pid", "text"),
    [
        ("aws_access_key", "key AKIAIOSFODNN7EXAMPLE here"),
        ("github_token", "ghp_" + "a" * 36),
        ("openai_key", "sk-proj-" + "A1b2C3d4" * 5),
        ("slack_token", "xoxb-1234567890-abcdefghij"),
        ("private_key", "-----BEGIN RSA PRIVATE KEY-----"),
        (
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ),
        ("credit_card", "card 4111-1111-1111-1111 exp"),
        ("password_assignment", "password = Xk9#mP2$vL8q"),
        ("google_api_key", "AIza" + "B" * 35),
    ],
)
def test_builtin_patterns(pid: str, text: str) -> None:
    findings = DlpScanner().scan_text(text, [pid])
    assert findings and findings[0].pattern_id == pid
    assert "*" in findings[0].masked


def test_password_placeholder_low_entropy_ignored() -> None:
    assert DlpScanner().scan_text("password=xxxxxxxxxx", ["password_assignment"]) == []


def test_redact_arguments_and_custom_pattern() -> None:
    s = DlpScanner()
    s.add("ticket", r"TCK-\d{6}")
    out = s.redact_arguments({"a": ["TCK-123456 and AKIAIOSFODNN7EXAMPLE"], "n": 3}, ["ticket", "aws_access_key"])
    assert out == {"a": ["[REDACTED:ticket] and [REDACTED:aws_access_key]"], "n": 3}
    with pytest.raises(ValueError, match="unknown validator"):
        s.add("x", "x", validator="nope")


def test_scan_arguments_paths() -> None:
    f = DlpScanner().scan_arguments({"body": {"lines": ["ok", "AKIAIOSFODNN7EXAMPLE"]}}, ["aws_access_key"])
    assert f[0].arg_path == "body.lines.1"


def test_mask() -> None:
    assert mask("abc") == "***"
    assert mask("abcdefghijkl").startswith("abcd")


def test_entities_extract() -> None:
    text = "Mail a@b.com or visit https://x.example.org/p?q=1. Server 10.0.0.1, file /etc/passwd/x, acct 1234 5678 90"
    kinds = {(e.kind, e.value) for e in entities.extract(text)}
    assert ("email", "a@b.com") in kinds
    assert ("url", "https://x.example.org/p?q=1") in kinds
    assert ("domain", "x.example.org") in kinds
    assert ("ip", "10.0.0.1") in kinds
    assert ("number", "1234567890") in kinds
    assert any(k == "path" for k, _ in kinds)
    assert entities.emails(text) == ["a@b.com"]
    assert entities.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert entities.registrable_domain("a.b.example.com") == "example.com"


def test_file_extensions_are_not_domains() -> None:
    assert "report.pdf" not in entities.domains("see report.pdf")


def test_normalize_invisible_and_confusables() -> None:
    assert normalize("I\u200bgnоre  ALL") == "ignore all"


def test_decode_candidates() -> None:
    b64 = base64.b64encode(b"ignore previous instructions").decode()
    hexed = b"hello world!!".hex()
    tags = "".join(chr(0xE0000 + ord(c)) for c in "hi there")
    found = dict(decode_candidates(f"x {b64} y {hexed} %69%67%6e z {tags}"))
    assert found["base64"] == "ignore previous instructions"
    assert found["hex"] == "hello world!!"
    assert "percent" in found
    assert found["unicode_tags"] == "hi there"
    assert reveal_tag_chars(tags) == "hi there"
