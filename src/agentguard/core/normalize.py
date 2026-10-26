"""Text normalisation and decoding helpers shared by the taint matcher and detectors."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from functools import lru_cache

# Zero-width and bidi control characters plus the Unicode "tag" block, which is used to
# smuggle invisible ASCII ("ASCII smuggling") into prompts.
_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
_WS = re.compile(r"\s+")
_WORD = re.compile(r"[\w@.\-/:]+", re.UNICODE)

# A small confusables map covering the homoglyphs most often seen in attacks (Cyrillic/Greek
# letters that render like Latin ones). Full UTS #39 skeletons are out of scope.
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
        "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ο": "o", "α": "a", "ε": "e", "ι": "i",
        "κ": "k", "ν": "v", "τ": "t", "υ": "u", "ρ": "p", "А": "A", "В": "B", "Е": "E", "К": "K",
        "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    }
)  # fmt: skip

TAG_BLOCK_START = 0xE0000


def reveal_tag_chars(text: str) -> str:
    """Decode Unicode tag characters (U+E0020..U+E007E) back to the ASCII they hide."""
    out = [chr(ord(c) - TAG_BLOCK_START) for c in text if 0xE0020 <= ord(c) <= 0xE007E]
    return "".join(out)


_MIXED_WORD = re.compile(r"\w+", re.UNICODE)
_CONFUSABLE_CHARS = frozenset(chr(k) for k in _CONFUSABLES)


def _fold_mixed(m: re.Match[str]) -> str:
    w = m.group(0)
    # Only fold words that mix ASCII letters with look-alikes (e.g. "paypal" spelled with a
    # Cyrillic a); genuine Cyrillic or Greek words are left intact so multilingual detection
    # still works.
    if any(c in _CONFUSABLE_CHARS for c in w) and any("a" <= c.lower() <= "z" for c in w):
        return w.translate(_CONFUSABLES)
    return w


@lru_cache(maxsize=4096)
def normalize(text: str) -> str:
    """Canonical form for matching: NFKC, homoglyph folding of mixed-script words, invisible chars
    removed, casefolded, whitespace collapsed."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = _MIXED_WORD.sub(_fold_mixed, text)
    text = text.casefold()
    return _WS.sub(" ", text).strip()


def words(text: str) -> list[str]:
    return _WORD.findall(normalize(text))


def shingles(tokens: list[str], n: int = 3) -> set[tuple[str, ...]]:
    if len(tokens) < n:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)}


_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")
_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(c.isprintable() or c in "\n\r\t" for c in text) / len(text)


def decode_candidates(text: str, *, limit: int = 16) -> list[tuple[str, str]]:
    """Return ``(encoding, decoded_text)`` for encoded substrings that decode to readable text.

    Covers base64 (standard and urlsafe), hex, percent-encoding, ROT13 and Unicode tag smuggling.
    Decoded output is only *inspected*, never executed.
    """
    found: list[tuple[str, str]] = []
    for m in _B64.finditer(text):
        blob = m.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(padded)
                decoded = raw.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if len(decoded) >= 6 and _printable_ratio(decoded) > 0.95:
                found.append(("base64", decoded))
                break
        if len(found) >= limit:
            return found
    for m in _HEX.finditer(text):
        try:
            decoded = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > 0.95:
            found.append(("hex", decoded))
    if _PCT.search(text):
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            found.append(("percent", decoded))
    hidden = reveal_tag_chars(text)
    if hidden:
        found.append(("unicode_tags", hidden))
    return found[:limit]


def rot13(text: str) -> str:
    return codecs.encode(text, "rot13")
