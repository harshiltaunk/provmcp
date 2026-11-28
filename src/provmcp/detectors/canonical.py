"""Canonical views of text, for detection that survives simple obfuscation (Week 12).

An adaptive attacker who knows the detectors can change how a value is
written without changing what it says: encode it, re-case it, insert
invisible characters, swap in look-alike letters, or defang it. The
substring and structured detectors compare text byte for byte (after light,
type-specific normalization), so each of these defeats them.

`views(text)` returns the text in a small set of canonical forms. The
detectors compare the views of a stored payload with the views of an
outbound call, so the same normalization applies on both sides. This covers
obfuscation in either direction: data encoded on its way out, and an
attacker's own address planted encoded and decoded by the agent.

Normalization, applied to every view:

    NFKC        full-width and other compatibility forms -> ASCII
    format      drop invisible format characters (Unicode category Cf),
                such as zero-width spaces and joiners
    confusables map common Cyrillic and Greek look-alike letters to Latin
                (a small fixed table, not the full Unicode confusables data)
    casefold    case-insensitive comparison

Extra views:

    defanged    `[at]`, `(at)`, `[.]`, `(dot)`, ` at `, ` dot `, `hxxp` undone
    despaced    runs of single characters separated by single spaces joined
                (`o w n e r` -> `owner`)
    decoded     base64, hex, percent-encoding and HTML character references,
                found as tokens and decoded, up to two layers deep
    squashed    (outbound side only) every character that cannot be part of
                a substring run removed, so separators inserted between the
                characters of a value no longer split it

This is a fixed decoder set. An encoding outside it (a reversal, a Caesar
shift, a keyed cipher, an ad-hoc interleaving) still defeats detection;
Week 12 measures exactly that.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote

# Common look-alikes (Cyrillic and Greek) for Latin letters.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",  # Cyrillic a
        "с": "c",
        "е": "e",
        "і": "i",
        "ј": "j",
        "о": "o",
        "р": "p",
        "ѕ": "s",
        "х": "x",
        "у": "y",
        "А": "A",
        "В": "B",
        "С": "C",
        "Е": "E",
        "Н": "H",
        "І": "I",
        "Ј": "J",
        "К": "K",
        "М": "M",
        "О": "O",
        "Р": "P",
        "Ѕ": "S",
        "Т": "T",
        "Х": "X",
        "ο": "o",  # Greek omicron
        "α": "a",  # Greek alpha
        "Ο": "O",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
        "Ζ": "Z",
    }
)

_DEFANG = (
    (re.compile(r"\s*[\[\(\{]\s*(?:at|@)\s*[\]\)\}]\s*", re.IGNORECASE), "@"),
    (re.compile(r"\s*[\[\(\{]\s*(?:dot|\.)\s*[\]\)\}]\s*", re.IGNORECASE), "."),
    (re.compile(r"\s+at\s+(?=[a-z0-9-]+(?:\.|\s+dot\s+))", re.IGNORECASE), "@"),
    (re.compile(r"\s+dot\s+(?=[a-z]{2,})", re.IGNORECASE), "."),
    (re.compile(r"\bhxxp(s?)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
)

# Characters that can belong to a substring run (see substring._extract_runs).
_NOT_RUN_CHAR = re.compile(r"[^A-Za-z0-9_.@:/\-]+")

_SPACED = re.compile(r"(?<!\S)(?:\S ){5,}\S(?!\S)")
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_HTML_REF = re.compile(r"&(?:#\d+|#[xX][0-9a-fA-F]+|[A-Za-z]+);")

MAX_DEPTH = 2


def normalize(text: str) -> str:
    """NFKC, invisible format characters removed, look-alikes mapped, casefolded."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.translate(_CONFUSABLES).casefold()


def defang(text: str) -> str:
    """Undo common defanging of addresses and links."""
    for pattern, replacement in _DEFANG:
        text = pattern.sub(replacement, text)
    return text


def despace(text: str) -> str:
    """Join runs of six or more single characters separated by single spaces."""
    return _SPACED.sub(lambda m: m.group(0).replace(" ", ""), text)


def squash(text: str) -> str:
    """Remove every character that cannot be part of a substring run."""
    return _NOT_RUN_CHAR.sub("", text)


def _printable(raw: bytes) -> str | None:
    """`raw` as text if it is UTF-8 and almost all printable, else None."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 4:
        return None
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return text if printable >= 0.95 * len(text) else None


def _b64(token: str) -> str | None:
    stripped = token.rstrip("=")
    padded = stripped + "=" * (-len(stripped) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            text = _printable(decoder(padded))
        except (binascii.Error, ValueError):
            continue
        if text is not None:
            return text
    return None


def _hex(token: str) -> str | None:
    try:
        return _printable(bytes.fromhex(token))
    except ValueError:
        return None


def decoded(text: str, depth: int = MAX_DEPTH) -> list[str]:
    """Every decoding of `text` (or of tokens inside it) the decoder set finds."""
    if depth <= 0:
        return []
    found: list[str] = []
    if _PERCENT.search(text):
        found.append(unquote(text))
    if _HTML_REF.search(text):
        found.append(html.unescape(text))
    for token in _HEX_TOKEN.findall(text):
        value = _hex(token)
        if value is not None:
            found.append(value)
    for token in _BASE64_TOKEN.findall(text):
        value = _b64(token)
        if value is not None:
            found.append(value)
    deeper = [d for item in found for d in decoded(item, depth - 1)]
    return _unique([*found, *deeper])


def views(text: str, *, squashed: bool = False) -> list[str]:
    """Canonical forms of `text` to compare. Always starts with `normalize(text)`."""
    out: list[str] = []
    for variant in (text, *decoded(text)):
        base = normalize(variant)
        out += [base, defang(base), defang(despace(base))]
        if squashed:
            out.append(squash(base))
    return _unique(out)


def _unique(items: list[str]) -> list[str]:
    """`items` without repeats, first occurrence kept."""
    return list(dict.fromkeys(items))
