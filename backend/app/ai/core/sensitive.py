"""Detection and sanitisation of secrets, personal data and biometric payloads.

Used before indexing (passwords, tokens, API keys and biometric data must
never enter the vector store), before logging, and by the Gemini privacy
policy. Detection is pattern-based and therefore incomplete: it cannot
recognise a person's name or a household routine. That is why the privacy
policy decides by *where data came from* first, and treats a clean scan only
as a necessary condition, never as proof that data is anonymous.

Text is normalised (NFKC, invisible and bidirectional control characters
removed) before scanning, so look-alike and zero-width tricks do not hide a
match. Sanitised output is the normalised text with each finding replaced
by ``[REDACTED:<category>]``.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Category(StrEnum):
    CREDENTIAL = "credential"
    BIOMETRIC = "biometric"
    PERSONAL = "personal"
    INTERNAL_ID = "internal_id"
    EVIDENCE_REF = "evidence_ref"


@dataclass(frozen=True)
class Finding:
    detector: str
    category: Category
    start: int
    end: int


@dataclass(frozen=True)
class Sanitised:
    text: str
    findings: tuple[Finding, ...]

    @property
    def categories(self) -> frozenset[Category]:
        return frozenset(f.category for f in self.findings)


_INVISIBLE = re.compile(
    "[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_SCAN_CHARS = 200_000

_IMAGE_EXT = r"(?:jpe?g|png|gif|bmp|webp|tiff?|heic|mp4|avi|mov|mkv|webm)"

_DETECTORS: tuple[tuple[str, Category, re.Pattern[str]], ...] = (
    (
        "private_key",
        Category.CREDENTIAL,
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?"
            r"(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"
        ),
    ),
    (
        "jwt",
        Category.CREDENTIAL,
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    (
        "bearer_token",
        Category.CREDENTIAL,
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*"),
    ),
    ("google_api_key", Category.CREDENTIAL, re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("openai_style_key", Category.CREDENTIAL, re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("github_token", Category.CREDENTIAL, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("aws_access_key", Category.CREDENTIAL, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", Category.CREDENTIAL, re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    (
        "password_hash",
        Category.CREDENTIAL,
        re.compile(r"\$argon2(?:id|i|d)\$\S+|\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),
    ),
    (
        "secret_assignment",
        Category.CREDENTIAL,
        re.compile(
            r"(?i)\b(?:pass(?:word|wd)?|pwd|secret(?:_key)?|token|api[_-]?key|"
            r"client[_-]?secret|access[_-]?key)\b\s*[:=]\s*[\"']?[^\s\"',;]{4,}"
        ),
    ),
    (
        "image_data_uri",
        Category.BIOMETRIC,
        re.compile(r"data:(?:image|video)/[A-Za-z0-9.+-]+;base64,[A-Za-z0-9+/=\s]+"),
    ),
    (
        "embedding_vector",
        Category.BIOMETRIC,
        # 16 or more decimal numbers in a row: an embedding or feature vector.
        re.compile(
            r"-?\d+\.\d+(?:[ \t]*[,;][ \t\n]*-?\d+\.\d+|[ \t\n]+-?\d+\.\d+){15,}"
        ),
    ),
    ("base64_blob", Category.BIOMETRIC, re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")),
    (
        "email",
        Category.PERSONAL,
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "ipv4",
        Category.PERSONAL,
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
    ),
    (
        "ipv6",
        Category.PERSONAL,
        # Full form (5+ groups) or compressed form with '::'. Times such as
        # 10:00:00 have too few groups and no '::', so they do not match.
        re.compile(
            r"(?i)(?<![\w:])(?:(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}"
            r"|(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?"
            r"|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}))(?![\w:])"
        ),
    ),
    (
        "mac_address",
        Category.PERSONAL,
        re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b"),
    ),
    (
        "phone_number",
        Category.PERSONAL,
        re.compile(r"(?<![\w.])\+?\d[\d ().-]{7,18}\d(?![\w.])"),
    ),
    (
        "evidence_path",
        Category.EVIDENCE_REF,
        re.compile(rf"(?i)\b[\w.-]+(?:/[\w.-]+)*\.{_IMAGE_EXT}\b"),
    ),
    ("hex_identifier", Category.INTERNAL_ID, re.compile(r"(?i)\b[0-9a-f]{32,}\b")),
)

_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")

#: Mapping keys whose values are never kept, whatever they contain.
SENSITIVE_KEY = re.compile(
    r"(?i)(password|passwd|secret|token|authorization|api[_-]?key|cookie|"
    r"embedding|vector|face|image|snapshot|photo|biometric|private[_-]?key)"
)


def normalise(text: str) -> str:
    """NFKC, remove invisible and bidi controls, drop other control chars."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    return _CONTROL.sub("", text)


def _phone_ok(match: str) -> bool:
    digits = sum(c.isdigit() for c in match)
    return 9 <= digits <= 15 and not _ISO_DATE.search(match)


def scan(text: str) -> tuple[Finding, ...]:
    """Findings in the *normalised* text, sorted by position."""
    clean = normalise(text)[:MAX_SCAN_CHARS]
    found: list[Finding] = []
    for name, category, pattern in _DETECTORS:
        for m in pattern.finditer(clean):
            if name == "phone_number" and not _phone_ok(m.group(0)):
                continue
            found.append(Finding(name, category, m.start(), m.end()))
    found.sort(key=lambda f: (f.start, -f.end))
    return tuple(found)


def sanitise(text: str) -> Sanitised:
    """Replace every finding; overlapping findings collapse into one marker."""
    clean = normalise(text)[:MAX_SCAN_CHARS]
    findings = scan(clean)
    merged: list[tuple[int, int, Category]] = []
    for f in findings:
        if merged and f.start < merged[-1][1]:
            start, end, cat = merged[-1]
            # Keep the most serious category for the merged span.
            worst = min(cat, f.category, key=_SEVERITY_ORDER.index)
            merged[-1] = (start, max(end, f.end), worst)
        else:
            merged.append((f.start, f.end, f.category))
    out: list[str] = []
    cursor = 0
    for start, end, cat in merged:
        out.append(clean[cursor:start])
        out.append(f"[REDACTED:{cat.value}]")
        cursor = end
    out.append(clean[cursor:])
    return Sanitised("".join(out), findings)


_SEVERITY_ORDER = [
    Category.CREDENTIAL,
    Category.BIOMETRIC,
    Category.EVIDENCE_REF,
    Category.PERSONAL,
    Category.INTERNAL_ID,
]


def sanitise_mapping(data: Mapping[str, Any], depth: int = 0) -> dict[str, Any]:
    """Sanitise every string value; drop values under sensitive keys entirely."""
    if depth > 4:
        return {"_truncated": True}
    clean: dict[str, Any] = {}
    for key, value in list(data.items())[:100]:
        name = normalise(str(key))[:64]
        if SENSITIVE_KEY.search(name):
            clean[name] = "[REDACTED:sensitive_field]"
        elif isinstance(value, str):
            clean[name] = sanitise(value).text
        elif isinstance(value, Mapping):
            clean[name] = sanitise_mapping(value, depth + 1)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            clean[name] = "[REDACTED:binary]"
        elif isinstance(value, (list, tuple)):
            clean[name] = [sanitise(str(v)).text for v in list(value)[:100]]
        elif isinstance(value, (int, float, bool)) or value is None:
            clean[name] = value
        else:
            clean[name] = sanitise(str(value)).text
    return clean
