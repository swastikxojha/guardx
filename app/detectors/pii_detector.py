"""Deterministic local PII and credential detection with safe redaction."""

from __future__ import annotations

import re
import logging
from functools import lru_cache
from dataclasses import dataclass
from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class PIIMatch:
    entity_type: str
    start: int
    end: int
    confidence: float
    value: str


PATTERNS: dict[str, tuple[re.Pattern[str], float]] = {
    "EMAIL": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), .99),
    "PHONE": (re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .()-]?)?(?:\(?\d{2,4}\)?[ .()-]?)?\d{3,4}[ .-]?\d{3,4}(?!\w)"), .82),
    "IP_ADDRESS": (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), .96),
    "SSN": (re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), .99),
    "CREDIT_CARD": (re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), .80),
    "DOB": (re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])[/-](?:0?[1-9]|1[0-2])[/-](?:19|20)\d{2}\b"), .92),
    "DOB_TEXT": (re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])\s+(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s*,?\s+(?:19|20)\d{2}\b", re.I), .92),
    "AADHAAR": (re.compile(r"(?<!\d)\d{4}[ -]\d{4}[ -]\d{4}(?!\d)"), .88),
    "PAN": (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b", re.I), .92),
    "IFSC": (re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.I), .94),
    "GSTIN": (re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b", re.I), .92),
}

# Context labels avoid treating an arbitrary 9-18 digit number as an account
# identifier, while still detecting common national and financial identifiers.
CONTEXT_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("NAME", re.compile(r"\b(?i:my name is|i am|contact|customer|patient|name\s*:)\s*((?:[A-Z][a-z'-]{1,30}\s+){1,2}[A-Z][a-z'-]{1,30})\b"), .82),
    ("ADDRESS", re.compile(r"\b(?:home address|mailing address|street address|address)\s*[:=]\s*([^\n,;]{5,120})", re.I), .88),
    ("BANK_ACCOUNT", re.compile(r"\b(?:bank\s+)?account(?:\s+number|\s+no\.?|\s+#)?\s*(?:is\s+|[:=]\s*)?(\d(?:[ -]?\d){8,17})\b", re.I), .88),
    ("SSN", re.compile(r"\b(?:ssn|social security(?: number)?)\s*[:=#]?\s*(\d{3}[ -]?\d{2}[ -]?\d{4})\b", re.I), .96),
    ("DOB", re.compile(r"\b(?:dob|date of birth|born on)\s*[:=]?\s*((?:\d{1,2}[/-]\d{1,2}[/-](?:19|20)\d{2})|(?:[A-Z][a-z]+\s+\d{1,2},?\s+(?:19|20)\d{2}))\b", re.I), .95),
    ("AADHAAR", re.compile(r"\b(?:aadhaar|aadhar)(?:\s+(?:number|no\.?))?\s*[:=#]?\s*(\d{4}[ -]?\d{4}[ -]?\d{4})\b", re.I), .97),
    ("PASSPORT", re.compile(r"\b(?:passport)(?:\s+(?:number|no\.?))?\s*[:=#]?\s*([A-Z]\d{7})\b", re.I), .90),
    ("DRIVING_LICENCE", re.compile(r"\b(?:driver'?s?\s+licen[cs]e|dl)(?:\s+(?:number|no\.?))?\s*[:=#]?\s*([A-Z0-9-]{8,20})\b", re.I), .84),
    ("VOTER_ID", re.compile(r"\b(?:voter\s+id|epic)(?:\s+(?:number|no\.?))?\s*[:=#]?\s*([A-Z]{3}\d{7})\b", re.I), .90),
    ("UPI", re.compile(r"\b(?:upi(?:\s+id)?\s*[:=]?\s*)?([\w.-]+@[a-zA-Z][\w.-]*)\b", re.I), .88),
    ("API_KEY", re.compile(r"(?i)\b(?:api[_ -]?key|secret[_ -]?key)\s*[:=]\s*([A-Za-z0-9_./+=-]{12,})"), .96),
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("API_KEY", re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"), .99),
    ("PASSWORD", re.compile(r"(?i)\b(?:password|passwd|pwd|passphrase)\s*[:=]\s*[^\s,;]+"), .96),
    ("ACCESS_TOKEN", re.compile(r"(?i)\b(?:bearer|access[_ -]?token|refresh[_ -]?token)\s+[A-Za-z0-9._~+/-]{12,}=?"), .96),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), .99),
)


@lru_cache(maxsize=1)
def _local_person_ner():
    """Load an explicitly configured local spaCy model, never downloading one."""
    model_name = settings.pii_ner_model.strip()
    if not model_name:
        return None
    try:
        import spacy
        return spacy.load(model_name, disable=["parser", "tagger", "lemmatizer"])
    except (ImportError, OSError) as exc:
        logger.warning("Local PII NER model unavailable; using deterministic detectors (%s)", type(exc).__name__)
        return None


def luhn(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _verhoeff(value: str) -> bool:
    """Validate the Aadhaar Verhoeff check digit without retaining the value."""
    multiplication = (
        (0,1,2,3,4,5,6,7,8,9),(1,2,3,4,0,6,7,8,9,5),(2,3,4,0,1,7,8,9,5,6),
        (3,4,0,1,2,8,9,5,6,7),(4,0,1,2,3,9,5,6,7,8),(5,9,8,7,6,0,4,3,2,1),
        (6,5,9,8,7,1,0,4,3,2),(7,6,5,9,8,2,1,0,4,3),(8,7,6,5,9,3,2,1,0,4),
        (9,8,7,6,5,4,3,2,1,0),
    )
    permutation = (
        (0,1,2,3,4,5,6,7,8,9),(1,5,7,6,2,8,3,0,9,4),(5,8,0,3,7,9,6,1,4,2),
        (8,9,1,6,0,4,3,5,2,7),(9,4,5,3,1,2,6,8,7,0),(4,2,8,6,5,7,3,9,0,1),
        (2,7,9,3,8,0,6,4,1,5),(7,0,4,6,9,1,3,2,5,8),
    )
    checksum = 0
    for index, digit in enumerate(reversed(value)):
        checksum = multiplication[checksum][permutation[index % 8][int(digit)]]
    return checksum == 0


def detect_pii(text: str) -> list[PIIMatch]:
    found: list[PIIMatch] = []

    def add(entity: str, start: int, end: int, confidence: float) -> None:
        if end > start:
            found.append(PIIMatch(entity, start, end, confidence, text[start:end]))

    for entity, (pattern, confidence) in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group()
            if entity == "CREDIT_CARD" and not luhn(value):
                continue
            if entity == "IP_ADDRESS" and any(int(part) > 255 for part in value.split(".")):
                continue
            if entity == "AADHAAR" and not _verhoeff(re.sub(r"\D", "", value)):
                continue
            add(entity, match.start(), match.end(), confidence)

    for entity, pattern, confidence in CONTEXT_PATTERNS:
        for match in pattern.finditer(text):
            # Context patterns capture only the private value, leaving labels intact.
            start, end = match.span(1)
            value = match.group(1)
            if entity == "UPI" and "@" not in value:
                continue
            if entity == "API_KEY" and value.startswith("sk-"):
                entity = "API_KEY"
            add(entity, start, end, confidence)

    # Optional local NER adds recall for unlabelled person names. It is opt-in,
    # does not download a model, and never sends text outside this process.
    ner = _local_person_ner()
    if ner is not None:
        try:
            doc = ner(text[:50_000])
            for entity in doc.ents:
                if entity.label_ == "PERSON":
                    start, end = entity.start_char, entity.end_char
                    # Small NER models sometimes emit only the first token of
                    # a multi-token name. Include adjacent title-cased tokens,
                    # while stopping at ordinary lowercase prose.
                    while True:
                        adjacent = re.match(r"\s+([A-Z][a-z]+(?:[-'][A-Z][a-z]+)*)\b", text[end:])
                        if not adjacent:
                            break
                        end += adjacent.end()
                    add("NAME", start, end, .78)
        except Exception as exc:  # Keep deterministic checks available on NER errors.
            logger.warning("Local PII NER failed; using deterministic detections (%s)", type(exc).__name__)

    for entity, pattern, confidence in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            add(entity, match.start(), match.end(), confidence)

    priority = {"CREDIT_CARD": 10, "SSN": 9, "AADHAAR": 8, "API_KEY": 8, "ACCESS_TOKEN": 8, "PASSWORD": 8}
    found.sort(key=lambda item: (item.start, -(item.end - item.start), -priority.get(item.entity_type, 0), -item.confidence))
    # Retain the most specific/high-confidence match for overlapping spans.
    non_overlapping: list[PIIMatch] = []
    for item in found:
        if any(item.start < prior.end and prior.start < item.end for prior in non_overlapping):
            continue
        non_overlapping.append(item)
    return non_overlapping


def sanitize(text: str, matches: list[PIIMatch], mode: str = "REDACT") -> str | None:
    mode = (mode or "REDACT").upper()
    if mode == "BLOCK":
        return None
    if mode == "ALLOW":
        return text
    if mode not in {"REDACT", "PSEUDONYMIZE"}:
        # Unknown configuration must fail closed instead of returning source text.
        return None

    counters: dict[str, int] = {}
    replacements: list[tuple[PIIMatch, str]] = []
    for match in matches:
        counters[match.entity_type] = counters.get(match.entity_type, 0) + 1
        suffix = "REDACTED" if mode == "REDACT" else f"{counters[match.entity_type]:03d}"
        replacements.append((match, f"[{match.entity_type}_{suffix}]"))
    output = text
    for match, token in reversed(replacements):
        output = output[:match.start] + token + output[match.end:]
    return output
