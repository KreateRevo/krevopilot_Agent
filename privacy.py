import hashlib
import hmac
import ipaddress
import re
from typing import Any

SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key|connection[_-]?string|dsn)",
    re.IGNORECASE,
)
VALUE_PATTERNS = [
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)"), r"\1=[REDACTED]"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[REDACTED_EMAIL]"),
    (re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"), "[REDACTED_IP]"),
    (re.compile(r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----"), "[REDACTED_PRIVATE_MATERIAL]"),
    (re.compile(r'''(["'])(?:(?!\1).){3,}\1'''), "[REDACTED_QUOTED_DETAIL]"),
]

LOG_VALUE_PATTERNS = [
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)\b([\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)[\w.-]*)\s*[:=]\s*([^\s,;]+)"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(postgres|mysql|mongodb|redis)://([^:\s/@]+):([^@\s]+)@"), r"\1://\2:[REDACTED]@"),
    (re.compile(r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----"), "[REDACTED_PRIVATE_MATERIAL]"),
]

IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


def alias_identifier(salt: bytes, kind: str, value: str | None) -> str:
    raw = f"{kind}:{value or 'unknown'}".encode("utf-8", errors="replace")
    digest = hmac.new(salt, raw, hashlib.sha256).hexdigest()[:16]
    return f"{kind}-{digest}"


def scrub_text(text: str | None, identifiers: list[str] | None = None) -> tuple[str, int]:
    cleaned = str(text or "")
    redactions = 0
    for identifier in sorted({item for item in (identifiers or []) if item}, key=len, reverse=True):
        cleaned, count = re.subn(re.escape(identifier), "[REDACTED_IDENTIFIER]", cleaned)
        redactions += count
    for pattern, replacement in VALUE_PATTERNS:
        cleaned, count = pattern.subn(replacement, cleaned)
        redactions += count
    return cleaned, redactions


def scrub_log_text(
    text: str | None,
    identifiers: list[str] | None = None,
    *,
    mask_emails: bool = True,
    mask_public_ips: bool = True,
    mask_internal_ips: bool = False,
) -> tuple[str, int]:
    """Redact application log text before it leaves the customer cluster.

    This intentionally keeps more diagnostic context than ``scrub_text``.
    Secrets/tokens are always masked. Emails and IPs are policy-controlled
    because some teams need internal IPs for debugging while strict teams may
    mask everything.
    """
    cleaned = str(text or "")
    redactions = 0
    for identifier in sorted({item for item in (identifiers or []) if item}, key=len, reverse=True):
        cleaned, count = re.subn(re.escape(identifier), "[REDACTED_IDENTIFIER]", cleaned)
        redactions += count
    for pattern, replacement in LOG_VALUE_PATTERNS:
        cleaned, count = pattern.subn(replacement, cleaned)
        redactions += count
    if mask_emails:
        cleaned, count = EMAIL_PATTERN.subn("[REDACTED_EMAIL]", cleaned)
        redactions += count
    if mask_public_ips or mask_internal_ips:
        def replace_ip(match: re.Match[str]) -> str:
            nonlocal redactions
            value = match.group(0)
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError:
                return value
            is_internal = parsed.is_private or parsed.is_loopback or parsed.is_link_local
            if mask_internal_ips or (mask_public_ips and not is_internal):
                redactions += 1
                return "[REDACTED_IP]"
            return value

        cleaned = IP_PATTERN.sub(replace_ip, cleaned)
    return cleaned, redactions


def sanitize_value(value: Any, key: str = "") -> tuple[Any, int]:
    if SENSITIVE_KEY.search(key):
        return "[REDACTED_SENSITIVE_FIELD]", 1
    if isinstance(value, dict):
        result = {}
        count = 0
        for child_key, child_value in value.items():
            cleaned, child_count = sanitize_value(child_value, str(child_key))
            result[str(child_key)] = cleaned
            count += child_count
        return result, count
    if isinstance(value, list):
        result = []
        count = 0
        for item in value:
            cleaned, child_count = sanitize_value(item, key)
            result.append(cleaned)
            count += child_count
        return result, count
    if isinstance(value, str):
        return scrub_text(value)
    return value, 0
