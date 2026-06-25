"""IOC validation and classification: IP, domain, URL, file hash."""

import re
import ipaddress

_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# Characters that have no legitimate place in an IP/FQDN/URL/hash and that
# could be used to smuggle shell metacharacters through to a subprocess call.
_FORBIDDEN_CHARS = set(";|&$`\n\r\x00 ")


def _is_ip_literal(value: str) -> bool:
    """Return True if value parses as a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def hash_subtype(value: str) -> str:
    """Classify a hex string as md5, sha1, sha256, or unknown based on length."""
    length = len(value)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    return "unknown"


def validate_indicator(value: str) -> tuple:
    """Validate that value is a safe, well-formed IP, FQDN, URL, or file hash.

    Returns a (is_valid, ioc_type) tuple. ioc_type is one of
    "ip", "domain", "url", "hash", or "" when is_valid is False.
    Rejects shell metacharacters, whitespace, and newlines outright so that
    nothing unsafe ever reaches a subprocess call.
    """
    if not value:
        return False, ""

    if any(ch in _FORBIDDEN_CHARS for ch in value):
        return False, ""

    if _MD5_RE.match(value) or _SHA1_RE.match(value) or _SHA256_RE.match(value):
        return True, "hash"

    if _is_ip_literal(value):
        return True, "ip"

    if value.startswith("http://") or value.startswith("https://"):
        rest = value.split("://", 1)[1]
        if not rest:
            return False, ""
        host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 and not _is_ip_literal(host) else host
        if _FQDN_RE.match(host) or _is_ip_literal(host):
            return True, "url"
        return False, ""

    if _FQDN_RE.match(value):
        return True, "domain"

    return False, ""
