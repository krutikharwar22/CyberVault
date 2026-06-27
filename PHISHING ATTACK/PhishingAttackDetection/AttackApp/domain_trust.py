"""
Domain trust assessment: only known official site domains may be labeled SAFE.

Fake / look-alike / forwarded suspicious domains are treated as threats.
HTTPS or generic ML "low score" alone does not imply safety.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any, Optional
from urllib.parse import parse_qs, unquote, urlsplit

# brand key -> official registrable domains (and common country TLDs)
OFFICIAL_BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "google": ("google.com", "google.co.in", "google.co.uk", "googleapis.com", "gstatic.com", "youtube.com"),
    "microsoft": ("microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "azure.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"),
    "paypal": ("paypal.com", "paypal.me"),
    "facebook": ("facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com"),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com",),
    "twitter": ("twitter.com", "x.com",),
    "github": ("github.com", "github.io"),
    "dropbox": ("dropbox.com",),
    "adobe": ("adobe.com",),
    "yahoo": ("yahoo.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
    "gov_in": ("gov.in", "nic.in"),
    "cybercrime": ("cybercrime.gov.in",),
    "kesha":("keshakapadia.com", "keshakapadia.in"),
    "RNGPIT":("https://rngpit.gnums.co.in"),
}

# Flat set for quick lookup
_OFFICIAL_HOSTS: set[str] = set()
for _domains in OFFICIAL_BRAND_DOMAINS.values():
    for _d in _domains:
        _OFFICIAL_HOSTS.add(_d.lower())

_REDIRECT_QUERY_KEYS = (
    "url", "u", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "next", "target", "dest", "destination", "link", "goto", "out", "continue",
    "rurl", "view", "redir", "forward",
)

_HOMOGLYPH_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
})


def _normalize_host(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
    except Exception:
        return ""
    host = (parts.hostname or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        pass
    return host


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain (not a full PSL implementation)."""
    host = (host or "").lower().strip(".")
    if not host:
        return ""
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    # co.in, com.au style
    if labels[-2] in ("co", "com", "org", "net", "gov", "ac") and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _host_is_official(host: str) -> tuple[bool, Optional[str]]:
    host = host.lower()
    reg = registrable_domain(host)
    if host in _OFFICIAL_HOSTS or reg in _OFFICIAL_HOSTS:
        return True, reg
    for official in _OFFICIAL_HOSTS:
        if host == official or host.endswith("." + official):
            return True, official
    return False, None


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _looks_like_brand_impersonation(host: str) -> list[str]:
    signals: list[str] = []
    reg = registrable_domain(host)
    host_ascii = host.translate(_HOMOGLYPH_MAP)

    for brand, domains in OFFICIAL_BRAND_DOMAINS.items():
        for official in domains:
            base = official.split(".")[0]
            if len(base) < 4:
                continue
            if base in host_ascii and reg != official and not host.endswith("." + official):
                if not _host_is_official(host)[0]:
                    signals.append(f"brand_in_hostname:{brand}")
            if reg != official:
                sim = _similarity(reg.replace("-", ""), official.replace(".", ""))
                if sim >= 0.82 and sim < 1.0:
                    signals.append(f"typosquat:{brand}")
                if sim >= 0.72 and ("-" in reg or reg.count(".") > official.count(".")):
                    signals.append(f"lookalike_domain:{brand}")

    if "xn--" in host:
        signals.append("punycode_homograph")
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
        signals.append("raw_ip_host")
    if host.count("-") >= 3:
        signals.append("many_hyphens")
    if len(host) > 48:
        signals.append("very_long_hostname")

    # paypa1-security-login.com style
    for brand in OFFICIAL_BRAND_DOMAINS:
        token = brand.replace("_", "")
        if len(token) >= 4 and token in host_ascii.replace("-", "").replace(".", ""):
            if not _host_is_official(host)[0]:
                signals.append(f"brand_token_embedded:{brand}")

    return list(dict.fromkeys(signals))


def extract_forwarded_urls(url: str, *, limit: int = 5) -> list[str]:
    """Nested URLs in query string (common in phishing forwards)."""
    raw = (url or "").strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
    except Exception:
        return []
    found: list[str] = []
    qs = parse_qs(parts.query, keep_blank_values=False)
    for key in _REDIRECT_QUERY_KEYS:
        for val in qs.get(key, []):
            decoded = unquote(val).strip()
            if decoded.startswith(("http://", "https://", "www.")):
                if decoded not in found:
                    found.append(decoded)
            if len(found) >= limit:
                return found
    return found


def assess_domain_trust(url: str) -> dict[str, Any]:
    """
    Returns trust verdict used before marking any URL SAFE.

    trust: official | unknown | impersonation | forwarded_risk
    """
    host = _normalize_host(url)
    if not host:
        return {
            "trust": "unknown",
            "host": "",
            "registered_domain": "",
            "official": False,
            "signals": ["no_host"],
            "forwarded_urls": [],
            "forwarded_assessments": [],
            "message": "No valid domain — cannot verify as an official site.",
        }

    reg = registrable_domain(host)
    is_official, matched = _host_is_official(host)
    signals = _looks_like_brand_impersonation(host)
    forwarded = extract_forwarded_urls(url)
    fwd_assessments: list[dict[str, Any]] = []

    for inner in forwarded:
        inner_host = _normalize_host(inner)
        inner_official, _ = _host_is_official(inner_host)
        inner_signals = _looks_like_brand_impersonation(inner_host)
        inner_trust = "official" if inner_official else (
            "impersonation" if inner_signals else "unknown"
        )
        fwd_assessments.append({
            "url": inner[:200],
            "host": inner_host,
            "trust": inner_trust,
            "signals": inner_signals,
        })

    if fwd_assessments and not is_official:
        risky_fwd = [f for f in fwd_assessments if f["trust"] != "official"]
        if risky_fwd or forwarded:
            signals.append("forwarded_untrusted_destination")
            return {
                "trust": "forwarded_risk",
                "host": host,
                "registered_domain": reg,
                "official": False,
                "matched_official": matched,
                "signals": signals,
                "forwarded_urls": forwarded,
                "forwarded_assessments": fwd_assessments,
                "message": (
                    "This link forwards to another domain that is not a verified official site. "
                    "Do not trust the message based on the visible sender alone."
                ),
            }

    if signals:
        return {
            "trust": "impersonation",
            "host": host,
            "registered_domain": reg,
            "official": False,
            "matched_official": None,
            "signals": signals,
            "forwarded_urls": forwarded,
            "forwarded_assessments": fwd_assessments,
            "message": (
                f"Domain «{reg}» resembles a known brand but is not an official registered site."
            ),
        }

    if is_official:
        return {
            "trust": "official",
            "host": host,
            "registered_domain": reg,
            "official": True,
            "matched_official": matched,
            "signals": [],
            "forwarded_urls": forwarded,
            "forwarded_assessments": fwd_assessments,
            "message": f"Domain matches verified official site ({matched or reg}).",
        }

    return {
        "trust": "unknown",
        "host": host,
        "registered_domain": reg,
        "official": False,
        "matched_official": None,
        "signals": ["unlisted_domain"],
        "forwarded_urls": forwarded,
        "forwarded_assessments": fwd_assessments,
        "message": (
            f"«{reg}» is not on the verified official-domain list. "
            "Only known legitimate organization domains are marked SAFE."
        ),
    }


def apply_domain_trust_to_prediction(
    url: str,
    ml_verdict: str,
    ml_threat_type: str,
    ml_score: float,
) -> tuple[str, str, float, dict[str, Any]]:
    """
    Merge ML output with domain policy. Never return safe unless trust is official.
    """
    domain = assess_domain_trust(url)
    trust = domain["trust"]

    if trust == "official" and ml_verdict != "threat":
        return "safe", "safe", ml_score, domain

    if trust in ("impersonation", "forwarded_risk"):
        threat_type = "phishing_domain" if trust == "impersonation" else "forwarded_phishing"
        score = max(ml_score, 0.85)
        return "threat", threat_type, score, domain

    # unknown / unlisted — not safe by policy
    if ml_verdict == "threat":
        return "threat", ml_threat_type, ml_score, domain

    return "threat", "unverified_domain", max(ml_score, 0.55), domain
