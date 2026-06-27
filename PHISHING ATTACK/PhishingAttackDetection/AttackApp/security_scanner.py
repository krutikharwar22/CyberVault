"""
Defensive analysis helpers: email/URL phishing signals, DNS resolution for URLs,
and heuristic checks for SQL injection and DoS-style patterns in pasted text.

Intended for security monitoring and training — not for attacking systems.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import unquote_plus
from urllib.parse import urlparse, urlunparse

from .domain_trust import assess_domain_trust, registrable_domain

# -----------------------------------------------------------------------------
# URL extraction
# -----------------------------------------------------------------------------

_URL_RE = re.compile(
    r'(?P<url>https?://[^\s<>"\'`]+|www\.[^\s<>"\'`]+)',
    re.IGNORECASE,
)


def normalize_url(raw: str) -> str:
    u = raw.strip().rstrip(").,;]")
    if u.lower().startswith("www."):
        return "http://" + u
    return u


def validate_and_normalize_scan_url(raw: str, *, max_len: int = 2048) -> tuple[str, dict[str, Any]]:
    """
    Normalize + validate a user-supplied URL for defensive scanning.

    Security goals:
    - accept only http(s)
    - reject userinfo (user:pass@host) to avoid ambiguity / log trickery
    - reject localhost/private/special IP literals (SSRF-style inputs)
    - keep a strict max length

    Returns (normalized_url, meta).
    Raises ValueError on invalid/unsafe inputs.
    """
    u = normalize_url(raw or "")
    if not u:
        raise ValueError("Empty URL")
    if len(u) > max_len:
        raise ValueError(f"URL too long (>{max_len} chars)")

    try:
        p = urlparse(u)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Invalid URL: {exc}") from exc

    scheme = (p.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only http(s) URLs are allowed")

    # Reject userinfo to avoid log/user confusion and unexpected parsing differences.
    if "@" in (p.netloc or ""):
        raise ValueError("URLs with user info (user@host) are not allowed")

    host = (p.hostname or "").strip().lower()
    if not host:
        raise ValueError("URL has no hostname")

    if host in ("localhost",):
        raise ValueError("Localhost URLs are not allowed")

    # Reject raw IP literals that are private/special to prevent SSRF-style abuse.
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("Private/special IPs are not allowed")
    except ValueError as exc:
        # host is not an IP literal -> OK, continue validation
        if "not appear to be an IPv4 or IPv6 address" not in str(exc):
            raise

    # Canonicalize host to IDNA (punycode) where applicable.
    idna_host = host.encode("idna").decode("ascii")
    rebuilt = urlunparse(
        (
            scheme,
            idna_host + (f":{p.port}" if p.port else ""),
            p.path or "",
            p.params or "",
            p.query or "",
            p.fragment or "",
        )
    )

    meta = {
        "scheme": scheme,
        "hostname": host,
        "hostname_idna": idna_host,
        "punycode_present": "xn--" in idna_host,
        "has_fragment": bool(p.fragment),
    }
    return rebuilt, meta


def url_heuristics(url: str, *, url_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Lightweight, defensive URL heuristics (no network access).

    Returns a dict with:
    - risk: low|medium|high
    - score: 0..1 heuristic score
    - signals: list of short labels
    """
    u = (url or "").strip()
    meta = url_meta or {}
    signals: list[str] = []

    # Obvious phishing cues
    if "@" in u:
        signals.append("contains_at_sign")
    if meta.get("punycode_present"):
        signals.append("idn_punycode")

    # Length + delimiter density (often seen in tracking / obfuscation)
    if len(u) >= 120:
        signals.append("very_long_url")
    if u.count(".") >= 5:
        signals.append("many_dots")
    if u.count("/") >= 6:
        signals.append("deep_path")
    if u.count("%") >= 6:
        signals.append("heavy_percent_encoding")
    if u.count("&") >= 6 and u.count("=") >= 6:
        signals.append("many_query_params")

    # Keyword cues (kept intentionally small; ML covers more nuance)
    lowered = u.lower()
    for kw in ("login", "signin", "verify", "update", "secure", "account", "password", "bank", "billing"):
        if kw in lowered:
            signals.append(f"kw:{kw}")
            break

    # Risk scoring: simple weighted sum, capped to [0,1]
    score = 0.0
    if "contains_at_sign" in signals:
        score += 0.45
    if "idn_punycode" in signals:
        score += 0.30
    if "heavy_percent_encoding" in signals:
        score += 0.15
    if "many_query_params" in signals:
        score += 0.10
    if "very_long_url" in signals:
        score += 0.10
    if any(s.startswith("kw:") for s in signals):
        score += 0.10
    score = max(0.0, min(score, 1.0))

    risk = "low"
    if score >= 0.6 or len(signals) >= 5:
        risk = "high"
    elif score >= 0.25 or len(signals) >= 2:
        risk = "medium"

    return {"risk": risk, "score": float(score), "signals": signals[:12]}


def extract_urls(text: str, *, limit: int = 32) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _URL_RE.finditer(text or ""):
        n = normalize_url(m.group("url"))
        if n not in seen:
            seen.add(n)
            out.append(n)
            if len(out) >= limit:
                break
    return out


# -----------------------------------------------------------------------------
# DNS / IP resolution (display only; short timeout to limit SSRF-style delays)
# -----------------------------------------------------------------------------

_PRIVATE_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
    "169.254.",
)


def _is_private_or_special_ip(ip: str) -> bool:
    if not ip:
        return True
    if ip.startswith("::") or ip == "::1":
        return True
    if ip.startswith("fe80:") or ip.startswith("fc") or ip.startswith("fd"):
        return True
    return ip.startswith(_PRIVATE_PREFIXES)


def resolve_hostname_ips(hostname: str, *, timeout: float = 2.5) -> dict[str, Any]:
    """
    Resolve A/AAAA records for a hostname. Returns public and private lists separately.
    """
    hostname = (hostname or "").strip().lower()
    if not hostname:
        return {"hostname": "", "ips_public": [], "ips_private": [], "error": "empty host"}

    prev = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        return {"hostname": hostname, "ips_public": [], "ips_private": [], "error": str(exc)}
    finally:
        socket.setdefaulttimeout(prev)

    public: list[str] = []
    private: list[str] = []
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if _is_private_or_special_ip(ip):
            if ip not in private:
                private.append(ip)
        else:
            if ip not in public:
                public.append(ip)

    return {"hostname": hostname, "ips_public": public, "ips_private": private, "error": None}


def resolve_url_ips(url: str, *, timeout: float = 2.5) -> dict[str, Any]:
    try:
        parsed = urlparse(url)
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "hostname": "", "ips_public": [], "ips_private": [], "error": str(exc)}
    host = parsed.hostname
    if not host:
        return {"url": url, "hostname": "", "ips_public": [], "ips_private": [], "error": "no host"}
    r = resolve_hostname_ips(host, timeout=timeout)
    r["url"] = url
    return r


# -----------------------------------------------------------------------------
# Phishing-style email heuristics (paste body / headers)
# -----------------------------------------------------------------------------

_PHISH_REGEXES: list[tuple[str, re.Pattern[str]]] = [
    ("verify your account", re.compile(r"verify your account", re.I)),
    ("confirm your identity", re.compile(r"confirm your identity", re.I)),
    ("unusual activity", re.compile(r"unusual activity", re.I)),
    ("account suspended", re.compile(r"account\s+(?:will be|is)\s+suspended", re.I)),
    ("urgent click", re.compile(r"click\s+(?:here|below|the\s+link)\s+(?:immediately|now|within)", re.I)),
    ("reset your password", re.compile(r"reset your password", re.I)),
    ("wire transfer", re.compile(r"wire transfer", re.I)),
    ("gift card", re.compile(r"gift card", re.I)),
    ("validate account", re.compile(r"validate your (?:email|account)", re.I)),
    ("security alert", re.compile(r"security alert", re.I)),
    ("dear customer", re.compile(r"dear customer", re.I)),
    ("kindly", re.compile(r"\bkindly\b", re.I)),
    ("act now", re.compile(r"act now", re.I)),
]

_HOMOGRAPH_HINT = re.compile(r"xn--", re.IGNORECASE)


def scan_email_phishing_signals(text: str) -> dict[str, Any]:
    t = text or ""
    hit_labels: list[str] = []
    for label, rx in _PHISH_REGEXES:
        if rx.search(t):
            hit_labels.append(label)
    return {
        "suspicious_phrase_hits": len(hit_labels),
        "suspicious_phrases": hit_labels[:12],
        "idn_punycode_hint": bool(_HOMOGRAPH_HINT.search(t)),
        "link_count": len(extract_urls(t, limit=200)),
    }


# -----------------------------------------------------------------------------
# SQL injection heuristics (logs, query strings, request bodies)
# -----------------------------------------------------------------------------

_SQLI_PATTERNS: list[tuple[str, int, re.Pattern[str]]] = [
    ("union_select", 5, re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)),
    ("boolean_tautology", 4, re.compile(r"(?:'|\")?\s*(?:or|and)\s+\d+\s*=\s*\d+", re.IGNORECASE)),
    ("comment_tokens", 2, re.compile(r"--[\s\r\n]|/\*|\*/|#")),
    ("stacked_semicolon", 5, re.compile(r";\s*(?:select|insert|update|delete|drop|alter|create)\b", re.IGNORECASE)),
    ("sleep_benchmark_waitfor", 5, re.compile(r"\b(?:sleep|benchmark|waitfor\s+delay)\b", re.IGNORECASE)),
    ("information_schema", 4, re.compile(r"\binformation_schema\b", re.IGNORECASE)),
    ("xp_cmdshell", 5, re.compile(r"\bxp_cmdshell\b", re.IGNORECASE)),
    ("into_outfile", 5, re.compile(r"\binto\s+outfile\b|\bload_file\s*\(", re.IGNORECASE)),
    ("extractvalue_updatexml", 4, re.compile(r"\b(?:extractvalue|updatexml)\s*\(", re.IGNORECASE)),
    ("hex_encoding", 3, re.compile(r"0x[0-9a-f]{6,}", re.IGNORECASE)),
    ("char_function", 2, re.compile(r"\bchar\s*\(\s*\d", re.IGNORECASE)),
    ("concat_function", 2, re.compile(r"\bconcat\s*\(", re.IGNORECASE)),
    ("sqli_keywords_cluster", 3, re.compile(r"\b(select|union|insert|update|delete|drop)\b.{0,40}\b(from|where)\b", re.IGNORECASE)),
]


def _normalize_payload(text: str) -> str:
    """
    Normalize input to improve detection on URL-encoded query strings and logs.
    - URL-decode (plus-to-space) to surface hidden keywords
    - Lowercase
    - Collapse whitespace
    """
    raw = (text or "").strip()
    if not raw:
        return ""
    decoded = unquote_plus(raw)
    decoded = decoded.replace("\x00", " ")
    decoded = decoded.lower()
    decoded = re.sub(r"\s+", " ", decoded)
    return decoded


def scan_sql_injection(text: str) -> dict[str, Any]:
    raw = text or ""
    norm = _normalize_payload(raw)
    hits: list[dict[str, str]] = []
    score = 0
    for name, weight, rx in _SQLI_PATTERNS:
        m = rx.search(norm)
        if m:
            snippet = m.group(0)
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            hits.append({"id": name, "match": snippet, "weight": str(weight)})
            score += weight

    # Extra query-string signal: lots of parameters + suspicious separators
    amp = norm.count("&")
    eq = norm.count("=")
    if amp >= 8 and eq >= 8:
        hits.append({"id": "many_query_params", "match": f"params≈{eq}", "weight": "1"})
        score += 1
    if "%27" in (raw or "").lower() or "%22" in (raw or "").lower():
        hits.append({"id": "encoded_quote", "match": "%27/%22", "weight": "1"})
        score += 1

    risk = "low"
    if score >= 8 or len(hits) >= 4:
        risk = "high"
    elif score >= 3 or len(hits) >= 1:
        risk = "medium"

    return {"risk": risk, "pattern_hits": hits, "hit_count": len(hits), "score": score}


# -----------------------------------------------------------------------------
# DoS / abuse-style patterns (log snippets, WAF messages)
# -----------------------------------------------------------------------------

_DOS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("rate_limit", re.compile(r"(?:429|too many requests|rate limit|throttl)", re.IGNORECASE)),
    ("syn_flood", re.compile(r"syn\s*flood|tcp\s*flood", re.IGNORECASE)),
    ("udp_flood", re.compile(r"udp\s*flood", re.IGNORECASE)),
    ("slowloris", re.compile(r"slowloris|slow\s*read", re.IGNORECASE)),
    ("volumetric", re.compile(r"volumetric|bps|packets per second|pps\b", re.IGNORECASE)),
    ("connection_exhaust", re.compile(r"connection (?:exhaust|limit|refused|reset)", re.IGNORECASE)),
    ("ddos_keyword", re.compile(r"\bddos\b|denial of service", re.IGNORECASE)),
]


_IPV4_LINE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


def scan_dos_patterns(text: str) -> dict[str, Any]:
    raw = text or ""
    norm = _normalize_payload(raw)
    hits: list[dict[str, str]] = []
    for name, rx in _DOS_PATTERNS:
        m = rx.search(norm)
        if m:
            snippet = m.group(0)
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            hits.append({"id": name, "match": snippet})

    # Query-style abuse signals
    query_len = len(norm)
    if query_len >= 2000:
        hits.append({"id": "very_long_payload", "match": f"len={query_len}"})
    param_count = norm.count("&") + 1 if ("=" in norm and "&" in norm) else 0
    if param_count and param_count >= 40:
        hits.append({"id": "param_flood", "match": f"params≈{param_count}"})
    if re.search(r"(.)\1{40,}", norm):
        hits.append({"id": "repeated_char_run", "match": "repeated-char-run"})
    if re.search(r"\b(or|and)\b\s+\d+\s*=\s*\d+", norm):
        # often co-occurs with SQLi; still useful as abusive query pattern in WAF logs
        hits.append({"id": "boolean_abuse_like", "match": "or/and N=N"})

    # Simple: many repeated IPs in pasted log lines may indicate a flood source
    ip_counts: dict[str, int] = {}
    for line in raw.splitlines():
        for ip in _IPV4_LINE.findall(line):
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    repeat_ips = sorted(
        ((ip, c) for ip, c in ip_counts.items() if c >= 5),
        key=lambda x: -x[1],
    )[:8]

    risk = "low"
    if len(hits) >= 2 or repeat_ips:
        risk = "medium"
    if len(hits) >= 4 or any(c >= 50 for _, c in repeat_ips):
        risk = "high"

    return {
        "risk": risk,
        "pattern_hits": hits,
        "hit_count": len(hits),
        "repeated_source_ips": [{"ip": ip, "lines": c} for ip, c in repeat_ips],
    }


# -----------------------------------------------------------------------------
# Bundled scans for views
# -----------------------------------------------------------------------------

@dataclass
class UrlScanBundle:
    url: str
    ml: dict[str, Any]
    dns: dict[str, Any]


def scan_url_with_ips(
    url: str,
    *,
    predict_url: Callable[..., Any],
    threshold: float,
) -> UrlScanBundle:
    safe_url, meta = validate_and_normalize_scan_url(url)
    pred = predict_url(safe_url, threshold=threshold)
    dns = resolve_url_ips(safe_url)
    heur = url_heuristics(safe_url, url_meta=meta)

    # "Overlay" verdict: keep the ML score, but allow strong heuristics to flag.
    effective_score = float(max(pred.score, heur["score"]))
    effective_verdict = pred.verdict
    effective_type = pred.threat_type
    if effective_verdict != "threat" and heur["risk"] == "high":
        effective_verdict = "threat"
        effective_type = "phishing_heuristic"
    domain = assess_domain_trust(safe_url)
    ml = {
        "verdict": effective_verdict,
        "threat_type": effective_type,
        "score": effective_score,
        "scores": pred.scores,
        "model": pred.model,
        "heuristics": heur,
        "domain_trust": domain,
    }
    # Domain policy from predict_url is authoritative; align bundle verdict.
    if pred.verdict == "threat":
        ml["verdict"] = "threat"
        ml["threat_type"] = pred.threat_type
        ml["score"] = pred.score
    return UrlScanBundle(url=safe_url, ml=ml, dns=dns)


def _email_href_display_mismatch(body: str) -> list[dict[str, str]]:
    """Detect visible link text pointing to a different domain than shown."""
    mismatches: list[dict[str, str]] = []
    for m in re.finditer(
        r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]{3,120})</a>',
        body,
        re.I,
    ):
        href, visible = m.group(1), re.sub(r"\s+", " ", m.group(2)).strip()
        if not href.startswith(("http://", "https://")):
            continue
        href_host = registrable_domain((urlparse(href).hostname or "").lower())
        vis_host = ""
        if visible.startswith(("http://", "https://", "www.")):
            vis_host = registrable_domain((urlparse(normalize_url(visible)).hostname or "").lower())
        if href_host and vis_host and href_host != vis_host:
            mismatches.append({"visible": visible[:80], "actual": href_host})
    return mismatches[:8]


def scan_email_bundle(
    body: str,
    *,
    predict_url: Callable[..., Any],
    threshold: float,
) -> dict[str, Any]:
    signals = scan_email_phishing_signals(body)
    urls = extract_urls(body)
    url_results: list[dict[str, Any]] = []
    worst = "safe"
    worst_score = 0.0
    domain_judgments: list[dict[str, Any]] = []

    for u in urls:
        pred = predict_url(u, threshold=threshold)
        dns = resolve_url_ips(u)
        domain = assess_domain_trust(u)
        entry = {
            "url": u,
            "verdict": pred.verdict,
            "threat_type": pred.threat_type,
            "score": pred.score,
            "scores": pred.scores,
            "dns": dns,
            "domain_trust": domain,
        }
        url_results.append(entry)
        domain_judgments.append({
            "host": domain.get("host"),
            "trust": domain.get("trust"),
            "message": domain.get("message"),
        })
        if pred.verdict == "threat":
            if pred.score >= worst_score:
                worst_score = pred.score
                worst = pred.threat_type or "threat"
        elif domain.get("trust") in ("impersonation", "forwarded_risk", "unknown"):
            if worst == "safe":
                worst = domain.get("trust") if domain.get("trust") != "unknown" else "unverified_domain"
            worst_score = max(worst_score, 0.6)

    href_mismatches = _email_href_display_mismatch(body)
    forwarded_phrase = bool(
        re.search(r"\b(?:forwarded|fwd|forwarding)\b", body, re.I)
    )

    keyword_alert = signals["suspicious_phrase_hits"] >= 2 or signals["idn_punycode_hint"]
    if keyword_alert and worst == "safe":
        worst = "phishing_heuristic"
    if href_mismatches and worst == "safe":
        worst = "link_mismatch"
    if forwarded_phrase and any(d.get("trust") != "official" for d in domain_judgments):
        worst = worst if worst != "safe" else "forwarded_untrusted"

    trusted_domains = [d for d in domain_judgments if d.get("trust") == "official"]
    untrusted_domains = [d for d in domain_judgments if d.get("trust") != "official"]

    message_verdict = "safe"
    message_note = "No links in message, or all linked domains are verified official sites."
    if not urls:
        message_note = "Paste includes no http(s) links — check sender address separately."
        message_verdict = "unknown"
    elif untrusted_domains:
        message_verdict = "threat"
        message_note = (
            "Message links include domains that are not verified official sites. "
            "Forwarded emails are not trustworthy based on the sender name alone."
        )
    elif forwarded_phrase:
        message_verdict = "suspicious"
        message_note = "Forwarded message — confirm the destination domain before clicking."

    return {
        "kind": "email",
        "phishing_signals": signals,
        "urls": url_results,
        "domain_judgments": domain_judgments,
        "href_mismatches": href_mismatches,
        "forwarded_detected": forwarded_phrase,
        "message_domain_verdict": message_verdict,
        "message_domain_note": message_note,
        "summary_threat": worst if worst != "safe" or keyword_alert else "safe",
        "keyword_alert": keyword_alert,
    }


def scan_data_bundle(payload: str) -> dict[str, Any]:
    sqli = scan_sql_injection(payload)
    dos = scan_dos_patterns(payload)
    # Pick a single label for history rows
    label = "safe"
    if sqli["risk"] == "high" or dos["risk"] == "high":
        if sqli["risk"] == "high" and dos["risk"] != "high":
            label = "sql_injection"
        elif dos["risk"] == "high" and sqli["risk"] != "high":
            label = "ddos"
        else:
            label = "mixed_payload"
    elif sqli["risk"] == "medium" or dos["risk"] == "medium":
        label = "suspicious_payload"

    return {"kind": "data", "sql_injection": sqli, "dos": dos, "summary_threat": label}


def summarize_for_storage(bundle: dict[str, Any]) -> str:
    """Short result string for ScanResult.result."""
    msg_verdict = bundle.get("message_domain_verdict")
    if msg_verdict == "threat":
        return "phishing_domain"
    if msg_verdict == "suspicious":
        return "suspicious_forwarded"
    st = bundle.get("summary_threat") or "unknown"
    if st == "safe":
        return "safe"
    return st
