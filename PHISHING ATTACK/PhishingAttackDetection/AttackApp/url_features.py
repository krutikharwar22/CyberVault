import math
import re
from urllib.parse import urlsplit, unquote

import numpy as np


_SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "password",
    "bank",
    "billing",
    "invoice",
    "payment",
    "support",
    "confirm",
    "reset",
    "webscr",
    "wp-admin",
)


_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return float(ent)


def extract_url_features(url: str) -> np.ndarray:
    """
    Returns 22 numeric URL-only features (float32) suitable for the models in `trianer.py`.
    The exact scales don't need to match any external dataset; they just need to be
    consistent between training and inference.
    """
    raw = (url or "").strip()
    if not raw:
        return np.zeros((22,), dtype=np.float32)

    if "://" not in raw:
        raw = "http://" + raw

    parts = urlsplit(raw)
    scheme = (parts.scheme or "").lower()
    netloc = (parts.netloc or "").lower()
    path = parts.path or ""
    query = parts.query or ""
    fragment = parts.fragment or ""

    host = netloc.split("@")[-1].split(":")[0]
    decoded_path = unquote(path)
    decoded_query = unquote(query)

    url_len = len(raw)
    host_len = len(host)
    path_len = len(path)
    query_len = len(query)

    dots = host.count(".")
    subdomains = max(dots - 1, 0)
    has_ip = 1.0 if _IPV4_RE.match(host or "") else 0.0

    digit_count = sum(ch.isdigit() for ch in raw)
    alpha_count = sum(ch.isalpha() for ch in raw)
    special_count = max(url_len - digit_count - alpha_count, 0)

    at_count = raw.count("@")
    dash_count = raw.count("-")
    underscore_count = raw.count("_")
    percent_count = raw.count("%")
    eq_count = raw.count("=")
    amp_count = raw.count("&")

    https = 1.0 if scheme == "https" else 0.0

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    tld_len = len(tld)

    keyword_hits = 0
    lowered = raw.lower()
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in lowered:
            keyword_hits += 1

    # A cheap "token" count: split on common delimiters
    tokens = [t for t in re.split(r"[/\.\-\_\?\=\&\:\#]+", lowered) if t]
    token_count = len(tokens)

    # Entropy over host+path+query tends to go up for random-looking URLs.
    entropy = _shannon_entropy((host + decoded_path + decoded_query)[:512])

    digit_ratio = (digit_count / url_len) if url_len else 0.0

    feats = np.array(
        [
            url_len,          # 0
            host_len,         # 1
            path_len,         # 2
            query_len,        # 3
            digit_count,      # 4
            special_count,    # 5
            subdomains,       # 6
            at_count,         # 7
            https,            # 8
            eq_count,         # 9
            amp_count,        # 10
            dash_count,       # 11
            underscore_count, # 12
            has_ip,           # 13
            keyword_hits,     # 14
            (1.0 if fragment else 0.0),  # 15
            percent_count,    # 16
            dots,             # 17
            float(token_count),  # 18
            float(tld_len),      # 19
            float(entropy),      # 20
            float(digit_ratio),  # 21
        ],
        dtype=np.float32,
    )
    return feats

