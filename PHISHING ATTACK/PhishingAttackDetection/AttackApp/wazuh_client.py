# cybervault/wazuh_client.py
"""
Wazuh REST API client.
Docs: https://documentation.wazuh.com/current/user-manual/api/reference.html

Set these in your Django settings.py (or .env):
    WAZUH_HOST     = "https://your-wazuh-manager:55000"
    WAZUH_USER     = "wazuh-wui"          # API user
    WAZUH_PASSWORD = "your-api-password"
    WAZUH_VERIFY_SSL = False              # set True in production with valid cert
"""

import logging
import time
from datetime import datetime, timedelta

import requests
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

WAZUH_HOST = getattr(settings, "WAZUH_HOST", "https://localhost:55000")
WAZUH_USER = getattr(settings, "WAZUH_USER", "wazuh")
WAZUH_PASSWORD = getattr(settings, "WAZUH_PASSWORD", "wazuh")
WAZUH_VERIFY_SSL = getattr(settings, "WAZUH_VERIFY_SSL", False)


# --------------------------------------------------------------------------- #
#  Auth                                                                        #
# --------------------------------------------------------------------------- #

_token_cache: dict = {"token": None, "expires_at": 0}


def _get_token() -> str:
    """Return a cached JWT or fetch a fresh one."""
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"]:
        return _token_cache["token"]

    resp = requests.post(
        f"{WAZUH_HOST}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASSWORD),
        verify=WAZUH_VERIFY_SSL,
        timeout=10,
    )
    resp.raise_for_status()
    token = resp.json()["data"]["token"]
    # Wazuh tokens expire in 900 s; refresh after 800 s
    _token_cache.update({"token": token, "expires_at": now + 800})
    return token


def _headers() -> dict:
    return {"Authorization": f"Bearer {_get_token()}"}


# --------------------------------------------------------------------------- #
#  Public helpers                                                              #
# --------------------------------------------------------------------------- #

def get_alerts(limit: int = 100, offset: int = 0, hours_back: int = 24) -> list[dict]:
    """
    Fetch recent alerts from the Wazuh Indexer via the manager API.
    Returns a list of raw alert dicts.
    """
    since = (datetime.utcnow() - timedelta(hours=hours_back)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    params = {
        
        "limit": limit,
        "offset": offset,
        "sort": "-timestamp",
        "q": f"timestamp>{since}",
    }
    try:
        resp = requests.get(
            f"{WAZUH_HOST}/alerts",
            headers=_headers(),
            params=params,
            verify=WAZUH_VERIFY_SSL,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("affected_items", [])
    except Exception as exc:
        logger.error("Wazuh get_alerts error: %s", exc)
        return []


def get_agents() -> list[dict]:
    """Return all registered Wazuh agents."""
    try:
        resp = requests.get(
            f"{WAZUH_HOST}/agents",
            headers=_headers(),
            params={"limit": 500},
            verify=WAZUH_VERIFY_SSL,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("affected_items", [])
    except Exception as exc:
        logger.error("Wazuh get_agents error: %s", exc)
        return []


def get_total_alerts_count() -> int:
    """Quick count of all alerts (for the 'Threats Detected' KPI card)."""
    try:
        resp = requests.get(
            f"{WAZUH_HOST}/alerts",
            headers=_headers(),
            params={"limit": 1},
            verify=WAZUH_VERIFY_SSL,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("total_affected_items", 0)
    except Exception as exc:
        logger.error("Wazuh count error: %s", exc)
        return 0


def get_active_agents_count() -> int:
    """Count agents whose status == 'active'."""
    try:
        resp = requests.get(
            f"{WAZUH_HOST}/agents",
            headers=_headers(),
            params={"status": "active", "limit": 1},
            verify=WAZUH_VERIFY_SSL,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("total_affected_items", 0)
    except Exception as exc:
        logger.error("Wazuh active agents error: %s", exc)
        return 0


# --------------------------------------------------------------------------- #
#  Alert → Model mapping helpers                                               #
# --------------------------------------------------------------------------- #

THREAT_TYPE_MAP = {
    "phishing": "phishing",
    "malware": "malware",
    "brute": "brute_force",
    "sql": "sql_injection",
    "ddos": "ddos",
}


def classify_threat(alert: dict) -> str:
    """Guess a threat_type from Wazuh rule description."""
    desc = (alert.get("rule", {}).get("description", "") or "").lower()
    for keyword, ttype in THREAT_TYPE_MAP.items():
        if keyword in desc:
            return ttype
    return "other"


def alert_to_activity(alert: dict) -> dict:
    """Convert a raw Wazuh alert into kwargs for RecentActivity.create()."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    threat_type = classify_threat(alert)
    level = int(rule.get("level", 0))

    status_map = {
        "phishing": "blocked",
        "malware": "blocked",
        "brute_force": "blocked",
        "sql_injection": "flagged",
        "ddos": "blocked",
        "other": "detected",
    }

    return {
        "activity_type": threat_type,
        "description": rule.get("description", "Unknown activity"),
        "status": status_map.get(threat_type, "detected"),
        "source_ip": alert.get("data", {}).get("srcip"),
        "user": alert.get("data", {}).get("dstuser") or agent.get("name"),
        "wazuh_rule_id": str(rule.get("id", "")),
    }
