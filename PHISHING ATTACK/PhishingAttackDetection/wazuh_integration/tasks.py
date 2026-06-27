# cybervault/tasks.py
"""
Celery beat tasks — run in background without blocking HTTP requests.

Install:
    pip install celery django-celery-beat redis

In settings.py add:
    INSTALLED_APPS += ["django_celery_beat"]
    CELERY_BROKER_URL = "redis://localhost:6379/0"
    CELERY_BEAT_SCHEDULE = {
        "sync-wazuh-every-minute": {
            "task": "cybervault.tasks.sync_wazuh",
            "schedule": 60.0,          # every 60 seconds
        },
        "update-system-health-every-5m": {
            "task": "cybervault.tasks.update_system_health",
            "schedule": 300.0,
        },
        "update-active-users-every-minute": {
 ""task": "cybervault.tasks.update_active_users",
            "schedule": 60.0,
        },
    }

Start workers:
    celery -A your_project worker -l info
    celery -A your_project beat   -l inf
"""

import logging
import psutil
from celery import shared_task
from django.contrib.sessions.models import Session
from django.contrib.auth import get_user_model
from django.utils import timezone

from AttackApp.models import ActiveUser, SystemHealth, WazuhSyncLog
from AttackApp.views import _sync_wazuh_alerts, _recompute_threat_levels
from wazuh_integration import wazuh_client

logger = logging.getLogger(__name__)
User = get_user_model()


@shared_task(
        bind=True, max_retries=3, default_retry_delay=10 )
def sync_wazuh(self):
    """Pull the latest Wazuh alerts and update all derived aggregates."""
    try:
        inserted = _sync_wazuh_alerts(hours_back=1)
        _recompute_threat_levels()
        logger.info("Wazuh sync: %d new alerts", inserted)
        return {"inserted": inserted}
    except Exception as exc:
        logger.error("sync_wazuh task failed: %s", exc)
        raise self.retry(exc=exc)


@shared_task
def update_system_health():
    """
    Sample local machine metrics + Wazuh agent count and store a health snapshot.
    In production point this at your Wazuh manager host metrics instead.
    """
    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent

        # Simple weighted health score (lower resource usage = better)
        score = round(100 - (cpu * 0.4 + mem * 0.3 + disk * 0.3), 1)
        score = max(0.0, min(100.0, score))

        if score >= 90:
            status = "Optimal"
        elif score >= 70:
            status = "Good"
        elif score >= 50:
            status = "Degraded"
        else:
            status = "Critical"

        agents_connected = wazuh_client.get_active_agents_count()

        SystemHealth.objects.create(
            cpu_usage=cpu,
            memory_usage=mem,
            disk_usage=disk,
            health_percentage=score,
            status=status,
            wazuh_agents_connected=agents_connected,
        )
        logger.info("System health recorded: %.1f%% (%s)", score, status)
    except Exception as exc:
        logger.error("update_system_health error: %s", exc)


@shared_task
def update_active_users():
    """
    Mark users as inactive if their Django session has expired.
    Adds new active users from live sessions.
    """
    try:
        now = timezone.now()
        active_sessions = Session.objects.filter(expire_date__gte=now)
        active_user_ids = set()

        for session in active_sessions:
            data = session.get_decoded()
            uid = data.get("_auth_user_id")
            if uid:
                active_user_ids.add(int(uid))

        # Deactivate users no longer in sessions
        ActiveUser.objects.exclude(
            username__in=User.objects.filter(id__in=active_user_ids).values_list("username", flat=True)
        ).update(is_active=False)

        logger.info("Active users refreshed: %d online", len(active_user_ids))
    except Exception as exc:
        logger.error("update_active_users error: %s", exc)