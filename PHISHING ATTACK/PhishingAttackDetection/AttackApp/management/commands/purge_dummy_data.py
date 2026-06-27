from __future__ import annotations

from django.core.management.base import BaseCommand
from django.db import transaction


class Command(BaseCommand):
    help = "Remove seeded demo/dummy rows created by earlier versions of the app."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print counts but do not delete anything.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        from AttackApp.models import (
            ActiveUser,
            BlockedAttack,
            LoginLog,
            RecentActivity,
            SystemHealth,
            ThreatDetected,
            ThreatLevel,
        )

        dry_run = bool(options.get("dry_run"))

        # Clear, high-confidence dummy marker: seeded ThreatDetected rows used wazuh_alert_id = "DUMMY-XXXX".
        dummy_threats_qs = ThreatDetected.objects.filter(wazuh_alert_id__startswith="DUMMY-")

        # Seeded data used specific fixed sets; keep deletions conservative by matching the exact tuples.
        seeded_ips = {
            "192.168.1.45",
            "10.0.0.22",
            "45.33.32.156",
            "192.168.1.8",
            "203.0.113.42",
            "198.51.100.7",
            "172.16.0.99",
            "192.168.2.10",
            "192.168.1.1",
        }
        seeded_login_tuples = {
            ("admin", "192.168.1.1", "safe"),
            ("john_doe", "10.0.0.22", "safe"),
            ("unknown", "45.33.32.156", "blocked"),
            ("jane_doe", "192.168.1.8", "review"),
        }
        seeded_activity_tuples = {
            ("phishing", "Phishing attempt blocked from 192.168.1.45", "blocked", "192.168.1.45", None),
            ("login", "User login successful — admin@cybervault.io", "successful", "192.168.1.1", "admin"),
            ("url_flag", "Suspicious URL flagged in email scan", "flagged", None, None),
            ("scan", "System scan completed — 0 vulnerabilities", "completed", None, None),
            ("brute_force", "Brute force attempt detected and blocked", "blocked", "45.33.32.156", None),
        }

        # Build querysets for other seeded rows using exact-field matches where possible.
        seeded_logins_qs = LoginLog.objects.none()
        for username, ip, status in seeded_login_tuples:
            seeded_logins_qs = seeded_logins_qs | LoginLog.objects.filter(
                username=username, ip_address=ip, status=status
            )

        seeded_activities_qs = RecentActivity.objects.none()
        for atype, desc, status, ip, user in seeded_activity_tuples:
            seeded_activities_qs = seeded_activities_qs | RecentActivity.objects.filter(
                activity_type=atype,
                description=desc,
                status=status,
                source_ip=ip,
                user=user,
            )

        seeded_active_users_qs = ActiveUser.objects.filter(
            username__in=["admin", "john_doe"], ip_address__in=["192.168.1.1", "10.0.0.22"]
        )

        seeded_health_qs = SystemHealth.objects.filter(
            cpu_usage=32.5,
            memory_usage=48.2,
            disk_usage=61.0,
            health_percentage=94.0,
            status="Optimal",
            wazuh_agents_connected=5,
        )

        dummy_blocked_attacks_qs = BlockedAttack.objects.filter(
            threat__in=dummy_threats_qs
        )

        counts = {
            "threat_detected_dummy": dummy_threats_qs.count(),
            "blocked_attack_linked_to_dummy": dummy_blocked_attacks_qs.count(),
            "recent_activity_seeded": seeded_activities_qs.count(),
            "login_log_seeded": seeded_logins_qs.count(),
            "active_user_seeded": seeded_active_users_qs.count(),
            "system_health_seeded": seeded_health_qs.count(),
            "threat_level_all": ThreatLevel.objects.count(),
        }

        self.stdout.write("Dummy purge candidates:")
        for k, v in counts.items():
            self.stdout.write(f" - {k}: {v}")

        if dry_run:
            self.stdout.write(self.style.WARNING("Dry-run enabled; no deletions performed."))
            return

        # Delete in an order that avoids leaving obvious orphaned demo rows behind.
        deleted_blocked = dummy_blocked_attacks_qs.delete()[0]
        deleted_threats = dummy_threats_qs.delete()[0]
        deleted_activities = seeded_activities_qs.delete()[0]
        deleted_logins = seeded_logins_qs.delete()[0]
        deleted_active = seeded_active_users_qs.delete()[0]
        deleted_health = seeded_health_qs.delete()[0]

        # ThreatLevel is derived; rebuild from remaining real data elsewhere if needed.
        deleted_levels = ThreatLevel.objects.all().delete()[0]

        self.stdout.write(self.style.SUCCESS("Dummy data purge complete:"))
        self.stdout.write(f" - BlockedAttack deleted: {deleted_blocked}")
        self.stdout.write(f" - ThreatDetected deleted: {deleted_threats}")
        self.stdout.write(f" - RecentActivity deleted: {deleted_activities}")
        self.stdout.write(f" - LoginLog deleted: {deleted_logins}")
        self.stdout.write(f" - ActiveUser deleted: {deleted_active}")
        self.stdout.write(f" - SystemHealth deleted: {deleted_health}")
        self.stdout.write(f" - ThreatLevel deleted (will recompute): {deleted_levels}")

