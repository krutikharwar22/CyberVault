# cybervault/models.py
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils import timezone
from django.contrib.auth import get_user_model
import random

class ThreatDetected(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    THREAT_TYPE_CHOICES = [
        ('phishing', 'Phishing'),
        ('malware', 'Malware'),
        ('brute_force', 'Brute Force'),
        ('sql_injection', 'SQL Injection'),
        ('ddos', 'DDoS'),
        ('other', 'Other'),
    ]

    wazuh_alert_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    threat_type    = models.CharField(max_length=50, choices=THREAT_TYPE_CHOICES, default='other')
    severity       = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='low')
    source_ip      = models.GenericIPAddressField(null=True, blank=True)
    description    = models.TextField()
    blocked        = models.BooleanField(default=False)
    detected_at    = models.DateTimeField(default=timezone.now)
    raw_data       = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-detected_at']

    def __str__(self):
        return f"[{self.threat_type}] {self.description[:60]}"


class BlockedAttack(models.Model):
    threat       = models.ForeignKey(ThreatDetected, on_delete=models.SET_NULL, null=True, blank=True)
    source_ip    = models.GenericIPAddressField(null=True, blank=True)
    attack_vector = models.CharField(max_length=100)
    blocked_at   = models.DateTimeField(default=timezone.now)
    rule_id      = models.CharField(max_length=50, null=True, blank=True)
    agent_name   = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        ordering = ['-blocked_at']

    def __str__(self):
        return f"Blocked {self.attack_vector} from {self.source_ip}"


class ActiveUser(models.Model):
    username    = models.CharField(max_length=150)
    ip_address  = models.GenericIPAddressField()
    login_time  = models.DateTimeField(default=timezone.now)
    last_seen   = models.DateTimeField(auto_now=True)
    session_key = models.CharField(max_length=40, null=True, blank=True)
    is_active   = models.BooleanField(default=True)

    class Meta:
        ordering = ['-login_time']

    def __str__(self):
        return f"{self.username} ({self.ip_address})"


class SystemHealth(models.Model):
    cpu_usage              = models.FloatField(default=0.0)
    memory_usage           = models.FloatField(default=0.0)
    disk_usage             = models.FloatField(default=0.0)
    health_percentage      = models.FloatField(default=100.0)
    status                 = models.CharField(max_length=50, default='Optimal')
    recorded_at            = models.DateTimeField(auto_now_add=True)
    wazuh_agents_connected = models.IntegerField(default=0)

    class Meta:
        ordering = ['-recorded_at']
        get_latest_by = 'recorded_at'

    def __str__(self):
        return f"Health {self.health_percentage}% @ {self.recorded_at}"


class RecentActivity(models.Model):
    ACTIVITY_TYPE_CHOICES = [
        ('phishing',   'Phishing'),
        ('login',      'Login'),
        ('url_flag',   'Suspicious URL'),
        ('scan',       'System Scan'),
        ('brute_force','Brute Force'),
        ('other',      'Other'),
    ]
    STATUS_CHOICES = [
        ('blocked',    'Blocked'),
        ('successful', 'Successful'),
        ('flagged',    'Flagged'),
        ('completed',  'Completed'),
        ('detected',   'Detected'),
    ]

    activity_type  = models.CharField(max_length=50, choices=ACTIVITY_TYPE_CHOICES)
    description    = models.TextField()
    status         = models.CharField(max_length=20, choices=STATUS_CHOICES)
    source_ip      = models.GenericIPAddressField(null=True, blank=True)
    user           = models.CharField(max_length=150, null=True, blank=True)
    timestamp      = models.DateTimeField(default=timezone.now)
    wazuh_rule_id  = models.CharField(max_length=50, null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def time_ago(self):
        delta = timezone.now() - self.timestamp
        minutes = int(delta.total_seconds() / 60)
        if minutes < 60:
            return f"{minutes}m ago"
        hours = minutes // 60
        return f"{hours}h ago"

    def __str__(self):
        return f"[{self.activity_type}] {self.description[:60]}"


class LoginLog(models.Model):
    STATUS_CHOICES = [
        ('safe',    'Safe'),
        ('blocked', 'Blocked'),
        ('review',  'Review'),
    ]

    username     = models.CharField(max_length=150)
    ip_address   = models.GenericIPAddressField()
    login_time   = models.DateTimeField(default=timezone.now)
    status       = models.CharField(max_length=20, choices=STATUS_CHOICES, default='safe')
    wazuh_agent  = models.CharField(max_length=100, null=True, blank=True)
    location     = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        ordering = ['-login_time']

    def __str__(self):
        return f"{self.username} from {self.ip_address} [{self.status}]"


class ThreatLevel(models.Model):
    threat_type = models.CharField(max_length=50, unique=True)
    percentage  = models.FloatField(default=0.0)
    color       = models.CharField(max_length=20, default='#00ffcc')
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-percentage']

    def __str__(self):
        return f"{self.threat_type}: {self.percentage}%"


class ScanResult(models.Model):
    # Target line: full URL, or a short label for email/data scans (was URLField for URL-only scans).
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="scan_results",
    )
    url = models.CharField(max_length=2048)
    result = models.CharField(max_length=100)
    scan_kind = models.CharField(max_length=16, default="url")  # url | email | data
    detail = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url[:120]


class Log(models.Model):
    action = models.CharField(max_length=200)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.action

class WazuhSyncLog(models.Model):
    synced_at        = models.DateTimeField(auto_now_add=True)
    alerts_fetched   = models.IntegerField(default=0)
    success          = models.BooleanField(default=True)
    error_message    = models.TextField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)

    class Meta:
        ordering = ['-synced_at']

    def __str__(self):
        return f"Sync @ {self.synced_at} — {'OK' if self.success else 'FAILED'}"
    
    
class UserNotificationState(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notification_state",
    )
    last_seen_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"NotificationState for {self.user}"



class BlockedIPAddress(models.Model):
    """IPs blocked by staff; enforced by BlockedIPMiddleware."""

    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=500, blank=True)
    blocked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="ips_blocked",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Blocked IP address"
        verbose_name_plural = "Blocked IP addresses"

    def __str__(self):
        return str(self.ip_address)


class UserSettings(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="attack_settings")

    # Dashboard
    dashboard_refresh_seconds = models.PositiveIntegerField(default=30)
    show_scan_scores = models.BooleanField(default=True)

    # URL detection behavior
    url_threat_threshold = models.FloatField(default=0.5)

    # History / UI
    history_page_size = models.PositiveIntegerField(default=200)
    truncate_urls_in_tables = models.BooleanField(default=True)

    # Logging / UX
    log_scan_to_recent_activity = models.BooleanField(default=True)

    # Notifications (placeholder toggles; wiring to email/SMS can come later)
    enable_notifications = models.BooleanField(default=True)
    email_alerts_on_threat = models.BooleanField(default=False)
    alert_email = models.EmailField(blank=True, default="")

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "User Settings"
        verbose_name_plural = "User Settings"

    def __str__(self):
        return f"Settings for {self.user}"
    


class PasswordResetOTP(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='reset_otps')
    otp = models.CharField(max_length=5)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def is_valid(self):
        """OTP is valid if created within 2 minutes and not used."""
        expiry = self.created_at + timezone.timedelta(minutes=2)
        return not self.is_used and timezone.now() <= expiry

    @classmethod
    def generate_for(cls, user):
        """Delete old OTPs and create a new one."""
        cls.objects.filter(user=user).delete()
        otp = str(random.randint(10000, 99999))
        return cls.objects.create(user=user, otp=otp)

    def __str__(self):
        return f"OTP for {self.user.username}"