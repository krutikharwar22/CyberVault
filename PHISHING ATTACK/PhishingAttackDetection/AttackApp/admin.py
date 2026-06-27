from django.contrib import admin
from .models import (
    ThreatDetected, BlockedAttack, BlockedIPAddress, ActiveUser,
    SystemHealth, RecentActivity, LoginLog,
    ThreatLevel, WazuhSyncLog,
)
from django.contrib import admin
from .models import ScanResult, Log, UserSettings


@admin.register(ThreatDetected)
class ThreatDetectedAdmin(admin.ModelAdmin):
    list_display    = ('threat_type', 'severity', 'source_ip', 'blocked', 'detected_at')
    list_filter     = ('threat_type', 'severity', 'blocked')
    search_fields   = ('source_ip', 'description')
    ordering        = ('-detected_at',)


@admin.register(BlockedAttack)
class BlockedAttackAdmin(admin.ModelAdmin):
    list_display  = ('attack_vector', 'source_ip', 'agent_name', 'blocked_at')
    list_filter   = ('attack_vector',)
    ordering      = ('-blocked_at',)


@admin.register(ActiveUser)
class ActiveUserAdmin(admin.ModelAdmin):
    list_display  = ('username', 'ip_address', 'is_active', 'login_time')
    list_filter   = ('is_active',)


@admin.register(SystemHealth)
class SystemHealthAdmin(admin.ModelAdmin):
    list_display = ('health_percentage', 'status', 'cpu_usage', 'memory_usage', 'recorded_at')
    ordering     = ('-recorded_at',)


@admin.register(BlockedIPAddress)
class BlockedIPAddressAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "blocked_by", "created_at")
    ordering = ("-created_at",)


@admin.register(RecentActivity)
class RecentActivityAdmin(admin.ModelAdmin):
    list_display  = ('activity_type', 'status', 'source_ip', 'user', 'timestamp')
    list_filter   = ('activity_type', 'status')
    ordering      = ('-timestamp',)


@admin.register(LoginLog)
class LoginLogAdmin(admin.ModelAdmin):
    list_display  = ('username', 'ip_address', 'status', 'login_time')
    list_filter   = ('status',)
    ordering      = ('-login_time',)


@admin.register(ThreatLevel)
class ThreatLevelAdmin(admin.ModelAdmin):
    list_display = ('threat_type', 'percentage', 'color', 'updated_at')


@admin.register(WazuhSyncLog)
class WazuhSyncLogAdmin(admin.ModelAdmin):
    list_display = ('synced_at', 'alerts_fetched', 'success', 'duration_seconds')
    list_filter  = ('success',)

    

admin.site.register(ScanResult)
admin.site.register(Log)
admin.site.register(UserSettings)

#new#
"""
threat_detection/admin.py
"""
from django.contrib import admin
from django.utils.html import format_html



