"""
threat_detection/models.py

Threat logging models for database persistence.
"""
from django.db import models


class ThreatLog(models.Model):
    """Log of detected threats."""
    
    threat_type = models.CharField(max_length=50)
    confidence = models.FloatField(default=0.0)
    severity = models.CharField(max_length=20, default='low')
    source_ip = models.CharField(max_length=45)
    url = models.CharField(max_length=2000)
    method = models.CharField(max_length=10, default='GET')
    user_agent = models.CharField(max_length=512, blank=True)
    path = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'threat_logs'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.threat_type} - {self.source_ip} ({self.created_at})"
