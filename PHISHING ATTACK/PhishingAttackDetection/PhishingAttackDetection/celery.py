import os
from celery import Celery
from celery.schedules import crontab

# Set default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PhishingAttackDetection.settings')

app = Celery('PhishingAttackDetection')

# Load configuration from Django settings with CELERY_ prefix
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all registered Django apps
app.autodiscover_tasks()

# Celery Beat Schedule - Periodic Tasks
app.conf.beat_schedule = {
    'purge-dummy-data-daily': {
        'task': 'AttackApp.tasks.purge_dummy_data_task',
        'schedule': crontab(hour=2, minute=0),  # Run daily at 2 AM
    },
    'health-check-every-5-minutes': {
        'task': 'AttackApp.tasks.system_health_check',
        'schedule': 300.0,  # Every 5 minutes
    },
    'cleanup-old-logs-weekly': {
        'task': 'AttackApp.tasks.cleanup_old_logs',
        'schedule': crontab(day_of_week=0, hour=3, minute=0),  # Weekly on Sunday at 3 AM
    },
}

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
