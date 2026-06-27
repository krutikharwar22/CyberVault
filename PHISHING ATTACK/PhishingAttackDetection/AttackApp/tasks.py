from celery import shared_task
from django.utils import timezone
from .models import LoginLog, ScanResult, SystemHealth, RecentActivity
import logging

logger = logging.getLogger(__name__)

# ===== Background Tasks =====

@shared_task(bind=True, max_retries=3)
def purge_dummy_data_task(self):
    """
    Purge old/dummy data from the database.
    Runs daily at 2 AM (configurable in celery.py)
    """
    try:
        # Delete login logs older than 30 days
        thirty_days_ago = timezone.now() - timezone.timedelta(days=30)
        deleted_logs, _ = LoginLog.objects.filter(timestamp__lt=thirty_days_ago).delete()
        
        # Delete scan results older than 90 days
        ninety_days_ago = timezone.now() - timezone.timedelta(days=90)
        deleted_scans, _ = ScanResult.objects.filter(timestamp__lt=ninety_days_ago).delete()
        
        logger.info(f'Purged {deleted_logs} login logs and {deleted_scans} scan results')
        return f'Successfully purged data: {deleted_logs} logs, {deleted_scans} scans'
    except Exception as exc:
        logger.error(f'Error purging data: {exc}')
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True)
def system_health_check(self):
    """
    Perform system health check.
    Runs every 5 minutes (configurable in celery.py)
    """
    try:
        from django.db import connection
        from django.core.cache import cache
        import psutil
        
        # Check database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Create or update health record
        health_data = {
            'database_status': 'healthy',
            'cpu_usage': cpu_percent,
            'memory_usage': memory.percent,
            'disk_usage': disk.percent,
            'status': 'healthy' if cpu_percent < 80 and memory.percent < 80 else 'warning'
        }
        
        # Store in cache for quick access
        cache.set('system_health', health_data, 300)  # 5 minutes
        
        logger.info(f'Health check: CPU={cpu_percent}%, Memory={memory.percent}%, Disk={disk.percent}%')
        return health_data
    except Exception as exc:
        logger.error(f'Error during health check: {exc}')
        return {'status': 'error', 'error': str(exc)}


@shared_task(bind=True, max_retries=3)
def cleanup_old_logs(self):
    """
    Clean up old activity logs and system health records.
    Runs weekly on Sunday at 3 AM (configurable in celery.py)
    """
    try:
        # Delete activity logs older than 60 days
        sixty_days_ago = timezone.now() - timezone.timedelta(days=60)
        deleted_activity, _ = RecentActivity.objects.filter(timestamp__lt=sixty_days_ago).delete()
        
        # Delete old system health records
        deleted_health, _ = SystemHealth.objects.filter(timestamp__lt=sixty_days_ago).delete()
        
        logger.info(f'Cleaned up {deleted_activity} activity logs and {deleted_health} health records')
        return f'Cleanup complete: {deleted_activity} activities, {deleted_health} health records'
    except Exception as exc:
        logger.error(f'Error cleaning up logs: {exc}')
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def scan_url_async(self, url, user_id=None):
    """
    Perform URL security scan asynchronously.
    Call this from views to avoid blocking the request.
    
    Example:
        from AttackApp.tasks import scan_url_async
        scan_url_async.delay(url='https://example.com', user_id=1)
    """
    try:
        from .security_scanner import URLSecurityScanner
        from .models import ScanResult, User
        from django.contrib.auth import get_user_model
        
        User = get_user_model()
        scanner = URLSecurityScanner()
        
        # Perform the scan
        scan_result = scanner.scan(url)
        
        # Save to database
        result = ScanResult.objects.create(
            url=url,
            is_phishing=scan_result.get('is_phishing', False),
            confidence=scan_result.get('confidence', 0.0),
            details=scan_result.get('details', {}),
            kind_detail=scan_result.get('kind', 'unknown'),
            user_id=user_id
        )
        
        logger.info(f'Completed async scan for {url} - Result ID: {result.id}')
        return {
            'scan_id': result.id,
            'url': url,
            'is_phishing': result.is_phishing,
            'confidence': float(result.confidence)
        }
    except Exception as exc:
        logger.error(f'Error during async scan: {exc}')
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def train_ml_model_async(self, model_type='url_classifier'):
    """
    Train ML model asynchronously in the background.
    Prevents blocking the Django server during long training jobs.
    
    Example:
        from AttackApp.tasks import train_ml_model_async
        train_ml_model_async.delay(model_type='url_classifier')
    """
    try:
        from .trianer import URLModelTrainer
        import datetime
        
        logger.info(f'Starting async training for {model_type} model')
        
        trainer = URLModelTrainer()
        result = trainer.train_and_save()
        
        logger.info(f'Completed async training for {model_type} - Result: {result}')
        return {
            'model_type': model_type,
            'status': 'completed',
            'timestamp': str(datetime.datetime.now()),
            'result': result
        }
    except Exception as exc:
        logger.error(f'Error during async model training: {exc}')
        raise self.retry(exc=exc, countdown=300 * (2 ** self.request.retries))


@shared_task
def log_user_activity(user_id, activity_type, description, ip_address=None):
    """
    Log user activity asynchronously.
    
    Example:
        from AttackApp.tasks import log_user_activity
        log_user_activity.delay(user_id=1, activity_type='login', 
                               description='User logged in', ip_address='192.168.1.1')
    """
    try:
        from .models import RecentActivity
        from django.contrib.auth import get_user_model
        
        User = get_user_model()
        user = User.objects.get(id=user_id)
        
        RecentActivity.objects.create(
            user=user,
            activity_type=activity_type,
            description=description,
            ip_address=ip_address or 'N/A'
        )
        
        logger.info(f'Logged activity for user {user_id}: {activity_type}')
        return True
    except Exception as exc:
        logger.error(f'Error logging user activity: {exc}')
        return False
