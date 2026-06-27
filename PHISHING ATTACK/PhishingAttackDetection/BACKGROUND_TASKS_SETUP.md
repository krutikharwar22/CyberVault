# Background Task Setup Guide

This guide explains how to run your Phishing Attack Detection application with background task processing.

## Overview

The application now supports:
- **Async Background Tasks** - Long-running operations like ML model training and URL scanning
- **Scheduled Tasks** - Periodic operations like data cleanup and health checks
- **Background Services** - Run the entire application in the background

## Prerequisites

### 1. Install Redis (Message Broker)

Redis is required for Celery to work. Choose one method:

#### Option A: Using Chocolatey (Recommended)
```powershell
# Run PowerShell as Administrator
choco install redis-64
```

#### Option B: Manual Download
1. Download from: https://github.com/microsoftarchive/redis/releases
2. Extract and add to PATH or run directly

#### Option C: Using Windows Subsystem for Linux (WSL)
```bash
wsl
sudo apt-get install redis-server
redis-server
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- **Celery** - Async task processor
- **Redis** - Message broker and result backend
- **django-celery-beat** - Scheduler for periodic tasks
- **psutil** - System monitoring

## Running the Application

### Quick Start (All-in-One)

Run this single command to start all services in separate windows:

```bash
start_all_services.bat
```

This opens 4 windows:
1. Redis Server
2. Django Development Server (http://localhost:8000)
3. Celery Worker (processes async tasks)
4. Celery Beat (handles scheduled tasks)

### Individual Service Startup

If you prefer to start services separately:

#### 1. Start Redis
```bash
start_redis.bat
# or manually:
redis-server --port 6379
```

#### 2. Start Django Server
```bash
start_django.bat
# or manually:
python manage.py runserver 0.0.0.0:8000
```

#### 3. Start Celery Worker (in a new terminal)
```bash
start_celery_worker.bat
# or manually:
celery -A PhishingAttackDetection worker --loglevel=info --concurrency=4
```

#### 4. Start Celery Beat Scheduler (in another new terminal)
```bash
start_celery_beat.bat
# or manually:
celery -A PhishingAttackDetection beat --loglevel=info
```

## Scheduled Background Tasks

The following tasks run automatically on a schedule:

### 1. Purge Dummy Data
- **Schedule**: Daily at 2:00 AM
- **Action**: Deletes login logs older than 30 days and scans older than 90 days
- **Task**: `AttackApp.tasks.purge_dummy_data_task`

### 2. System Health Check
- **Schedule**: Every 5 minutes
- **Action**: Checks database, CPU, memory, and disk usage
- **Task**: `AttackApp.tasks.system_health_check`

### 3. Cleanup Old Logs
- **Schedule**: Weekly (Sunday at 3:00 AM)
- **Action**: Deletes activity logs and health records older than 60 days
- **Task**: `AttackApp.tasks.cleanup_old_logs`

## Using Background Tasks in Your Code

### Example 1: Async URL Scanning

Instead of blocking the user's request during a scan:

```python
# In your view
from AttackApp.tasks import scan_url_async

def scan_view(request):
    url = request.POST.get('url')
    
    # Send task to background worker (returns immediately)
    result = scan_url_async.delay(url=url, user_id=request.user.id)
    
    return JsonResponse({
        'task_id': result.id,
        'status': 'processing',
        'message': 'URL scan started in background'
    })
```

### Example 2: Async ML Model Training

Train models without blocking the server:

```python
from AttackApp.tasks import train_ml_model_async

# Start training in background
result = train_ml_model_async.delay(model_type='url_classifier')

# Get status
task_status = result.state  # 'PENDING', 'STARTED', 'SUCCESS', 'FAILURE'
task_result = result.result  # Returns result when done
```

### Example 3: Log User Activity

Log activities asynchronously:

```python
from AttackApp.tasks import log_user_activity

# Send to background worker
log_user_activity.delay(
    user_id=request.user.id,
    activity_type='login',
    description='User logged in',
    ip_address=request.META.get('REMOTE_ADDR')
)
```

### Example 4: Check Task Status

```python
from celery.result import AsyncResult

# Get task result
task_id = 'your-task-id'
result = AsyncResult(task_id)

if result.ready():
    print(f"Task result: {result.result}")
else:
    print(f"Task state: {result.state}")
```

## Monitoring Background Tasks

### View Active Tasks

```bash
# In a Python shell or management command
from AttackApp.tasks import app
inspect = app.control.inspect()
active_tasks = inspect.active()
```

### View Task Statistics

```bash
celery -A PhishingAttackDetection inspect stats
```

### View Registered Tasks

```bash
celery -A PhishingAttackDetection inspect registered
```

## Configuration Files

### Main Configuration Files Created/Modified:

1. **PhishingAttackDetection/celery.py** - Celery configuration and beat schedule
2. **PhishingAttackDetection/__init__.py** - Celery app initialization
3. **PhishingAttackDetection/settings.py** - Django Celery settings
4. **AttackApp/tasks.py** - Background task definitions

### Key Settings in settings.py:

```python
# Broker and Result Backend
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

# Task Configuration
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes hard limit
CELERY_TASK_SOFT_TIME_LIMIT = 25 * 60  # 25 minutes soft limit

# Concurrency
CELERY_WORKER_CONCURRENCY = 4  # Number of parallel workers
```

## Running as Windows Service (Production)

For production deployment as a Windows service, you have options:

### Option 1: NSSM (Non-Sucking Service Manager)

```bash
# Download from: https://nssm.cc/download
# Add to PATH

# Create service for Django
nssm install DjangoServer "C:\Python39\python.exe" "manage.py runserver"

# Create service for Celery Worker
nssm install CeleryWorker "C:\Python39\python.exe" -c "celery -A PhishingAttackDetection worker"

# Create service for Celery Beat
nssm install CeleryBeat "C:\Python39\python.exe" -c "celery -A PhishingAttackDetection beat"

# Start services
net start DjangoServer
net start CeleryWorker
net start CeleryBeat
```

### Option 2: Task Scheduler

Use Windows Task Scheduler to run the batch files on startup.

## Troubleshooting

### Redis Connection Error
```
Error: Connection to Redis failed
```
**Solution**: Make sure Redis is running. Run `start_redis.bat` first.

### Celery Worker Not Processing Tasks
```
Solution: Check if Celery worker is running. Run `start_celery_worker.bat`
```

### Tasks Not Scheduled
```
Solution: Ensure Celery Beat is running. Run `start_celery_beat.bat`
```

### Check Celery Logs

```bash
# View worker logs in real-time
celery -A PhishingAttackDetection worker --loglevel=debug

# View Celery Beat logs
celery -A PhishingAttackDetection beat --loglevel=debug
```

## Performance Tuning

### Increase Worker Concurrency
```bash
celery -A PhishingAttackDetection worker --concurrency=8 --loglevel=info
```

### Use Multi-Processing Pool
```bash
celery -A PhishingAttackDetection worker --pool=prefork --loglevel=info
```

### Monitor Resource Usage
```bash
# Install and use Flower (web-based monitoring)
pip install flower
flower -A PhishingAttackDetection --port=5555
```

Then visit: http://localhost:5555

## Next Steps

1. **Install dependencies**: `pip install -r requirements.txt`
2. **Start all services**: `start_all_services.bat`
3. **Test a background task**: Navigate to the application and trigger a URL scan
4. **Monitor**: Watch the Celery worker window for task execution

## Support

For more information:
- Celery Docs: https://docs.celeryproject.io/
- Django-Celery Integration: https://docs.celeryproject.io/en/stable/django/
- Redis Documentation: https://redis.io/documentation
