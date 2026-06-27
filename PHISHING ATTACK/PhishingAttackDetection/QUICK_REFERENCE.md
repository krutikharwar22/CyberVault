# Quick Reference - Background Tasks

## 🚀 Quick Start

### All-in-One (Easiest)
```bash
start_all_services.bat
```
Opens 4 windows: Redis, Django, Celery Worker, Celery Beat

---

## 📋 Individual Commands

| Service | Command | Purpose |
|---------|---------|---------|
| **Redis** | `start_redis.bat` | Message broker (required) |
| **Django** | `start_django.bat` | Web server on http://localhost:8000 |
| **Celery Worker** | `start_celery_worker.bat` | Processes async tasks |
| **Celery Beat** | `start_celery_beat.bat` | Handles scheduled tasks |

---

## 🔧 Production Setup (Windows Services)

### Prerequisites
1. Download NSSM: https://nssm.cc/download
2. Add NSSM to Windows PATH
3. Run Command Prompt as Administrator

### Install Services
```bash
install_windows_services.bat
```

### Uninstall Services
```bash
uninstall_windows_services.bat
```

### Manage Services
```bash
# View all services
services.msc

# Start/Stop via command line
net start ServiceName
net stop ServiceName

# Check status
sc query ServiceName
```

---

## 📝 Using Background Tasks

### 1. Async URL Scanning
```python
from AttackApp.tasks import scan_url_async

# Trigger async scan
result = scan_url_async.delay(url='https://example.com', user_id=1)
print(f"Task ID: {result.id}")
```

### 2. Async Model Training
```python
from AttackApp.tasks import train_ml_model_async

# Start training in background
result = train_ml_model_async.delay(model_type='url_classifier')
```

### 3. Log Activity Asynchronously
```python
from AttackApp.tasks import log_user_activity

log_user_activity.delay(
    user_id=1,
    activity_type='login',
    description='User logged in',
    ip_address='192.168.1.1'
)
```

### 4. Check Task Status
```python
from celery.result import AsyncResult

task = AsyncResult('task-id-here')
print(f"Status: {task.state}")      # PENDING, STARTED, SUCCESS, FAILURE
print(f"Result: {task.result}")     # When task.ready() == True
```

---

## 📅 Scheduled Tasks

| Task | Schedule | Purpose |
|------|----------|---------|
| `purge_dummy_data_task` | Daily 2:00 AM | Clean old logs & scans |
| `system_health_check` | Every 5 minutes | Monitor CPU/Memory/Disk |
| `cleanup_old_logs` | Sunday 3:00 AM | Archive old records |

---

## 🔍 Monitoring

### View Active Tasks
```bash
celery -A PhishingAttackDetection inspect active
```

### View Statistics
```bash
celery -A PhishingAttackDetection inspect stats
```

### View Registered Tasks
```bash
celery -A PhishingAttackDetection inspect registered
```

### Web-Based Monitoring (Flower)
```bash
pip install flower
flower -A PhishingAttackDetection --port=5555
# Then visit http://localhost:5555
```

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Redis connection error | Run `start_redis.bat` first |
| Tasks not processing | Check if Celery worker is running |
| Scheduled tasks not running | Ensure Celery Beat is running |
| Can't connect to Django | Check port 8000 is not in use |
| Permission denied (Windows) | Run batch files as Administrator |

---

## 📂 Key Files

- `PhishingAttackDetection/celery.py` - Celery config & schedule
- `PhishingAttackDetection/settings.py` - Django Celery settings
- `AttackApp/tasks.py` - Task definitions
- `BACKGROUND_TASKS_SETUP.md` - Full documentation

---

## ⚙️ Configuration

Edit `PhishingAttackDetection/settings.py` to customize:

```python
# Broker connection
CELERY_BROKER_URL = 'redis://localhost:6379/0'

# Worker settings
CELERY_WORKER_PREFETCH_MULTIPLIER = 4
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes

# Task expiration
CELERY_RESULT_EXPIRES = 3600  # 1 hour
```

---

## 📖 Full Documentation

See `BACKGROUND_TASKS_SETUP.md` for complete setup guide and examples.
