@echo off
REM Start Celery Beat Scheduler for Periodic Tasks

cd /d "%~dp0"

echo Starting Celery Beat Scheduler...
echo This will handle periodic/scheduled tasks

celery -A PhishingAttackDetection beat --loglevel=info

pause
