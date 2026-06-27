@echo off
REM Start Celery Worker for Background Tasks

cd /d "%~dp0"

echo Starting Celery Worker...
echo This will process async background tasks

celery -A PhishingAttackDetection worker --loglevel=info --concurrency=4

pause
