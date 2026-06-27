@echo off
REM Start All Services in Background Using Multiple Windows

echo This script will open multiple windows to run all services
echo Make sure Redis is installed first!
echo.

cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

echo Starting all services...
echo.

REM Start Redis in a new window
echo [1/4] Starting Redis Server...
start "Redis Server" cmd /k "redis-server --port 6379"
timeout /t 2

REM Start Django Server
echo [2/4] Starting Django Development Server...
start "Django Server - http://localhost:8000" cmd /k "python manage.py runserver 0.0.0.0:8000"
timeout /t 2

REM Start Celery Worker
echo [3/4] Starting Celery Worker...
start "Celery Worker" cmd /k "celery -A PhishingAttackDetection worker --loglevel=info --concurrency=4"
timeout /t 2

REM Start Celery Beat
echo [4/4] Starting Celery Beat Scheduler...
start "Celery Beat Scheduler" cmd /k "celery -A PhishingAttackDetection beat --loglevel=info"

echo.
echo All services started successfully!
echo.
echo Services running:
echo   - Redis Server (Port 6379)
echo   - Django Server (http://localhost:8000)
echo   - Celery Worker (for async tasks)
echo   - Celery Beat (for scheduled tasks)
echo.
echo To stop all services, close all the opened windows or use Task Manager.
echo Press any key to close this window...
pause >nul
