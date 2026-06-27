@echo off
REM Install Windows Services for Phishing Attack Detection Application
REM Requires: NSSM (Non-Sucking Service Manager) and Administrator privileges

echo.
echo ====================================================
echo  Windows Service Installation Script
echo ====================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script requires Administrator privileges!
    echo Please run as Administrator.
    pause
    exit /b 1
)

REM Get current directory
cd /d "%~dp0"

REM Check if NSSM is installed
where nssm >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: NSSM is not installed or not in PATH
    echo.
    echo Download NSSM from: https://nssm.cc/download
    echo 1. Extract the zip file
    echo 2. Copy nssm.exe to a folder
    echo 3. Add that folder to Windows PATH
    echo.
    echo Or run these commands in PowerShell as Administrator:
    echo   choco install nssm
    echo.
    pause
    exit /b 1
)

REM Get Python path
for /f "delims=" %%i in ('python -c "import sys; print(sys.executable)"') do set PYTHON_PATH=%%i

if not exist "%PYTHON_PATH%" (
    echo ERROR: Cannot find Python installation
    pause
    exit /b 1
)

echo Python found at: %PYTHON_PATH%
echo Project directory: %cd%
echo.

REM Install Redis Service (if not already installed)
sc query Redis >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Redis Service...
    nssm install Redis redis-server --port 6379
    nssm set Redis AppDirectory "%cd%"
    nssm set Redis AppStdout "%cd%\logs\redis.log"
    nssm set Redis AppStderr "%cd%\logs\redis.err"
    net start Redis
    echo [OK] Redis service installed and started
) else (
    echo [SKIP] Redis service already installed
)

REM Install Django Service
sc query DjangoServer >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Django Service...
    nssm install DjangoServer "%PYTHON_PATH%" manage.py runserver 0.0.0.0:8000
    nssm set DjangoServer AppDirectory "%cd%"
    nssm set DjangoServer AppStdout "%cd%\logs\django.log"
    nssm set DjangoServer AppStderr "%cd%\logs\django.err"
    nssm set DjangoServer AppRotateFiles 1
    nssm set DjangoServer AppRotateOnline 1
    nssm set DjangoServer AppRotateSize 10485760
    net start DjangoServer
    echo [OK] Django service installed and started
) else (
    echo [SKIP] Django service already installed
)

REM Install Celery Worker Service
sc query CeleryWorker >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Celery Worker Service...
    nssm install CeleryWorker "%PYTHON_PATH%" -m celery -A PhishingAttackDetection worker --loglevel=info --concurrency=4
    nssm set CeleryWorker AppDirectory "%cd%"
    nssm set CeleryWorker AppStdout "%cd%\logs\celery_worker.log"
    nssm set CeleryWorker AppStderr "%cd%\logs\celery_worker.err"
    nssm set CeleryWorker AppRotateFiles 1
    nssm set CeleryWorker AppRotateOnline 1
    nssm set CeleryWorker AppRotateSize 10485760
    net start CeleryWorker
    echo [OK] Celery Worker service installed and started
) else (
    echo [SKIP] Celery Worker service already installed
)

REM Install Celery Beat Service
sc query CeleryBeat >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Celery Beat Service...
    nssm install CeleryBeat "%PYTHON_PATH%" -m celery -A PhishingAttackDetection beat --loglevel=info
    nssm set CeleryBeat AppDirectory "%cd%"
    nssm set CeleryBeat AppStdout "%cd%\logs\celery_beat.log"
    nssm set CeleryBeat AppStderr "%cd%\logs\celery_beat.err"
    nssm set CeleryBeat AppRotateFiles 1
    nssm set CeleryBeat AppRotateOnline 1
    nssm set CeleryBeat AppRotateSize 10485760
    net start CeleryBeat
    echo [OK] Celery Beat service installed and started
) else (
    echo [SKIP] Celery Beat service already installed
)

echo.
echo ====================================================
echo  Installation Complete!
echo ====================================================
echo.
echo Services installed:
echo   - Redis (Port 6379)
echo   - DjangoServer (http://localhost:8000)
echo   - CeleryWorker (Background tasks)
echo   - CeleryBeat (Scheduled tasks)
echo.
echo To check service status:
echo   services.msc
echo.
echo To view service logs:
echo   type logs\redis.log
echo   type logs\django.log
echo   type logs\celery_worker.log
echo   type logs\celery_beat.log
echo.
echo To manage services:
echo   net start ServiceName
echo   net stop ServiceName
echo   nssm remove ServiceName (to uninstall)
echo.
pause
