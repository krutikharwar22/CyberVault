@echo off
REM Remove Windows Services for Phishing Attack Detection Application
REM Requires: Administrator privileges

echo.
echo ====================================================
echo  Windows Service Removal Script
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

REM Check if NSSM is installed
where nssm >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: NSSM is not installed or not in PATH
    pause
    exit /b 1
)

echo Removing services...
echo.

REM Stop and remove services
for %%S in (DjangoServer CeleryWorker CeleryBeat Redis) do (
    sc query %%S >nul 2>&1
    if %errorlevel% equ 0 (
        echo Stopping %%S...
        net stop %%S
        echo Removing %%S...
        nssm remove %%S confirm
        echo [OK] %%S removed
    ) else (
        echo [SKIP] %%S not found
    )
    echo.
)

echo.
echo ====================================================
echo  Services Removed Successfully!
echo ====================================================
echo.
pause
