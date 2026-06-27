@echo off
REM Start Django Development Server in Background

cd /d "%~dp0"

echo Starting Django Development Server on http://localhost:8000
echo Press Ctrl+C to stop the server

python manage.py runserver 0.0.0.0:8000

pause
