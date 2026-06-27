@echo off
REM Start Redis Server (Required for Celery Message Broker)
REM Make sure Redis is installed via: choco install redis-64 or download from https://github.com/microsoftarchive/redis/releases

echo Starting Redis Server...
redis-server --port 6379

pause
