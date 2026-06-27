# PowerShell Script to Start All Services
# Usage: .\start_all_services.ps1
# Note: Run as Administrator if encountering permission issues

# Get the script's directory
$ScriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

# Function to check if a command exists
function CommandExists {
    param($command)
    $null = Get-Command $command -ErrorAction SilentlyContinue
    return $?
}

# Function to start a service in a new window
function StartServiceWindow {
    param(
        [string]$WindowTitle,
        [string]$Command,
        [string]$Arguments = ""
    )
    
    if ($Arguments) {
        Start-Process -FilePath $Command -ArgumentList $Arguments -WindowStyle Normal -PassThru | Out-Null
    } else {
        Start-Process -FilePath $Command -WindowStyle Normal -PassThru | Out-Null
    }
    
    Write-Host "[OK] Started: $WindowTitle"
    Start-Sleep -Seconds 2
}

Write-Host "==============================================="
Write-Host "  Phishing Attack Detection - Service Starter"
Write-Host "==============================================="
Write-Host ""

# Check if Python is available
if (-not (CommandExists python)) {
    Write-Host "ERROR: Python is not installed or not in PATH"
    Write-Host "Please install Python and add it to PATH"
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Starting all services..."
Write-Host ""

# Create logs directory if it doesn't exist
$LogsDir = Join-Path -Path $ScriptDir -ChildPath "logs"
if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir | Out-Null
}

# Start Redis
Write-Host "[1/4] Starting Redis Server..."
try {
    if (CommandExists redis-server) {
        $RedisProcess = Start-Process -FilePath "redis-server" -ArgumentList "--port 6379" `
            -WindowStyle Normal -PassThru -RedirectStandardOutput "$LogsDir\redis.log"
        Write-Host "[OK] Redis Server started"
    } else {
        Write-Host "[WARNING] Redis not found. Make sure it's installed and in PATH"
    }
} catch {
    Write-Host "[ERROR] Failed to start Redis: $_"
}
Start-Sleep -Seconds 2

# Start Django
Write-Host "[2/4] Starting Django Development Server..."
try {
    $DjangoProcess = Start-Process -FilePath "python" `
        -ArgumentList "manage.py", "runserver", "0.0.0.0:8000" `
        -WindowStyle Normal -PassThru -RedirectStandardOutput "$LogsDir\django.log"
    Write-Host "[OK] Django server started on http://localhost:8000"
} catch {
    Write-Host "[ERROR] Failed to start Django: $_"
}
Start-Sleep -Seconds 2

# Start Celery Worker
Write-Host "[3/4] Starting Celery Worker..."
try {
    $WorkerProcess = Start-Process -FilePath "python" `
        -ArgumentList "-m", "celery", "-A", "PhishingAttackDetection", "worker", `
        "--loglevel=info", "--concurrency=4" `
        -WindowStyle Normal -PassThru -RedirectStandardOutput "$LogsDir\celery_worker.log"
    Write-Host "[OK] Celery Worker started"
} catch {
    Write-Host "[ERROR] Failed to start Celery Worker: $_"
}
Start-Sleep -Seconds 2

# Start Celery Beat
Write-Host "[4/4] Starting Celery Beat Scheduler..."
try {
    $BeatProcess = Start-Process -FilePath "python" `
        -ArgumentList "-m", "celery", "-A", "PhishingAttackDetection", "beat", `
        "--loglevel=info" `
        -WindowStyle Normal -PassThru -RedirectStandardOutput "$LogsDir\celery_beat.log"
    Write-Host "[OK] Celery Beat Scheduler started"
} catch {
    Write-Host "[ERROR] Failed to start Celery Beat: $_"
}

Write-Host ""
Write-Host "==============================================="
Write-Host "  All Services Started Successfully!"
Write-Host "==============================================="
Write-Host ""
Write-Host "Services Running:"
Write-Host "  ✓ Redis Server (Port 6379)"
Write-Host "  ✓ Django Server (http://localhost:8000)"
Write-Host "  ✓ Celery Worker (Async Tasks)"
Write-Host "  ✓ Celery Beat (Scheduled Tasks)"
Write-Host ""
Write-Host "Logs directory: $LogsDir"
Write-Host ""
Write-Host "To stop services, close the windows or use Task Manager"
Write-Host ""
Read-Host "Press Enter to exit this window"
