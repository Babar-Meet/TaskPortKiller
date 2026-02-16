@echo off
echo TaskPortKiller - Professional Ports/Processes Management Tool
echo ===========================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python 3.7 or higher and try again.
    echo.
    pause
    exit /b 1
)

REM Check if psutil is installed
python -c "import psutil" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo psutil library not found. Installing...
    pip install psutil
    if %ERRORLEVEL% neq 0 (
        echo ERROR: Failed to install psutil
        pause
        exit /b 1
    )
)

REM Run the application
echo Starting TaskPortKiller...
echo.
python main.py

REM Handle exit codes
if %ERRORLEVEL% neq 0 (
    echo.
    echo Application exited with error code: %ERRORLEVEL%
    pause
    exit /b %ERRORLEVEL%
)
