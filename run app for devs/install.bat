@echo off
echo TaskPortKiller - Installation Script
echo ====================================
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

REM Check if pip is available
pip --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: pip is not available
    echo.
    echo Please ensure Python's pip module is installed and in PATH.
    echo.
    pause
    exit /b 1
)

REM Install required packages
echo Installing required packages...
pip install -r requirements.txt

if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: Failed to install required packages
    pause
    exit /b 1
)

echo.
echo Installation complete!
echo.
echo You can now run TaskPortKiller by:
echo 1. Double-clicking run_app.bat
echo 2. Or running 'python main.py' from the command line
echo.
pause
