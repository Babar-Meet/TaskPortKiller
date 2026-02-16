@echo off
setlocal

:: =====================================================
::    TaskPortKiller - Build EXE
:: =====================================================
echo.
echo =====================================================
echo    TaskPortKiller - Build Executable
echo =====================================================
echo.
echo This will create a single .exe file that can run on
echo ANY Windows computer without Python.
echo.
echo Press any key to begin...
pause >nul

:: Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: Python is not installed!
    echo.
    echo Please install Python 3.6+ from python.org
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

:: Create and activate virtual environment
echo.
echo Step 1: Setting up environment...
python -m venv build_env
call build_env\Scripts\activate.bat

:: Upgrade pip
echo.
echo Step 2: Installing tools...
python -m pip install --upgrade pip >nul

:: Install requirements (if any)
if exist requirements.txt (
    echo Installing dependencies from requirements.txt...
    pip install -r requirements.txt
) else (
    echo No requirements.txt found, skipping.
)

:: Install PyInstaller
echo Installing PyInstaller...
pip install pyinstaller >nul

:: Build the executable
echo.
echo Step 3: Building executable (this may take a minute)...
if not exist main.py (
    echo ERROR: main.py not found!
    pause
    exit /b 1
)

:: Clean previous builds
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist TaskPortKiller.spec del TaskPortKiller.spec

:: Build with icon if present
set ICON_OPTION=
if exist icon.ico set ICON_OPTION=--icon=icon.ico

pyinstaller --onefile --windowed %ICON_OPTION% --name=TaskPortKiller --distpath=dist main.py
if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

:: Clean up build environment
echo.
echo Step 4: Cleaning up...
deactivate
rmdir /s /q build_env

:: Show result
if exist "dist\TaskPortKiller.exe" (
    echo.
    echo =====================================================
    echo    ✅ SUCCESS!
    echo =====================================================
    echo.
    echo Your standalone executable is in the "dist" folder:
    echo   %CD%\dist\TaskPortKiller.exe
    echo.
    echo To distribute, just copy that .exe file – no Python needed!
) else (
    echo.
    echo ❌ ERROR: Build failed – output not found.
)

echo.
pause
endlocal