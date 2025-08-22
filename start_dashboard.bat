@echo off
echo ========================================
echo    IT Security Dashboard Launcher
echo ========================================
echo.
echo Starting Security Dashboard...
echo.
echo Please wait while the system initializes...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

REM Check if requirements are installed
echo Checking dependencies...
pip show flask >nul 2>&1
if errorlevel 1 (
    echo Installing required packages...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install requirements
        pause
        exit /b 1
    )
)

echo.
echo Starting dashboard...
echo.
echo Dashboard will be available at: http://localhost:5000
echo.
echo Press Ctrl+C to stop the dashboard
echo.

REM Start the dashboard
python app.py

pause

