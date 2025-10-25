@echo off
echo ======================================================================
echo    SOC AI Agents - Quick Start Script
echo ======================================================================
echo.

REM Check if .env file exists
if not exist .env (
    echo [ERROR] .env file not found!
    echo.
    echo Please create .env file from .env.example:
    echo   1. Copy .env.example to .env
    echo   2. Add your OpenAI API key
    echo.
    pause
    exit /b 1
)

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    echo Please install Python 3.8 or higher from:
    echo https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [INFO] Checking dependencies...
echo.

REM Install dependencies if needed
pip show flask >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Installing dependencies... This may take a few minutes.
    echo.
    pip install flask flask-socketio python-socketio eventlet python-dotenv openai
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install dependencies!
        pause
        exit /b 1
    )
    echo.
    echo [SUCCESS] Dependencies installed!
    echo.
) else (
    echo [INFO] Dependencies already installed.
    echo.
)

echo ======================================================================
echo    Starting Enhanced SOC AI Agents Web Application
echo ======================================================================
echo.
echo The application will start in a few seconds...
echo.
echo When ready, open your browser to: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server.
echo.
echo ======================================================================
echo.

REM Run the application
python enhanced_web_chatbot.py

pause
