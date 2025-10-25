@echo off
echo 🛡️  SOC AI AGENTS - WEB CHATBOT
echo ====================================
echo Starting SOC-protected web chatbot...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    pause
    exit /b 1
)

REM Install requirements if needed
if not exist "requirements_web.txt" (
    echo 📦 Creating requirements file...
    python auto_integrate_soc.py
)

echo 📦 Installing/updating dependencies...
pip install -r requirements_web.txt

echo 🚀 Starting web chatbot...
echo 🌐 Web interface will be available at: http://localhost:5000
echo 🛡️  SOC monitoring is ACTIVE
echo.
echo Press Ctrl+C to stop the server
echo.

python web_chatbot.py

pause
