@echo off
echo ========================================
echo SOC AI Agents Web Interface
echo ========================================
echo.
echo Starting web server...
echo Server will be available at: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo.

cd /d "%~dp0"
python web\app.py
