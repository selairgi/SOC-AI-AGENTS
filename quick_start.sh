#!/bin/bash

echo "======================================================================"
echo "   SOC AI Agents - Quick Start Script"
echo "======================================================================"
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "[ERROR] .env file not found!"
    echo ""
    echo "Please create .env file from .env.example:"
    echo "  1. Copy .env.example to .env"
    echo "  2. Add your OpenAI API key"
    echo ""
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed!"
    echo ""
    echo "Please install Python 3.8 or higher"
    echo ""
    exit 1
fi

echo "[INFO] Checking dependencies..."
echo ""

# Install dependencies if needed
if ! python3 -c "import flask" &> /dev/null; then
    echo "[INFO] Installing dependencies... This may take a few minutes."
    echo ""
    pip3 install flask flask-socketio python-socketio eventlet python-dotenv openai
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to install dependencies!"
        exit 1
    fi
    echo ""
    echo "[SUCCESS] Dependencies installed!"
    echo ""
else
    echo "[INFO] Dependencies already installed."
    echo ""
fi

echo "======================================================================"
echo "   Starting Enhanced SOC AI Agents Web Application"
echo "======================================================================"
echo ""
echo "The application will start in a few seconds..."
echo ""
echo "When ready, open your browser to: http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the server."
echo ""
echo "======================================================================"
echo ""

# Run the application
python3 enhanced_web_chatbot.py
