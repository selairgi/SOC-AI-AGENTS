#!/bin/bash
echo "🛡️  SOC AI AGENTS - WEB CHATBOT"
echo "===================================="
echo "Starting SOC-protected web chatbot..."
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    echo "Please install Python 3.7+ and try again"
    exit 1
fi

# Install requirements if needed
if [ ! -f "requirements_web.txt" ]; then
    echo "📦 Creating requirements file..."
    python3 auto_integrate_soc.py
fi

echo "📦 Installing/updating dependencies..."
pip3 install -r requirements_web.txt

echo "🚀 Starting web chatbot..."
echo "🌐 Web interface will be available at: http://localhost:5000"
echo "🛡️  SOC monitoring is ACTIVE"
echo
echo "Press Ctrl+C to stop the server"
echo

python3 web_chatbot.py
