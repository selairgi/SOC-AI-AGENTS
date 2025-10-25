# 🛡️ SOC AI Agents - Web Chatbot

## Overview
A web-based chatbot with integrated SOC (Security Operations Center) AI Agents for real-time security monitoring.

## Features
- 🌐 **Web Interface**: Modern, responsive chat interface
- 🛡️ **SOC Monitoring**: Real-time threat detection
- 🚨 **Security Alerts**: Live security alert notifications
- 🔒 **Threat Detection**: Detects prompt injection, data exfiltration, system commands
- 📊 **Real-time Updates**: WebSocket-based live updates

## Quick Start

### Windows:
```bash
start_web_chatbot.bat
```

### Linux/Mac:
```bash
./start_web_chatbot.sh
```

### Manual:
```bash
pip install -r requirements_web.txt
python web_chatbot.py
```

## Usage
1. Open your web browser
2. Navigate to `http://localhost:5000`
3. Start chatting - SOC will monitor for threats
4. View security alerts in the right panel

## Security Features
- **Prompt Injection Detection**: Detects attempts to manipulate the chatbot
- **Data Exfiltration Prevention**: Blocks attempts to extract sensitive data
- **System Command Blocking**: Prevents malicious system commands
- **Real-time Monitoring**: Continuous security analysis
- **Automated Response**: Immediate threat response

## Integration
To integrate SOC monitoring with your own application, use `soc_integration_template.py` as a starting point.

## API Endpoints
- `POST /api/chat` - Send chat message
- `GET /api/security/alerts` - Get security alerts
- `GET /api/security/status` - Get SOC status

## WebSocket Events
- `security_alert` - Real-time security alert notifications
- `connect` - Client connection
- `disconnect` - Client disconnection
