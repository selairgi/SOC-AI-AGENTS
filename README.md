# 🛡️ SOC AI Agents

**AI-powered Security Operations Center with autonomous threat detection and automated remediation**

## What Is This?

A production-ready SOC system that monitors AI agents for security threats in real-time and automatically responds to attacks. Think of it as a security guard for your AI applications.

## Core Features

🤖 **Multi-Agent System** - Three autonomous agents working together
🌐 **Web Interface** - Interactive chatbot with live security monitoring
🚨 **Real-Time Threat Detection** - Identifies 6 types of attacks instantly
⚡ **Auto Remediation** - Blocks IPs, limits rates, terminates sessions
🧠 **AI Integration** - Uses OpenAI GPT with comprehensive logging
🎯 **False Positive Detection** - ML-based confidence scoring
📊 **Live Dashboard** - Real-time alerts, metrics, and system status
🔒 **Enterprise Ready** - Circuit breakers, retry logic, idempotency

## Quick Start

```bash
# 1. Install dependencies
pip install flask flask-socketio python-socketio eventlet openai python-dotenv

# 2. Set up OpenAI API key (optional)
echo OPENAI_API_KEY=sk-your-key-here > .env

# 3. Launch web interface
python enhanced_web_chatbot.py

# 4. Open browser
http://localhost:5000
```

**That's it!** Try clicking "Prompt Injection" to see the system detect and block threats.

---

## How It Works: Agent Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         USER INPUT                          │
│                    (Web UI or Chat Message)                 │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
         ┌───────────────────────────────────────┐
         │      1. SOC BUILDER AGENT             │
         │  ┌─────────────────────────────────┐  │
         │  │ • Monitors logs & messages      │  │
         │  │ • Detects suspicious patterns   │  │
         │  │ • Generates security alerts     │  │
         │  └─────────────────────────────────┘  │
         └──────────────┬────────────────────────┘
                        │ Publishes Alerts
                        ▼
         ┌───────────────────────────────────────┐
         │      2. SOC ANALYST AGENT             │
         │  ┌─────────────────────────────────┐  │
         │  │ • Analyzes alert severity       │  │
         │  │ • Checks false positive score   │  │
         │  │ • Creates remediation plan      │  │
         │  └─────────────────────────────────┘  │
         └──────────────┬────────────────────────┘
                        │ Sends Playbook
                        ▼
         ┌───────────────────────────────────────┐
         │      3. REMEDIATOR AGENT              │
         │  ┌─────────────────────────────────┐  │
         │  │ • Executes remediation actions  │  │
         │  │ • Blocks IPs / Rate limits      │  │
         │  │ • Terminates sessions           │  │
         │  └─────────────────────────────────┘  │
         └──────────────┬────────────────────────┘
                        │
                        ▼
         ┌───────────────────────────────────────┐
         │         ACTION TAKEN                  │
         │  🚫 Block IP   ⏱️ Rate Limit           │
         │  🔒 Session End  ⛔ User Suspend       │
         └───────────────────────────────────────┘
```

## Threat Detection Flow

```
Message → Check Blocks → Check Rate → Generate AI → Security → Remediate
                ↓            ↓        Response      Analysis       ↓
           [BLOCKED?]   [LIMITED?]       ↓            ↓       [TAKE ACTION]
                ↓            ↓        ┌──────┐   ┌────────┐       ↓
             REJECT       REJECT      │OpenAI│   │Pattern │   Block/Limit
                                      │  +   │→  │ Match  │→  /Terminate
                                      │Logs  │   │  +ML   │
                                      └──────┘   └────────┘
```

## Agent Communication

```
┌─────────────────────────────────────────────────────────────────┐
│                         MESSAGE BUS                             │
│              (Async pub/sub for agent coordination)             │
└──────────────┬───────────────────┬──────────────────────────────┘
               │                   │
       publishes alerts    subscribes to alerts
               │                   │
        ┌──────▼─────┐     ┌───────▼────────┐
        │ SOC Builder│     │  SOC Analyst   │
        └────────────┘     └────────┬───────┘
                                    │
                           sends to queue
                                    │
                           ┌────────▼────────┐
                           │  Remediator     │
                           └─────────────────┘
```

## Supported Threats

| Threat Type | Description | Severity | Auto Action |
|-------------|-------------|----------|-------------|
| **Prompt Injection** | AI jailbreak attempts | HIGH | Rate limit + Monitor |
| **Data Exfiltration** | Extracting sensitive data | CRITICAL | Block IP + Terminate session |
| **System Manipulation** | Command injection | HIGH | Terminate session |
| **Privacy Violation** | Accessing private info | HIGH/CRITICAL | Block + Notify compliance |
| **Rate Limit Abuse** | Excessive requests | MEDIUM | Apply rate limit |
| **Malicious Input** | XSS, SQL injection, etc. | HIGH | Block IP |

## Remediation Actions

```
┌────────────────────────────────────────────────────────────┐
│                   GRADUATED RESPONSE                       │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  LOW SEVERITY          → Monitor & Log                    │
│  ────────────────────────────────────────                 │
│                                                            │
│  MEDIUM SEVERITY       → Rate Limit (5 req/120s)          │
│  ────────────────────────────────────────                 │
│                                                            │
│  HIGH SEVERITY         → Rate Limit + Terminate Session   │
│  ────────────────────────────────────────                 │
│                                                            │
│  CRITICAL SEVERITY     → Block IP + Terminate + Suspend   │
│  ────────────────────────────────────────                 │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

## Key Components

### Web Layer
- `enhanced_web_chatbot.py` - Flask app with SocketIO for real-time updates
- `templates/enhanced_chatbot.html` - Interactive UI with security dashboard

### AI & Security
- `real_ai_integration.py` - OpenAI API integration with logging
- `security_rules.py` - Pattern-based threat detection
- `false_positive_detector.py` - ML-based confidence scoring

### SOC Agents
- `soc_builder.py` - Log monitoring & alert generation
- `soc_analyst.py` - Alert analysis & playbook creation
- `remediator.py` - Action execution engine

### Remediation
- `real_remediation.py` - IP blocking, rate limiting, session management
- `action_policy.py` - Policy enforcement & approval workflows

### Reliability
- `execution_tracker.py` - Idempotency & deduplication
- `retry_circuit_breaker.py` - Retry logic with circuit breaker
- `bounded_queue.py` - Memory-bounded queues with backpressure

## Usage Examples

### Web Interface
```bash
# Start the web app
python enhanced_web_chatbot.py

# Access at http://localhost:5000
# Toggle SOC monitoring ON/OFF
# Click attack buttons to test
# Watch live alerts panel
```

### Command Line
```bash
# Run with default settings (dev environment, 60s)
python main.py

# Run production environment
python main.py --environment production

# Run indefinitely
python main.py --duration 0

# Enable real remediation
python main.py --real
```

### Attack Testing
In the web UI, use the built-in attack scenario buttons:
- **Prompt Injection** - Tests AI jailbreak detection
- **Data Exfiltration** - Tests data protection
- **System Manipulation** - Tests command injection blocking
- **Malicious Input** - Tests XSS/SQLi detection

## API Endpoints

```
POST   /api/chat              # Send message, get AI response + security check
GET    /api/soc/status        # View SOC status, stats, blocked entities
POST   /api/soc/toggle        # Enable/disable SOC monitoring
GET    /api/security/alerts   # Get recent security alerts
POST   /api/test/scenario/:name  # Run attack scenario test
```

## Configuration

### Security Modes
```python
# Edit enhanced_web_chatbot.py line 115
security_mode="strict"  # Options: default | security_aware | strict
```

### Rate Limiting
```python
# Edit enhanced_web_chatbot.py line 460
limit=5,        # Requests allowed
window=120.0,   # Time window (seconds)
```

### Block Duration
```python
# Edit enhanced_web_chatbot.py line 471
duration=3600,  # IP block time (seconds)
```

## Environment Presets

| Preset | Scan Paths | Use Case |
|--------|------------|----------|
| **development** | Workspace logs | Testing & dev |
| **production** | /var/log/app | Production deployment |
| **medical** | Medical agent logs | HIPAA compliance |
| **financial** | Financial agent logs | PCI/SOX compliance |

## Testing

```bash
# Run full test suite
python main.py --run-tests

# Quick smoke test
python main.py --smoke-test

# Test specific scenarios
python test_medical_soc.py
python test_web_soc.py
```

## Verifying Remediation

**Server Console** - Watch for these messages:
```
⏱️  RATE LIMIT APPLIED: ip 127.0.0.1 - 5 requests per 120.0s
🚫 BLOCKED IP: 127.0.0.1 3600s - Reason: Critical threat
🚫 TERMINATED SESSION: session_xyz - Reason: Security threat
```

**Browser Console (F12)** - Check API responses:
```json
{
  "security_check": {
    "remediation_taken": true,
    "remediation_actions": [
      {"type": "rate_limit", "target": "127.0.0.1"},
      {"type": "terminate_session", "target": "session_xyz"}
    ]
  }
}
```

**Quick Test**:
1. Click "Prompt Injection" → Rate limit applied
2. Send 6+ messages quickly → 6th blocked
3. Click "Data Exfiltration" → IP blocked
4. Try any message → Access denied ✓

## Architecture Highlights

🔄 **Message Bus** - Async pub/sub for agent communication
🎯 **Queue-Based** - Remediator uses bounded queue with backpressure
⚡ **Non-Blocking** - All operations are async
🔒 **Thread-Safe** - Concurrent access with locks
📝 **Audit Trail** - Complete action history
🛡️ **Idempotent** - Actions deduplicated, safe to retry

## Requirements

- Python 3.8+
- OpenAI API key (optional, has fallback mode)

**Core dependencies:**
```
flask
flask-socketio
python-socketio
eventlet
python-dotenv
openai
```

## Production Deployment

⚠️ **Before going live:**
- Use HTTPS (configure reverse proxy)
- Move to persistent storage (Redis/PostgreSQL)
- Set up log aggregation (ELK/Splunk)
- Use secret management (AWS Secrets Manager)
- Configure firewall rules
- Review rate limits for your traffic
- Enable monitoring/alerting

## Troubleshooting

**No OpenAI responses?**
- Install: `pip install openai`
- Add API key to `.env`
- Fallback mode works without API key

**Stuck blocked?**
- Restart server to clear blocks
- Wait for timeout (default: 1 hour for IPs)

**No alerts appearing?**
- Toggle SOC ON (green switch)
- Try explicit attack messages
- Check console for errors

## Project Structure

```
SOC ai agents/
├── enhanced_web_chatbot.py      # Main web application
├── soc_builder.py               # Alert generation agent
├── soc_analyst.py               # Alert analysis agent
├── remediator.py                # Action execution agent
├── real_remediation.py          # Remediation engine
├── real_ai_integration.py       # OpenAI integration
├── security_rules.py            # Threat detection
├── false_positive_detector.py   # ML scoring
├── message_bus.py               # Agent communication
├── models.py                    # Data models
├── config.py                    # Configuration
├── main.py                      # CLI entry point
└── templates/
    └── enhanced_chatbot.html    # Web UI
```

## License

This is a prototype/educational system demonstrating SOC automation concepts.

---

**Ready to see it in action?** Run `python enhanced_web_chatbot.py` and open http://localhost:5000
