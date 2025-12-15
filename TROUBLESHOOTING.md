# 🔧 Troubleshooting Web Server Startup

## Issue: Server Not Starting / Can't Access localhost:5000

### Current Status

The server is initializing but appears to hang during startup. This is likely because:
1. The semantic detector is loading the ML model (~500MB)
2. Model downloading/loading takes 1-3 minutes on first run
3. No error - just slow initialization

### Solution: Wait Longer!

**The server takes 1-3 minutes to fully start** on first run because it needs to:
- Load sentence-transformers model
- Initialize semantic detector
- Set up all security components

### How to Start

#### Method 1: Direct Python (Recommended for Debugging)

```bash
cd "c:\Users\salah\Desktop\SOC AI agents cursor"
python web/app.py
```

**Wait for this message**:
```
======================================================================
Web interface: http://localhost:5000
Health check: http://localhost:5000/health
======================================================================
 * Running on http://0.0.0.0:5000
```

**This may take 1-3 minutes!** Be patient! ⏳

#### Method 2: Use start_web.bat

```bash
start_web.bat
```

Same thing - just wait for the "Running on..." message.

### What You'll See

**During Startup (1-3 minutes)**:
```
AgentMemory - INFO - Agent Memory initialized
RealAIIntegration - INFO - Real AI Integration initialized
ActionPolicyEngine - INFO - Added policy rule: Block Private IPs
... (many more lines) ...
Remediator - INFO - Ready to execute playbooks

[LOADING SEMANTIC DETECTOR - THIS TAKES TIME!]
[May appear stuck here for 1-3 minutes]

SemanticThreatDetector - INFO - Loading model...
SemanticThreatDetector - INFO - Model loaded successfully
SOCWebApp - INFO - =============================
SOCWebApp - INFO - SECURE SOC AI AGENTS - WEB APPLICATION
...
 * Running on http://0.0.0.0:5000
```

### Quick Test: Skip Semantic Detection (Fast Startup)

If you want to test WITHOUT waiting for the ML model:

**Edit**: `security/security_rules.py`

Find and temporarily disable:
```python
# Comment out semantic detector initialization
# self.semantic_detector = SemanticThreatDetector()
```

**Then** the server will start in ~5 seconds!

### Verify Server is Running

In another terminal:
```bash
curl http://localhost:5000/health
```

Expected response:
```json
{"status":"healthy","checks":{"database":"ok",...}}
```

### Common Issues

#### Issue 1: "Module not found"
```bash
pip install flask flask-socketio flask-limiter flask-cors eventlet python-dotenv
pip install sentence-transformers torch scikit-learn
```

#### Issue 2: "Port 5000 already in use"
```bash
# Find process using port 5000
netstat -ano | findstr :5000

# Kill it (replace PID with the actual number)
taskkill /PID <PID> /F
```

#### Issue 3: "Cannot connect to database"
The app uses SQLite - no database setup needed. If you see this, check file permissions.

### Alternative: Use Docker

If local startup is problematic:

```bash
deploy-docker.bat
```

Docker handles all dependencies automatically!

### Still Not Working?

Try running just the OpenAI check:

```bash
python -c "from ai.real_ai_integration import RealAIIntegration; ai = RealAIIntegration(); print('OpenAI OK' if ai.use_real_ai else 'Using fallback')"
```

Then try loading the semantic detector:

```bash
python -c "from security.semantic_detector import SemanticThreatDetector; d = SemanticThreatDetector(); print(f'Loaded {len(d.attack_patterns)} patterns')"
```

This will show where it's stuck!

### Expected Timeline

- **0-5 seconds**: Flask app initializes
- **5-30 seconds**: SOC components load
- **30-180 seconds**: Semantic detector loads ML model (FIRST TIME ONLY)
- **Total**: 1-3 minutes first run, ~30 seconds subsequent runs

### Success Indicators

✅ You should see:
```
 * Running on http://0.0.0.0:5000
```

✅ Browser works:
- http://localhost:5000 shows the chat interface

✅ Health check works:
```bash
curl http://localhost:5000/health
# Returns: {"status":"healthy"...}
```

### If All Else Fails

**Simplest possible test**:

Create `test_simple.py`:
```python
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return "IT WORKS!"

if __name__ == '__main__':
    app.run(port=5000)
```

Run it:
```bash
python test_simple.py
```

If THIS works → the issue is with SOC components loading
If THIS fails → Flask installation issue

---

**TL;DR: Just wait 1-3 minutes for the semantic detector to load!** ⏳
