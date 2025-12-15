# How to Unblock an IP Address

There are multiple ways to unblock an IP address in the SOC AI Agents system.

---

## Method 1: Using the Python Script (Easiest) ✅

### List All Blocked IPs
```bash
python unblock_ip.py --list
```

**Output**:
```
Currently blocked IP addresses:
======================================================================

📍 IP: 192.168.1.100
   Reason: Prompt injection detected
   Blocked at: 2025-12-13 19:00:00
   Duration: 3600 seconds
   Alert ID: alert_12345
```

### Unblock a Specific IP
```bash
python unblock_ip.py 192.168.1.100
```

**Output**:
```
Attempting to unblock IP: 192.168.1.100
✓ IP 192.168.1.100 is currently blocked
  Blocked at: 2025-12-13 19:00:00
  Reason: Prompt injection detected

✅ Successfully unblocked IP: 192.168.1.100
```

---

## Method 2: Via Web UI (When Available)

1. Open the web interface: http://localhost:5000

2. Navigate to the **Remediation** tab/panel

3. Look for the blocked IP in the list of active remediations

4. Click **Remove** or **Undo** on that remediation action

**Note**: The UI method depends on the remediation panel being implemented in the frontend.

---

## Method 3: Direct Python Code

If you need to unblock IPs programmatically:

```python
from security.real_remediation import RealRemediationEngine

# Initialize the engine
engine = RealRemediationEngine()

# Unblock an IP
ip_to_unblock = "192.168.1.100"
if engine.unblock_ip(ip_to_unblock):
    print(f"✅ Successfully unblocked {ip_to_unblock}")
else:
    print(f"❌ IP {ip_to_unblock} was not blocked")
```

---

## Method 4: Check Current Blocks

To see what IPs are currently blocked:

```python
from security.real_remediation import RealRemediationEngine

engine = RealRemediationEngine()

# Print all blocked IPs
for ip, info in engine.blocked_ips.items():
    print(f"IP: {ip}")
    print(f"  Reason: {info.get('reason')}")
    print(f"  Blocked at: {info.get('timestamp')}")
    print()
```

---

## Method 5: Automatic Expiration

**Temporary blocks expire automatically!**

If an IP was blocked with a duration (e.g., 1 hour), it will be automatically unblocked when the duration expires.

The system has a cleanup thread that runs periodically to remove expired blocks.

---

## Common Use Cases

### Case 1: You Blocked Yourself During Testing
```bash
# Find your IP in the blocked list
python unblock_ip.py --list

# Unblock your IP
python unblock_ip.py YOUR_IP_ADDRESS
```

### Case 2: False Positive Detection
If the system incorrectly blocked a legitimate user:

```bash
python unblock_ip.py 10.0.0.50
```

### Case 3: After CTF Testing
After running the CTF tests, you might want to clear all blocks:

```python
from security.real_remediation import RealRemediationEngine

engine = RealRemediationEngine()

# Unblock all IPs
for ip in list(engine.blocked_ips.keys()):
    engine.unblock_ip(ip)
    print(f"Unblocked: {ip}")
```

---

## Understanding IP Blocking

### When IPs Get Blocked

IPs are automatically blocked when:
1. **Critical security alerts** are detected
2. **Prompt injection attempts** are identified
3. **Auto-remediation** is enabled and triggers on high-severity threats
4. **Manual blocking** via remediation actions

### Block Information

Each blocked IP stores:
- **IP address**: The blocked IP
- **Reason**: Why it was blocked
- **Timestamp**: When it was blocked
- **Duration**: How long the block lasts (None = permanent)
- **Alert ID**: Associated security alert (if any)

### Block Duration

- **Temporary blocks**: Automatically expire after the specified duration
- **Permanent blocks**: Last until manually removed
- **Default duration**: Configured in the remediation engine settings

---

## Troubleshooting

### "IP not blocked" Message

If you try to unblock an IP that isn't blocked:
```
ℹ IP 192.168.1.100 is not currently blocked
```

**Solutions**:
1. Check if the IP was already unblocked
2. Verify you have the correct IP address
3. Run `python unblock_ip.py --list` to see what's actually blocked

### Script Import Errors

If you get import errors:
```bash
# Make sure you're in the project directory
cd "c:\Users\salah\Desktop\SOC AI agents cursor"

# Then run the script
python unblock_ip.py --list
```

### Permission Issues

The script needs access to the same data the web server uses. Make sure:
- The web server isn't running, OR
- The blocks are stored in a shared location (database/file)

---

## Quick Reference

**List blocked IPs**: `python unblock_ip.py --list`

**Unblock specific IP**: `python unblock_ip.py <IP_ADDRESS>`

**Example**: `python unblock_ip.py 192.168.1.100`

---

## Advanced: Create an API Endpoint

If you want to add an API endpoint for unblocking, you can add this to [web/app.py](web/app.py):

```python
@app.route('/api/remediation/unblock', methods=['POST'])
@csrf.exempt
def unblock_ip_api():
    """API endpoint to unblock an IP address"""
    data = request.json
    ip_address = data.get('ip_address')

    if not ip_address:
        return jsonify({"error": "IP address required"}), 400

    if remediation_engine.unblock_ip(ip_address):
        return jsonify({
            "success": True,
            "message": f"Successfully unblocked IP: {ip_address}"
        })
    else:
        return jsonify({
            "success": False,
            "message": f"IP {ip_address} was not blocked"
        }), 404
```

Then you can unblock via curl:
```bash
curl -X POST http://localhost:5000/api/remediation/unblock \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100"}'
```

---

**Created**: 2025-12-13
**Script**: [unblock_ip.py](unblock_ip.py)
**Remediation Engine**: [security/real_remediation.py](security/real_remediation.py)
