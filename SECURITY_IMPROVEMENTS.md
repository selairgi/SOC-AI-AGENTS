# SOC AI Agents Security Improvements

This document describes the comprehensive security improvements implemented for the SOC AI Agents system.

## Overview

The security improvements address five critical areas:

1. **Structured Actions (Canonical)** - Modern action format with legacy support
2. **Action Whitelist & Validation** - Comprehensive action security
3. **Dry-Run Gating** - Protection against high-risk operations
4. **Schema Validation** - Data integrity and format validation
5. **Input Sanitization** - Prevention of shell injection attacks

## 1. Structured Actions (Canonical)

### Implementation
- Actions are now stored in `playbook.metadata["actions"]` as a list of strings
- Legacy `playbook.target` is maintained for backward compatibility
- The remediator reads `metadata["actions"]` first, falling back to `target.split(",")` if metadata is missing

### Benefits
- **Type Safety**: Actions are explicitly structured as lists
- **Extensibility**: Easy to add metadata to individual actions
- **Backward Compatibility**: Existing systems continue to work
- **Validation**: Each action can be individually validated

### Example Usage

```python
# New structured format
playbook = Playbook(
    action="multi_action",
    target="",  # Legacy field
    justification="Security response",
    metadata={
        "actions": [
            "block_ip:192.168.1.100",
            "suspend_user:user123",
            "initiate_forensics"
        ]
    }
)

# Legacy format still works
playbook_legacy = Playbook(
    action="multi_action",
    target="block_ip:192.168.1.100,suspend_user:user123",
    justification="Security response"
)
```

## 2. Action Whitelist & Validation

### Implementation
- Comprehensive whitelist of allowed actions in `security_config.py`
- Parameter validation for each action type (IP addresses, user IDs, etc.)
- Risk level classification for actions
- Real-time validation during execution

### Security Features
- **Whitelist Enforcement**: Only pre-approved actions can execute
- **Parameter Validation**: IP addresses, user IDs, and other parameters are validated
- **Risk Classification**: Actions are categorized by risk level
- **Format Validation**: Strict format requirements for all parameters

### Supported Actions

| Action | Risk Level | Requires Real Mode | Description |
|--------|------------|-------------------|-------------|
| `block_ip` | HIGH | Yes | Block an IP address |
| `suspend_user` | HIGH | Yes | Suspend a user account |
| `isolate_agent` | CRITICAL | Yes | Isolate an AI agent |
| `rate_limit_ip` | MEDIUM | Yes | Apply rate limiting to IP |
| `rate_limit_user` | MEDIUM | Yes | Apply rate limiting to user |
| `flag_user` | MEDIUM | No | Flag user for review |
| `initiate_forensics` | MEDIUM | Yes | Start forensic investigation |
| `enable_enhanced_monitoring` | LOW | Yes | Enable enhanced monitoring |
| `notify_compliance_team` | LOW | No | Notify compliance team |
| `require_human_review` | LOW | No | Require human review |

### Validation Examples

```python
# Valid actions
"block_ip:192.168.1.100"     # Valid IP
"suspend_user:user123"        # Valid user ID
"initiate_forensics"         # No parameters needed

# Invalid actions (blocked)
"unknown_action:target"      # Not in whitelist
"block_ip:invalid_ip"        # Invalid IP format
"suspend_user:user;rm -rf /" # Invalid user ID format
```

## 3. Dry-Run Gating

### Implementation
- Explicit `DRY_RUN` flag in configuration
- High-risk actions are blocked when `DRY_RUN=True`
- Comprehensive logging of blocked actions
- Statistics tracking for dry-run operations

### Security Features
- **High-Risk Protection**: Destructive operations blocked in dry-run
- **Explicit Mode Control**: Clear distinction between dry-run and real mode
- **Audit Trail**: All blocked actions are logged
- **Statistics**: Track dry-run vs real execution

### Configuration

```python
# config.py
REAL_MODE = False  # If True, execute real operations
DRY_RUN = not REAL_MODE  # Explicit dry-run flag
```

### High-Risk Actions (Blocked in Dry-Run)
- `block_ip` - Network blocking
- `suspend_user` - User account suspension
- `isolate_agent` - Agent isolation
- `iptables` - Firewall modifications

### Example Behavior

```python
# In dry-run mode (DRY_RUN=True)
action = "block_ip:192.168.1.100"
# Result: Action blocked, logged as "[DRY-RUN] Blocked high-risk action"

# In real mode (REAL_MODE=True)
action = "block_ip:192.168.1.100"
# Result: Action executed (if validation passes)
```

## 4. Schema Validation

### Implementation
- JSON Schema validation for alerts and playbooks
- Comprehensive field validation
- Type checking and format validation
- Early rejection of malformed data

### Schema Features
- **Alert Validation**: ID format, severity levels, threat types
- **Playbook Validation**: Action format, parameter structure
- **Log Entry Validation**: Source format, timestamp validation
- **Custom Schemas**: Support for additional schema types

### Validation Rules

#### Alert Schema
```json
{
  "id": "string (alphanumeric, 1-100 chars)",
  "timestamp": "number (>= 0)",
  "severity": "enum [low, medium, high, critical]",
  "title": "string (1-200 chars)",
  "description": "string (1-1000 chars)",
  "threat_type": "enum [prompt_injection, data_exfiltration, ...]",
  "agent_id": "string (optional, alphanumeric)",
  "evidence": "object (optional)"
}
```

#### Playbook Schema
```json
{
  "action": "string (1-50 chars)",
  "target": "string (max 500 chars)",
  "justification": "string (1-1000 chars)",
  "owner": "string (alphanumeric, max 100 chars)",
  "metadata": {
    "actions": "array of strings (max 20 items)",
    "alert_id": "string (alphanumeric)"
  }
}
```

### Usage

```python
# Enable schema validation
ENABLE_SCHEMA_VALIDATION = True

# Validation happens automatically in SOCAnalyst
analyst = SOCAnalyst(bus, remediator_queue)
# Alerts and playbooks are validated before processing
```

## 5. Input Sanitization

### Implementation
- Comprehensive input sanitization to prevent shell injection
- Removal of dangerous characters
- Length limiting
- Safe parameter passing

### Security Features
- **Shell Injection Prevention**: Dangerous characters removed
- **Length Limiting**: Inputs limited to 1000 characters
- **Character Filtering**: Removal of `;`, `&`, `|`, `` ` ``, `$`, `()`, `<>`, `"'`, `\`, newlines
- **Safe Subprocess**: All subprocess calls use argument lists, never shell strings

### Sanitization Rules

```python
# Dangerous characters removed
dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\', '\n', '\r']

# Examples
"192.168.1.100; rm -rf /" → "192.168.1.100 rm -rf "
"user123 & cat /etc/passwd" → "user123  cat /etc/passwd"
"agent_456 | nc -l 8080" → "agent_456  nc -l 8080"
```

### Safe Subprocess Usage

```python
# ❌ UNSAFE - Shell injection possible
subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True)

# ✅ SAFE - Arguments as list
subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
```

## Configuration

### Security Settings

```python
# config.py
REAL_MODE = False                    # Real operations disabled by default
DRY_RUN = not REAL_MODE             # Explicit dry-run flag
ENABLE_SCHEMA_VALIDATION = True     # Enable JSON schema validation
ENABLE_ACTION_WHITELIST = True      # Enable action whitelist
ENABLE_INPUT_SANITIZATION = True    # Enable input sanitization
```

## Testing

### Test Suite
Comprehensive test suite in `test_security_improvements.py` covers:

1. **Structured Actions**: New format and legacy support
2. **Action Whitelist**: Valid/invalid action validation
3. **Dry-Run Gating**: High-risk action blocking
4. **Schema Validation**: Alert and playbook validation
5. **Input Sanitization**: Shell injection prevention
6. **Integration**: End-to-end security workflow

### Running Tests

```bash
python test_security_improvements.py
```

### Test Coverage
- ✅ Structured actions with metadata support
- ✅ Legacy target format fallback
- ✅ Action whitelist validation
- ✅ Parameter format validation
- ✅ Dry-run high-risk action blocking
- ✅ Schema validation for alerts/playbooks
- ✅ Input sanitization and shell injection prevention
- ✅ Unknown action rejection
- ✅ Integration scenario testing

## Security Benefits

### 1. Defense in Depth
- Multiple layers of security validation
- Fail-safe defaults (dry-run mode)
- Comprehensive input sanitization

### 2. Audit Trail
- All security decisions are logged
- Execution statistics tracked
- Validation failures recorded

### 3. Operational Safety
- High-risk operations require explicit real mode
- Unknown actions are rejected
- Malformed data is rejected early

### 4. Extensibility
- Easy to add new actions to whitelist
- Custom validation rules supported
- Schema evolution capabilities

## Production Deployment

### Security Checklist
- [ ] Set `REAL_MODE = False` for initial deployment
- [ ] Enable all security features (`ENABLE_* = True`)
- [ ] Review action whitelist for your environment
- [ ] Test with dry-run mode first
- [ ] Monitor execution statistics
- [ ] Set up alerting for validation failures

### Monitoring
- Track execution statistics via `remediator.get_execution_stats()`
- Monitor validation failure rates
- Alert on unknown action attempts
- Log all dry-run blocked actions

## Conclusion

These security improvements provide comprehensive protection for the SOC AI Agents system:

1. **Structured Actions** ensure type safety and extensibility
2. **Action Whitelist** prevents unauthorized operations
3. **Dry-Run Gating** protects against accidental damage
4. **Schema Validation** ensures data integrity
5. **Input Sanitization** prevents injection attacks

The system now provides enterprise-grade security while maintaining backward compatibility and operational flexibility.
