# Exception Handling Improvement Guide

This guide documents how to replace broad `except Exception` handlers with specific exception types.

## 📚 Custom Exception Classes

All custom exceptions are defined in [shared/exceptions.py](shared/exceptions.py).

### Exception Hierarchy

```
SOCException (base)
├── SecurityException
│   ├── ThreatDetectionError
│   ├── PromptInjectionDetected
│   ├── DataExfiltrationDetected
│   ├── MaliciousInputDetected
│   ├── BlockedIPError
│   ├── BlockedUserError
│   ├── BlockedSessionError
│   └── RateLimitExceeded
├── AIException
│   ├── AIAPIError
│   ├── AITimeoutError
│   ├── AIRateLimitError
│   └── InvalidAIResponse
├── DatabaseException
│   ├── ConnectionPoolExhausted
│   ├── DatabaseTimeoutError
│   └── InvalidDatabaseSchema
├── ConfigurationException
│   ├── MissingEnvironmentVariable
│   └── InvalidConfiguration
├── ValidationException
│   ├── InvalidInputError
│   ├── SchemaValidationError
│   └── MessageTooLongError
├── RemediationException
│   ├── RemediationActionFailed
│   ├── UnsupportedRemediationAction
│   └── CloudProviderError
├── AgentException
│   ├── AgentInitializationError
│   ├── AgentCommunicationError
│   └── AgentTimeoutError
├── WebApplicationException
│   ├── InvalidSessionError
│   ├── CSRFTokenError
│   └── WebSocketError
└── CacheException
    ├── RedisConnectionError
    └── CacheKeyError
```

---

## 🔄 Replacement Patterns

### Pattern 1: AI Integration Errors

**Before** (Broad exception):
```python
try:
    ai_response = self.ai_integration.generate_response(...)
except Exception as e:
    self.logger.error(f"AI integration error: {e}", exc_info=True)
    result["response"] = "AI service unavailable"
```

**After** (Specific exceptions):
```python
from shared.exceptions import AIAPIError, AITimeoutError, AIRateLimitError

try:
    ai_response = self.ai_integration.generate_response(...)
except AITimeoutError as e:
    self.logger.error(f"AI request timeout: {e}")
    result["response"] = "AI service is taking too long. Please try again."
except AIRateLimitError as e:
    self.logger.warning(f"AI rate limit exceeded: {e}")
    result["response"] = "AI service is temporarily unavailable due to rate limits."
except AIAPIError as e:
    self.logger.error(f"AI API error: {e}", exc_info=True)
    result["response"] = "AI service error. Please try again later."
except Exception as e:
    # Catch unexpected errors
    self.logger.critical(f"Unexpected AI error: {e}", exc_info=True)
    result["response"] = "Unexpected error occurred."
```

---

### Pattern 2: Threat Detection Errors

**Before** (Broad exception):
```python
try:
    alert = self.intelligent_detector.detect_prompt_injection(temp_log)
except Exception as e:
    self.logger.warning(f"Intelligent detection error: {e}")
```

**After** (Specific exceptions):
```python
from shared.exceptions import ThreatDetectionError, PromptInjectionDetected

try:
    alert = self.intelligent_detector.detect_prompt_injection(temp_log)
except PromptInjectionDetected as e:
    # Re-raise to be caught by security handler
    raise
except ThreatDetectionError as e:
    self.logger.warning(f"Threat detection failed: {e}")
    alert = None  # Fall back to rule-based detection
except Exception as e:
    self.logger.error(f"Unexpected detection error: {e}", exc_info=True)
    alert = None
```

---

### Pattern 3: Database Errors

**Before** (Broad exception):
```python
try:
    with self._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(...)
        conn.commit()
except Exception as e:
    self.logger.error(f"Database error: {e}", exc_info=True)
```

**After** (Specific exceptions):
```python
import sqlite3
from shared.exceptions import DatabaseException, DatabaseTimeoutError, ConnectionPoolExhausted

try:
    with self._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(...)
        conn.commit()
except sqlite3.OperationalError as e:
    if "database is locked" in str(e).lower():
        raise DatabaseTimeoutError(f"Database locked: {e}")
    raise DatabaseException(f"Database operation failed: {e}")
except sqlite3.IntegrityError as e:
    self.logger.warning(f"Database integrity error: {e}")
    raise DatabaseException(f"Data integrity violation: {e}")
except ConnectionPoolExhausted as e:
    self.logger.error(f"Connection pool exhausted: {e}")
    raise
except Exception as e:
    self.logger.critical(f"Unexpected database error: {e}", exc_info=True)
    raise DatabaseException(f"Unexpected database error: {e}")
```

---

### Pattern 4: Configuration/Initialization Errors

**Before** (Broad exception):
```python
try:
    self.openai_client = openai.OpenAI(api_key=openai_api_key)
    self.analyst = SOCAnalyst(...)
    self.remediator = Remediator(...)
except Exception as e:
    self.logger.error(f"Failed to initialize: {e}", exc_info=True)
    raise
```

**After** (Specific exceptions):
```python
from shared.exceptions import (
    MissingEnvironmentVariable,
    InvalidConfiguration,
    AgentInitializationError,
    AIAPIError
)
import openai

try:
    if not openai_api_key:
        raise MissingEnvironmentVariable("OPENAI_API_KEY")

    self.openai_client = openai.OpenAI(api_key=openai_api_key)

except openai.APIError as e:
    raise AIAPIError(f"Failed to initialize OpenAI client: {e}")
except MissingEnvironmentVariable as e:
    self.logger.error(f"Configuration error: {e}")
    raise

try:
    self.analyst = SOCAnalyst(...)
    self.remediator = Remediator(...)
except (ValueError, TypeError) as e:
    raise AgentInitializationError(f"Invalid agent configuration: {e}")
except Exception as e:
    self.logger.critical(f"Unexpected initialization error: {e}", exc_info=True)
    raise AgentInitializationError(f"Failed to initialize agents: {e}")
```

---

### Pattern 5: Input Validation Errors

**Before** (Broad exception):
```python
try:
    if len(message) > 10000:
        raise ValueError("Message too long")
    # ... validation logic ...
except Exception as e:
    self.logger.error(f"Validation error: {e}")
    return {"error": "Invalid input"}
```

**After** (Specific exceptions):
```python
from shared.exceptions import InvalidInputError, MessageTooLongError
from shared.constants import MAX_MESSAGE_LENGTH

try:
    if len(message) > MAX_MESSAGE_LENGTH:
        raise MessageTooLongError(len(message), MAX_MESSAGE_LENGTH)

    if not user_id or len(user_id) > 256:
        raise InvalidInputError("user_id", "Must be 1-256 characters")

    # ... more validation ...

except (MessageTooLongError, InvalidInputError) as e:
    self.logger.warning(f"Input validation failed: {e}")
    return {"error": str(e), "blocked": True}
except Exception as e:
    self.logger.error(f"Unexpected validation error: {e}", exc_info=True)
    return {"error": "Validation failed"}
```

---

### Pattern 6: Remediation Errors

**Before** (Broad exception):
```python
try:
    if action_type == "block_ip":
        self._block_ip(ip_address)
    elif action_type == "terminate_session":
        self._terminate_session(session_id)
except Exception as e:
    self.logger.error(f"Remediation failed: {e}", exc_info=True)
```

**After** (Specific exceptions):
```python
from shared.exceptions import (
    RemediationActionFailed,
    UnsupportedRemediationAction,
    CloudProviderError
)

try:
    if action_type == "block_ip":
        self._block_ip(ip_address)
    elif action_type == "terminate_session":
        self._terminate_session(session_id)
    elif action_type == "cloud_firewall_block":
        self._cloud_firewall_block(ip_address)
    else:
        raise UnsupportedRemediationAction(action_type)

except CloudProviderError as e:
    self.logger.error(f"Cloud provider error during {action_type}: {e}")
    raise RemediationActionFailed(f"Cloud remediation failed: {e}")
except ValueError as e:
    raise RemediationActionFailed(f"Invalid remediation parameters: {e}")
except UnsupportedRemediationAction as e:
    self.logger.warning(f"Unsupported action: {e}")
    raise
except Exception as e:
    self.logger.critical(f"Unexpected remediation error: {e}", exc_info=True)
    raise RemediationActionFailed(f"Unexpected error during {action_type}: {e}")
```

---

## 🎯 Best Practices

### 1. **Order of Exception Handlers**
Always catch from **most specific to least specific**:
```python
try:
    ...
except SpecificError:      # Most specific first
    ...
except ParentError:        # Parent exceptions next
    ...
except Exception:          # Generic Exception last (if needed)
    ...
```

### 2. **When to Keep `except Exception`**
Keep broad exception handling **only** when:
- It's the last handler in a chain (catch-all)
- You're at a top-level boundary (e.g., main request handler)
- You log it as CRITICAL and re-raise or return error response
- You genuinely can't predict what might fail

**Example** (acceptable):
```python
try:
    # Complex operation with many potential failures
    result = complex_operation()
except KnownError1 as e:
    handle_known_error_1(e)
except KnownError2 as e:
    handle_known_error_2(e)
except Exception as e:
    # Last resort - log and fail gracefully
    self.logger.critical(f"Unexpected error: {e}", exc_info=True)
    return error_response("Internal error")
```

### 3. **Logging Levels**
- `logger.debug()`: Detailed diagnostic info
- `logger.info()`: Expected events (successful operations)
- `logger.warning()`: Handled errors, recoverable issues
- `logger.error()`: Unhandled errors requiring attention
- `logger.critical()`: System-level failures, data loss risk

**Exception logging**:
```python
except SpecificError as e:
    logger.warning(f"Handled error: {e}")  # Expected, handled

except UnexpectedError as e:
    logger.error(f"Error: {e}", exc_info=True)  # Unexpected, logged with traceback

except Exception as e:
    logger.critical(f"CRITICAL: {e}", exc_info=True)  # Should never happen
```

### 4. **Re-raising Exceptions**
```python
# Good - re-raise to let caller handle
except DatabaseError as e:
    logger.error(f"Database failed: {e}")
    raise  # Let caller decide what to do

# Good - wrap in more specific exception
except sqlite3.Error as e:
    raise DatabaseException(f"SQLite error: {e}") from e

# Bad - swallow exception silently
except DatabaseError as e:
    logger.error(f"Database failed: {e}")
    pass  # ❌ Never do this
```

---

## 📝 Files Requiring Updates

### High Priority (Production Critical)
1. ✅ `shared/exceptions.py` - Created custom exception classes
2. ⏸️ `web/security_pipeline.py` - 8 broad exception handlers
3. ⏸️ `security/intelligent_prompt_detector.py` - Detection errors
4. ⏸️ `web/app.py` - Flask route error handling
5. ⏸️ `core/soc_analyst.py` - Agent error handling
6. ⏸️ `ai/real_ai_integration.py` - AI API errors

### Medium Priority
7. ⏸️ `core/remediator.py` - Remediation errors
8. ⏸️ `shared/agent_memory.py` - Database errors
9. ⏸️ `shared/environment_config.py` - Configuration errors
10. ⏸️ `enterprise/auth_rbac.py` - Authentication errors

### Low Priority (Test/Utility Files)
- Test files can keep broad exception handling for simplicity
- Utility scripts may not need specific exceptions

---

## 🚀 Implementation Strategy

### Phase 1: Core Exception Classes ✅
- [x] Create `shared/exceptions.py` with comprehensive exception hierarchy

### Phase 2: Update Production Files (High Priority)
1. Update `web/security_pipeline.py` (security orchestration)
2. Update `ai/real_ai_integration.py` (AI integration)
3. Update `security/intelligent_prompt_detector.py` (threat detection)
4. Update `shared/agent_memory.py` (database operations)

### Phase 3: Update Supporting Files (Medium Priority)
5. Update `core/soc_analyst.py` (agent logic)
6. Update `core/remediator.py` (remediation)
7. Update `web/app.py` (Flask routes)
8. Update configuration/validation modules

### Phase 4: Testing & Verification
- Verify all exceptions are caught correctly
- Test error paths with specific exception types
- Update unit tests to verify exception types

---

## 📊 Progress Tracking

| File | Exception Count | Status | Priority |
|------|-----------------|--------|----------|
| `shared/exceptions.py` | N/A | ✅ Created | High |
| `web/security_pipeline.py` | 8 | ⏸️ Pending | High |
| `ai/real_ai_integration.py` | ? | ⏸️ Pending | High |
| `security/intelligent_prompt_detector.py` | ? | ⏸️ Pending | High |
| `shared/agent_memory.py` | ? | ⏸️ Pending | High |
| Other files (42) | ? | ⏸️ Pending | Medium/Low |

---

**Created**: 2025-12-14
**Last Updated**: 2025-12-14
**Status**: Phase 1 Complete, Phase 2 In Progress
