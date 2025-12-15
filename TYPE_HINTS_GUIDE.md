# Type Hints Implementation Guide

This guide documents how to add comprehensive type hints to the SOC AI Agents codebase.

## 📚 Why Type Hints?

**Benefits**:
- **IDE Support**: Better autocomplete and IntelliSense
- **Early Error Detection**: Catch type errors before runtime
- **Documentation**: Types serve as inline documentation
- **Refactoring Safety**: Easier to refactor with type checking
- **Code Quality**: mypy/pyright can verify type correctness

---

## 🎯 Type Hint Strategy

### Coverage Goals
- **High Priority**: Public methods, API endpoints, core security logic
- **Medium Priority**: Internal methods, utility functions
- **Low Priority**: Test files (can omit for brevity)

### Tools
```bash
# Type checking
pip install mypy pyright

# Run type checker
mypy web/ core/ security/ shared/ ai/ --ignore-missing-imports
pyright web/ core/ security/ shared/ ai/
```

---

## 📝 Common Type Patterns

### Pattern 1: Basic Method Signatures

**Before**:
```python
def __init__(self, socketio=None):
    self.socketio = socketio
```

**After**:
```python
from typing import Optional
from flask_socketio import SocketIO

def __init__(self, socketio: Optional[SocketIO] = None) -> None:
    self.socketio = socketio
```

---

### Pattern 2: Return Types

**Before**:
```python
def process_chat_message(self, message: str, user_id: str, session_id: str, ...):
    result = {"response": "...", "blocked": False}
    return result
```

**After**:
```python
from typing import Dict, Any

def process_chat_message(
    self,
    message: str,
    user_id: str,
    session_id: str,
    user_ip: str = "127.0.0.1",
    security_mode: str = "security_aware",
    auto_remediation: bool = False
) -> Dict[str, Any]:
    result: Dict[str, Any] = {"response": "...", "blocked": False}
    return result
```

---

### Pattern 3: Lists and Dictionaries

**Before**:
```python
def get_alerts(self):
    return self.soc_alerts

def get_chat_history(self, session_id):
    return self.chat_history.get(session_id, [])
```

**After**:
```python
from typing import List, Dict, Optional
from shared.models import Alert

def get_alerts(self) -> List[Alert]:
    return self.soc_alerts

def get_chat_history(self, session_id: str) -> List[Dict[str, Any]]:
    return self.chat_history.get(session_id, [])
```

---

### Pattern 4: Optional Parameters

**Before**:
```python
def emit_alert(self, alert, metadata=None):
    if metadata is None:
        metadata = {}
    # ...
```

**After**:
```python
from typing import Optional, Dict, Any
from shared.models import Alert

def emit_alert(
    self,
    alert: Alert,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    if metadata is None:
        metadata = {}
    # ...
```

---

### Pattern 5: Async Functions

**Before**:
```python
async def _run_soc_components(self):
    await asyncio.gather(...)
```

**After**:
```python
async def _run_soc_components(self) -> None:
    await asyncio.gather(...)
```

---

### Pattern 6: Type Aliases for Complex Types

**Before**:
```python
def analyze_threat(self, log_entry: dict, context: dict) -> dict:
    # ...
```

**After** (Using type aliases):
```python
from typing import Dict, Any, TypedDict

# Define type alias
class ThreatContext(TypedDict):
    user_id: str
    session_id: str
    ip_address: str
    timestamp: float

class ThreatResult(TypedDict):
    is_threat: bool
    severity: str
    confidence: float
    patterns_matched: List[str]

def analyze_threat(
    self,
    log_entry: Dict[str, Any],
    context: ThreatContext
) -> ThreatResult:
    # ...
```

---

### Pattern 7: Union Types

**Before**:
```python
def get_config_value(self, key):
    # Returns str, int, bool, or None
    return self.config.get(key)
```

**After**:
```python
from typing import Union, Optional

def get_config_value(self, key: str) -> Union[str, int, bool, None]:
    return self.config.get(key)

# OR using Python 3.10+ syntax:
def get_config_value(self, key: str) -> str | int | bool | None:
    return self.config.get(key)
```

---

### Pattern 8: Callable Types

**Before**:
```python
def register_callback(self, callback):
    self.callbacks.append(callback)
```

**After**:
```python
from typing import Callable, List

def register_callback(
    self,
    callback: Callable[[str, Dict[str, Any]], None]
) -> None:
    self.callbacks.append(callback)

# OR for complex callbacks, define a Protocol:
from typing import Protocol

class AlertCallback(Protocol):
    def __call__(self, alert: Alert, metadata: Dict[str, Any]) -> None:
        ...

def register_callback(self, callback: AlertCallback) -> None:
    self.callbacks.append(callback)
```

---

### Pattern 9: Generic Types

**Before**:
```python
class Cache:
    def get(self, key):
        return self._cache.get(key)

    def set(self, key, value):
        self._cache[key] = value
```

**After**:
```python
from typing import Generic, TypeVar, Optional, Dict

T = TypeVar('T')

class Cache(Generic[T]):
    def __init__(self) -> None:
        self._cache: Dict[str, T] = {}

    def get(self, key: str) -> Optional[T]:
        return self._cache.get(key)

    def set(self, key: str, value: T) -> None:
        self._cache[key] = value

# Usage:
alert_cache: Cache[Alert] = Cache()
string_cache: Cache[str] = Cache()
```

---

### Pattern 10: Class Attributes with Types

**Before**:
```python
class SecureSOCWebIntegration:
    def __init__(self):
        self.soc_enabled = True
        self.active_sessions = {}
        self.chat_history = {}
        self.soc_alerts = []
```

**After**:
```python
from typing import Dict, List, Any
from shared.models import Alert

class SecureSOCWebIntegration:
    soc_enabled: bool
    active_sessions: Dict[str, Dict[str, Any]]
    chat_history: Dict[str, List[Dict[str, Any]]]
    soc_alerts: List[Alert]

    def __init__(self) -> None:
        self.soc_enabled = True
        self.active_sessions = {}
        self.chat_history = {}
        self.soc_alerts = []
```

---

## 📂 File-Specific Type Hints

### web/security_pipeline.py

```python
from typing import Dict, Any, Optional, List, Tuple
from flask_socketio import SocketIO
from shared.models import Alert, LogEntry

class SecureSOCWebIntegration:
    def __init__(self, socketio: Optional[SocketIO] = None) -> None: ...

    def start_soc_monitoring(self) -> None: ...

    async def _run_soc_components(self) -> None: ...

    def process_chat_message(
        self,
        message: str,
        user_id: str,
        session_id: str,
        user_ip: str = "127.0.0.1",
        security_mode: str = "security_aware",
        auto_remediation: bool = False
    ) -> Dict[str, Any]: ...

    def _take_remediation_action(
        self,
        alert: Alert,
        user_id: str,
        session_id: str,
        user_ip: str,
        auto_remediation: bool
    ) -> Tuple[str, str]: ...

    def _emit_workflow_log(
        self,
        step: str,
        status: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None: ...

    def _emit_security_alert(
        self,
        alert: Alert,
        fp_score: float,
        user_ip: str,
        remediation_status: Optional[str] = None
    ) -> None: ...

    def _store_chat_history(
        self,
        session_id: str,
        message: str,
        result: Dict[str, Any]
    ) -> None: ...

    def toggle_soc(self, enabled: bool) -> Dict[str, Any]: ...

    def get_statistics(self) -> Dict[str, Any]: ...
```

---

### ai/real_ai_integration.py

```python
from typing import Dict, Any, Optional, List

class RealAIIntegration:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-3.5-turbo"
    ) -> None: ...

    def generate_response(
        self,
        prompt: str,
        user_id: str,
        session_id: str,
        security_mode: str = "security_aware",
        max_tokens: int = 500,
        temperature: float = 0.7
    ) -> Dict[str, Any]: ...

    def analyze_security_threat(
        self,
        log_entry: Dict[str, Any],
        alert: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]: ...
```

---

### security/intelligent_prompt_detector.py

```python
from typing import Dict, Any, Optional, List, Tuple
from shared.models import Alert, LogEntry

class IntelligentPromptDetector:
    def __init__(self, ai_integration: Any) -> None: ...

    def detect_prompt_injection(
        self,
        log_entry: LogEntry
    ) -> Optional[Alert]: ...

    def _calculate_danger_score(
        self,
        message: str
    ) -> Tuple[float, List[str], float]: ...

    def _check_patterns(
        self,
        message: str
    ) -> Tuple[float, List[str]]: ...

    def _check_keywords(
        self,
        message: str
    ) -> Tuple[float, List[str]]: ...
```

---

### shared/agent_memory.py

```python
from typing import Dict, Any, Optional, List
from contextlib import contextmanager
import sqlite3

class AgentMemory:
    def __init__(
        self,
        db_path: str = "agent_memory.db",
        pool_size: int = 5
    ) -> None: ...

    @contextmanager
    def _get_connection(self) -> sqlite3.Connection: ...

    def store_prompt_injection_pattern(
        self,
        pattern: str,
        severity: str,
        description: str
    ) -> None: ...

    def get_all_patterns(self) -> List[Dict[str, Any]]: ...

    def store_alert_decision(
        self,
        alert_id: str,
        decision: str,
        reasoning: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None: ...
```

---

## 🚀 Implementation Checklist

### Phase 1: Core Security Files ✅
- [ ] `web/security_pipeline.py` (10 methods)
- [ ] `security/intelligent_prompt_detector.py` (8 methods)
- [ ] `ai/real_ai_integration.py` (6 methods)
- [ ] `security/false_positive_detector.py` (5 methods)

### Phase 2: Database & Utilities
- [ ] `shared/agent_memory.py` (15 methods)
- [ ] `shared/environment_config.py` (8 methods)
- [ ] `shared/message_bus.py` (6 methods)
- [ ] `shared/schema_validator.py` (4 methods)

### Phase 3: Core Agents
- [ ] `core/soc_analyst.py` (10 methods)
- [ ] `core/remediator.py` (8 methods)
- [ ] `core/soc_agent_builder.py` (6 methods)

### Phase 4: Web Application
- [ ] `web/app.py` (Flask routes - 20+ endpoints)

---

## 🧪 Type Checking Configuration

### mypy.ini
```ini
[mypy]
python_version = 3.11
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = False  # Set to True when fully typed
ignore_missing_imports = True

[mypy-tests.*]
ignore_errors = True
```

### pyproject.toml (for pyright)
```toml
[tool.pyright]
pythonVersion = "3.11"
typeCheckingMode = "basic"
reportMissingTypeStubs = false
reportUnknownMemberType = false
exclude = ["tests/", "venv/"]
```

---

## 📊 Progress Tracking

| File | Methods | Type Hints Added | Status |
|------|---------|------------------|--------|
| `web/security_pipeline.py` | 10 | 0/10 | ⏸️ Pending |
| `ai/real_ai_integration.py` | 6 | 0/6 | ⏸️ Pending |
| `security/intelligent_prompt_detector.py` | 8 | 0/8 | ⏸️ Pending |
| `shared/agent_memory.py` | 15 | 0/15 | ⏸️ Pending |
| `core/soc_analyst.py` | 10 | 0/10 | ⏸️ Pending |
| Other files | ~100+ | 0/100+ | ⏸️ Pending |

**Total Estimated**: ~150+ methods requiring type hints

---

## 💡 Best Practices

1. **Start with Return Types**: Always add return types first (easiest)
2. **Add Parameter Types**: Then add parameter types
3. **Use Type Aliases**: For complex nested types, create type aliases
4. **Leverage IDE**: Let IDE auto-suggest types from usage
5. **Run Type Checker**: Use mypy/pyright to verify correctness
6. **Document Complex Types**: Add docstring for non-obvious types
7. **Gradual Typing**: Start with high-priority files, expand gradually
8. **Use `Any` Sparingly**: Only when type truly unknown
9. **Prefer Protocols**: Over inheritance for duck-typing
10. **Keep It Simple**: Don't over-complicate with too specific types

---

**Created**: 2025-12-14
**Status**: Guide Created - Implementation Pending
**Estimated Effort**: 4-6 hours for Phase 1-3, 8-10 hours for full codebase
