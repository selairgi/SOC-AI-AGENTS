"""
Configuration constants and settings for SOC AI Agents.
"""

# -------------------- CONFIG --------------------
REAL_MODE = False  # If True, remediate for real (calls system commands). Default False -> dry-run
DRY_RUN = not REAL_MODE  # Explicit dry-run flag (opposite of REAL_MODE)
ALERT_QUEUE_MAX = 100
LOG_GENERATION_INTERVAL = 0.5  # seconds between generated logs
DEFAULT_RUN_DURATION = 10  # default seconds to run the demo when invoked from CLI

# Security settings
ENABLE_SCHEMA_VALIDATION = True  # Enable JSON schema validation for alerts/playbooks
ENABLE_ACTION_WHITELIST = True   # Enable action whitelist validation
ENABLE_INPUT_SANITIZATION = True # Enable input sanitization

# If you want to integrate an LLM for deeper triage, implement llm_verify_alert(alert) below
USE_LLM_FOR_TRIAGE = False

