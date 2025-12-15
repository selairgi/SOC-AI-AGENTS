"""
Shared Constants for SOC AI Agents
Centralizes all magic numbers and configuration values
"""

# =============================================================================
# THREAT DETECTION THRESHOLDS
# =============================================================================

# Intelligent Prompt Detector Thresholds
DANGER_SCORE_THRESHOLD = 0.15  # Minimum score to consider dangerous
CERTAINTY_SCORE_THRESHOLD = 0.7  # Minimum certainty for high-confidence detection

# False Positive Analysis Thresholds
FALSE_POSITIVE_IGNORE_THRESHOLD = 0.95  # FP probability above which to ignore alert
FALSE_POSITIVE_BLOCK_PROMPT_INJECTION = 0.9  # FP threshold for blocking prompt injections
FALSE_POSITIVE_BLOCK_HIGH_SEVERITY = 0.7  # FP threshold for blocking high/critical threats

# Alert Severity Blocking Thresholds
MIN_SEVERITY_FOR_BLOCKING = "high"  # Minimum severity level that triggers automatic blocking

# =============================================================================
# RATE LIMITING
# =============================================================================

RATE_LIMIT_REQUESTS_PER_MINUTE = 10  # Default rate limit for API endpoints
RATE_LIMIT_BURST_SIZE = 20  # Maximum burst size for rate limiting

# =============================================================================
# DATABASE & CACHING
# =============================================================================

DATABASE_CONNECTION_POOL_SIZE = 5  # Number of database connections to maintain
DATABASE_TIMEOUT_SECONDS = 5.0  # Database operation timeout
MAX_CACHED_PATTERNS = 1000  # Maximum number of patterns to cache in memory
MAX_CACHED_ALERTS = 100  # Maximum number of alerts to store in memory
MAX_CHAT_HISTORY_PER_SESSION = 50  # Maximum chat messages to store per session

# =============================================================================
# REMEDIATION SETTINGS
# =============================================================================

DEFAULT_IP_BLOCK_DURATION_SECONDS = 3600  # 1 hour default IP block duration
SESSION_TERMINATION_DELAY_SECONDS = 0  # Delay before terminating session
CLEANUP_INTERVAL_SECONDS = 300  # 5 minutes - how often to clean up expired blocks

# =============================================================================
# INPUT VALIDATION
# =============================================================================

MAX_MESSAGE_LENGTH = 10000  # Maximum length of user message
MAX_USER_ID_LENGTH = 256  # Maximum length of user ID
MAX_SESSION_ID_LENGTH = 256  # Maximum length of session ID
MAX_IP_ADDRESS_LENGTH = 45  # Maximum length of IP address (IPv6)

# =============================================================================
# AI INTEGRATION
# =============================================================================

DEFAULT_AI_MODEL = "gpt-4o-mini"  # Default OpenAI model
DEFAULT_AI_MAX_TOKENS = 500  # Default max tokens for AI responses
DEFAULT_AI_TEMPERATURE = 0.7  # Default temperature for AI responses
AI_REQUEST_TIMEOUT_SECONDS = 30  # Timeout for AI API calls

# =============================================================================
# LOGGING & MONITORING
# =============================================================================

DEFAULT_RUN_DURATION_SECONDS = 10  # Default duration for SOC monitoring
LOG_GENERATION_INTERVAL_SECONDS = 0.5  # Interval between log generation
ALERT_QUEUE_MAX_SIZE = 100  # Maximum size of alert queue

# =============================================================================
# SECURITY RULES
# =============================================================================

# Prompt Injection Pattern Weights
PATTERN_WEIGHT_HIGH = 1.0  # Weight for high-confidence patterns
PATTERN_WEIGHT_MEDIUM = 0.6  # Weight for medium-confidence patterns
PATTERN_WEIGHT_LOW = 0.3  # Weight for low-confidence patterns

# Keyword Detection Weights
KEYWORD_WEIGHT_CRITICAL = 0.8  # Weight for critical keywords
KEYWORD_WEIGHT_SUSPICIOUS = 0.5  # Weight for suspicious keywords
KEYWORD_WEIGHT_CONTEXT = 0.3  # Weight for contextual keywords

# =============================================================================
# WEB APPLICATION
# =============================================================================

# CORS Settings
DEFAULT_CORS_ORIGINS = "http://localhost:5000"  # Default allowed origins

# Session Settings
SESSION_COOKIE_SECURE = True  # Require HTTPS for session cookies
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookies
SESSION_COOKIE_SAMESITE = "Lax"  # CSRF protection

# CSRF Token Settings
CSRF_TOKEN_LENGTH = 32  # Length of CSRF token in bytes

# =============================================================================
# FILE PATHS
# =============================================================================

DEFAULT_DB_PATH = "agent_memory.db"  # Default database file path
DEFAULT_LOGS_DIR = "logs"  # Default logs directory
DEFAULT_CACHE_DIR = ".cache"  # Default cache directory

# =============================================================================
# ERROR MESSAGES
# =============================================================================

ERROR_MESSAGE_GENERIC = "I apologize, but I encountered an error processing your request."
ERROR_MESSAGE_RATE_LIMIT = "Rate limit exceeded. Please wait before trying again."
ERROR_MESSAGE_BLOCKED_IP = "Access denied: Your IP address has been blocked due to security violations."
ERROR_MESSAGE_BLOCKED_USER = "Access denied: Your account has been suspended due to security violations."
ERROR_MESSAGE_BLOCKED_SESSION = "Access denied: Your session has been terminated due to security policy violations."
ERROR_MESSAGE_SECURITY_THREAT = "I cannot process this request due to security restrictions."
ERROR_MESSAGE_INVALID_INPUT = "Invalid input provided."

# =============================================================================
# SUCCESS MESSAGES
# =============================================================================

SUCCESS_MESSAGE_REMEDIATION_EXECUTED = "Remediation action executed successfully."
SUCCESS_MESSAGE_IP_UNBLOCKED = "IP address has been unblocked."
SUCCESS_MESSAGE_ALERT_PROCESSED = "Security alert processed successfully."
