"""
Custom Exception Classes for SOC AI Agents

Provides specific exception types for better error handling and debugging.
"""


# =============================================================================
# BASE EXCEPTIONS
# =============================================================================

class SOCException(Exception):
    """Base exception for all SOC AI Agents errors."""
    pass


# =============================================================================
# SECURITY EXCEPTIONS
# =============================================================================

class SecurityException(SOCException):
    """Base exception for security-related errors."""
    pass


class ThreatDetectionError(SecurityException):
    """Error during threat detection processing."""
    pass


class PromptInjectionDetected(SecurityException):
    """Prompt injection attack detected."""
    def __init__(self, message: str, danger_score: float = 0.0, patterns_matched: list = None):
        super().__init__(message)
        self.danger_score = danger_score
        self.patterns_matched = patterns_matched or []


class DataExfiltrationDetected(SecurityException):
    """Data exfiltration attempt detected."""
    pass


class MaliciousInputDetected(SecurityException):
    """Malicious input detected."""
    pass


class BlockedIPError(SecurityException):
    """IP address has been blocked."""
    def __init__(self, ip_address: str, reason: str = "Security violation"):
        super().__init__(f"IP {ip_address} blocked: {reason}")
        self.ip_address = ip_address
        self.reason = reason


class BlockedUserError(SecurityException):
    """User account has been blocked."""
    def __init__(self, user_id: str, reason: str = "Security violation"):
        super().__init__(f"User {user_id} blocked: {reason}")
        self.user_id = user_id
        self.reason = reason


class BlockedSessionError(SecurityException):
    """Session has been terminated."""
    def __init__(self, session_id: str, reason: str = "Security violation"):
        super().__init__(f"Session {session_id} terminated: {reason}")
        self.session_id = session_id
        self.reason = reason


class RateLimitExceeded(SecurityException):
    """Rate limit exceeded."""
    def __init__(self, limit: int, window: str = "1 minute"):
        super().__init__(f"Rate limit exceeded: {limit} requests per {window}")
        self.limit = limit
        self.window = window


# =============================================================================
# AI INTEGRATION EXCEPTIONS
# =============================================================================

class AIException(SOCException):
    """Base exception for AI integration errors."""
    pass


class AIAPIError(AIException):
    """Error calling AI API (OpenAI, etc)."""
    pass


class AITimeoutError(AIException):
    """AI API request timeout."""
    pass


class AIRateLimitError(AIException):
    """AI API rate limit exceeded."""
    pass


class InvalidAIResponse(AIException):
    """AI returned invalid or unexpected response."""
    pass


# =============================================================================
# DATABASE EXCEPTIONS
# =============================================================================

class DatabaseException(SOCException):
    """Base exception for database errors."""
    pass


class ConnectionPoolExhausted(DatabaseException):
    """Database connection pool exhausted."""
    pass


class DatabaseTimeoutError(DatabaseException):
    """Database operation timeout."""
    pass


class InvalidDatabaseSchema(DatabaseException):
    """Database schema validation failed."""
    pass


# =============================================================================
# CONFIGURATION EXCEPTIONS
# =============================================================================

class ConfigurationException(SOCException):
    """Base exception for configuration errors."""
    pass


class MissingEnvironmentVariable(ConfigurationException):
    """Required environment variable not set."""
    def __init__(self, var_name: str):
        super().__init__(f"Required environment variable not set: {var_name}")
        self.var_name = var_name


class InvalidConfiguration(ConfigurationException):
    """Invalid configuration value."""
    pass


# =============================================================================
# VALIDATION EXCEPTIONS
# =============================================================================

class ValidationException(SOCException):
    """Base exception for validation errors."""
    pass


class InvalidInputError(ValidationException):
    """Input validation failed."""
    def __init__(self, field: str, reason: str):
        super().__init__(f"Invalid {field}: {reason}")
        self.field = field
        self.reason = reason


class SchemaValidationError(ValidationException):
    """JSON schema validation failed."""
    pass


class MessageTooLongError(ValidationException):
    """Message exceeds maximum length."""
    def __init__(self, length: int, max_length: int):
        super().__init__(f"Message too long: {length} characters (max: {max_length})")
        self.length = length
        self.max_length = max_length


# =============================================================================
# REMEDIATION EXCEPTIONS
# =============================================================================

class RemediationException(SOCException):
    """Base exception for remediation errors."""
    pass


class RemediationActionFailed(RemediationException):
    """Remediation action execution failed."""
    pass


class UnsupportedRemediationAction(RemediationException):
    """Remediation action not supported."""
    def __init__(self, action: str):
        super().__init__(f"Unsupported remediation action: {action}")
        self.action = action


class CloudProviderError(RemediationException):
    """Cloud provider API error during remediation."""
    pass


# =============================================================================
# AGENT EXCEPTIONS
# =============================================================================

class AgentException(SOCException):
    """Base exception for agent errors."""
    pass


class AgentInitializationError(AgentException):
    """Agent initialization failed."""
    pass


class AgentCommunicationError(AgentException):
    """Inter-agent communication failed."""
    pass


class AgentTimeoutError(AgentException):
    """Agent operation timeout."""
    pass


# =============================================================================
# WEB APPLICATION EXCEPTIONS
# =============================================================================

class WebApplicationException(SOCException):
    """Base exception for web application errors."""
    pass


class InvalidSessionError(WebApplicationException):
    """Invalid or expired session."""
    pass


class CSRFTokenError(WebApplicationException):
    """CSRF token validation failed."""
    pass


class WebSocketError(WebApplicationException):
    """WebSocket communication error."""
    pass


# =============================================================================
# CACHE EXCEPTIONS
# =============================================================================

class CacheException(SOCException):
    """Base exception for cache errors."""
    pass


class RedisConnectionError(CacheException):
    """Redis connection failed."""
    pass


class CacheKeyError(CacheException):
    """Invalid cache key."""
    pass
