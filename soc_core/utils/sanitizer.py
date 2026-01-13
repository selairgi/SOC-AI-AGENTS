"""
Input Sanitizer - Security validation for remediation inputs.

Prevents command injection and validates action parameters.
"""

import re
import ipaddress
import logging
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    sanitized_value: str
    errors: List[str]
    warnings: List[str]


class InputSanitizer:
    """
    Sanitizes and validates inputs for remediation actions.

    Features:
    - Shell injection prevention
    - IP address validation
    - User ID validation
    - Path traversal prevention
    - Action whitelisting
    """

    # Dangerous characters for shell injection
    DANGEROUS_CHARS = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\', '\n', '\r']

    # Allowed actions
    ALLOWED_ACTIONS: Set[str] = {
        "block_ip", "unblock_ip",
        "disable_account", "enable_account",
        "isolate_system", "restore_system",
        "kill_process", "quarantine_file",
        "reset_password", "revoke_tokens",
        "notify", "escalate", "monitor", "dismiss"
    }

    # Localhost IPs that should never be blocked
    PROTECTED_IPS: Set[str] = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}

    # Maximum input lengths
    MAX_LENGTHS = {
        "ip": 45,  # IPv6 max
        "user": 256,
        "host": 253,
        "path": 4096,
        "default": 1000
    }

    def __init__(
        self,
        strict_mode: bool = True,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize sanitizer.

        Args:
            strict_mode: If True, reject any suspicious input
        """
        self.strict_mode = strict_mode
        self.logger = logger or logging.getLogger("Sanitizer")

    def sanitize_string(
        self,
        value: str,
        max_length: int = 1000,
        allow_special: bool = False
    ) -> ValidationResult:
        """
        Sanitize a generic string input.

        Args:
            value: Input string
            max_length: Maximum allowed length
            allow_special: Allow special characters

        Returns:
            ValidationResult with sanitized value
        """
        errors = []
        warnings = []

        if not isinstance(value, str):
            value = str(value)

        # Trim whitespace
        sanitized = value.strip()

        # Check length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
            warnings.append(f"Truncated to {max_length} chars")

        # Remove dangerous characters
        if not allow_special:
            original = sanitized
            for char in self.DANGEROUS_CHARS:
                sanitized = sanitized.replace(char, '')

            if sanitized != original:
                if self.strict_mode:
                    errors.append("Contains dangerous characters")
                else:
                    warnings.append("Removed dangerous characters")

        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=sanitized,
            errors=errors,
            warnings=warnings
        )

    def validate_ip(self, ip: str) -> ValidationResult:
        """
        Validate and sanitize IP address.

        Args:
            ip: IP address string

        Returns:
            ValidationResult
        """
        errors = []
        warnings = []

        # Basic sanitization
        sanitized = ip.strip().lower()

        # Check if localhost
        if sanitized in self.PROTECTED_IPS:
            errors.append(f"Protected IP address: {sanitized}")
            return ValidationResult(False, sanitized, errors, warnings)

        # Validate IP format
        try:
            ip_obj = ipaddress.ip_address(sanitized)

            # Check for private/local IPs
            if ip_obj.is_private:
                warnings.append("Private IP address")
            if ip_obj.is_loopback:
                errors.append("Loopback address not allowed")
            if ip_obj.is_link_local:
                warnings.append("Link-local address")

        except ValueError:
            errors.append(f"Invalid IP address format: {sanitized}")

        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=sanitized,
            errors=errors,
            warnings=warnings
        )

    def validate_user_id(self, user_id: str) -> ValidationResult:
        """
        Validate user ID.

        Args:
            user_id: User identifier

        Returns:
            ValidationResult
        """
        errors = []
        warnings = []

        # Sanitize
        result = self.sanitize_string(user_id, self.MAX_LENGTHS["user"])
        sanitized = result.sanitized_value
        errors.extend(result.errors)
        warnings.extend(result.warnings)

        # Check format (alphanumeric, underscores, hyphens, dots, @)
        if sanitized and not re.match(r'^[\w\-\.@]+$', sanitized):
            errors.append("Invalid characters in user ID")

        # Protected users
        protected = {"root", "admin", "administrator", "system", "service"}
        if sanitized.lower() in protected:
            warnings.append(f"Protected user account: {sanitized}")

        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=sanitized,
            errors=errors,
            warnings=warnings
        )

    def validate_hostname(self, hostname: str) -> ValidationResult:
        """
        Validate hostname.

        Args:
            hostname: Hostname string

        Returns:
            ValidationResult
        """
        errors = []
        warnings = []

        # Sanitize
        result = self.sanitize_string(hostname, self.MAX_LENGTHS["host"])
        sanitized = result.sanitized_value.lower()
        errors.extend(result.errors)
        warnings.extend(result.warnings)

        # Validate format
        if sanitized:
            # Check valid hostname pattern
            pattern = r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$'
            if not re.match(pattern, sanitized):
                errors.append("Invalid hostname format")

        # Check for localhost
        if sanitized in {"localhost", "localhost.localdomain"}:
            warnings.append("Localhost hostname")

        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=sanitized,
            errors=errors,
            warnings=warnings
        )

    def validate_path(self, path: str) -> ValidationResult:
        """
        Validate file path (prevent traversal attacks).

        Args:
            path: File path

        Returns:
            ValidationResult
        """
        errors = []
        warnings = []

        # Sanitize
        result = self.sanitize_string(path, self.MAX_LENGTHS["path"])
        sanitized = result.sanitized_value
        errors.extend(result.errors)
        warnings.extend(result.warnings)

        # Check for path traversal
        if ".." in sanitized:
            errors.append("Path traversal detected")

        # Check for absolute paths in restricted areas
        dangerous_paths = ["/etc", "/root", "/var/log", "C:\\Windows", "C:\\System"]
        for dp in dangerous_paths:
            if sanitized.lower().startswith(dp.lower()):
                warnings.append(f"Sensitive path: {dp}")

        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=sanitized,
            errors=errors,
            warnings=warnings
        )

    def validate_action(self, action: str) -> ValidationResult:
        """
        Validate action type against whitelist.

        Args:
            action: Action name

        Returns:
            ValidationResult
        """
        errors = []
        warnings = []

        sanitized = action.strip().lower()

        if sanitized not in self.ALLOWED_ACTIONS:
            errors.append(f"Action not in whitelist: {sanitized}")
            errors.append(f"Allowed: {', '.join(sorted(self.ALLOWED_ACTIONS))}")

        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=sanitized,
            errors=errors,
            warnings=warnings
        )

    def validate_target(
        self,
        action: str,
        target: Dict[str, str]
    ) -> Tuple[bool, Dict[str, str], List[str]]:
        """
        Validate target parameters for an action.

        Args:
            action: Action type
            target: Target parameters dict

        Returns:
            Tuple of (is_valid, sanitized_target, errors)
        """
        all_errors = []
        sanitized = {}

        # Validate based on action type
        if action in ("block_ip", "unblock_ip"):
            ip = target.get("ip") or target.get("source_ip", "")
            result = self.validate_ip(ip)
            sanitized["ip"] = result.sanitized_value
            all_errors.extend(result.errors)

        elif action in ("disable_account", "enable_account", "reset_password", "revoke_tokens"):
            user = target.get("user") or target.get("username", "")
            result = self.validate_user_id(user)
            sanitized["user"] = result.sanitized_value
            all_errors.extend(result.errors)

        elif action in ("isolate_system", "restore_system"):
            host = target.get("host") or target.get("hostname", "")
            result = self.validate_hostname(host)
            sanitized["host"] = result.sanitized_value
            all_errors.extend(result.errors)

        elif action == "quarantine_file":
            path = target.get("file_path", "")
            result = self.validate_path(path)
            sanitized["file_path"] = result.sanitized_value
            all_errors.extend(result.errors)

        elif action == "kill_process":
            pid = target.get("pid", "")
            if pid and not str(pid).isdigit():
                all_errors.append("Invalid PID")
            sanitized["pid"] = str(pid) if str(pid).isdigit() else ""

        else:
            # Generic sanitization for other actions
            for key, value in target.items():
                result = self.sanitize_string(str(value))
                sanitized[key] = result.sanitized_value
                all_errors.extend(result.errors)

        return len(all_errors) == 0, sanitized, all_errors

    def is_safe_to_block(self, ip: str) -> Tuple[bool, str]:
        """
        Check if IP is safe to block (not localhost/protected).

        Args:
            ip: IP address

        Returns:
            Tuple of (is_safe, reason)
        """
        result = self.validate_ip(ip)

        if not result.is_valid:
            return False, "; ".join(result.errors)

        # Additional safety checks
        try:
            ip_obj = ipaddress.ip_address(result.sanitized_value)
            if ip_obj.is_loopback:
                return False, "Cannot block loopback address"
            if str(ip_obj) in self.PROTECTED_IPS:
                return False, "Protected IP address"
        except ValueError:
            return False, "Invalid IP format"

        return True, "OK"
