"""
Circuit Breaker - Resilience pattern for action execution.

Prevents cascading failures by stopping requests to failing targets.
"""

import time
import random
import logging
from typing import Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass
from enum import Enum


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class TargetState:
    """State for a specific target."""
    failures: int = 0
    successes: int = 0
    last_failure: float = 0
    state: CircuitState = CircuitState.CLOSED
    state_changed_at: float = 0


class CircuitBreaker:
    """
    Circuit breaker for resilient action execution.

    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Too many failures, requests rejected immediately
    - HALF_OPEN: Testing if target recovered

    Usage:
        cb = CircuitBreaker()

        # Check before executing
        if cb.can_execute("block_ip", "192.168.1.1"):
            try:
                result = execute_action()
                cb.record_success("block_ip", "192.168.1.1")
            except:
                cb.record_failure("block_ip", "192.168.1.1")
        else:
            # Circuit is open, skip execution
            pass
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        success_threshold: int = 2,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Failures before opening circuit
            recovery_timeout: Seconds before trying half-open
            success_threshold: Successes needed to close circuit
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold
        self.logger = logger or logging.getLogger("CircuitBreaker")

        self._targets: Dict[str, TargetState] = {}

        self.stats = {
            "total_checks": 0,
            "allowed": 0,
            "rejected": 0,
            "circuits_opened": 0,
            "circuits_closed": 0
        }

    def _get_key(self, action: str, target: str) -> str:
        """Generate unique key for action:target pair."""
        return f"{action}:{target}"

    def _get_state(self, action: str, target: str) -> TargetState:
        """Get or create target state."""
        key = self._get_key(action, target)
        if key not in self._targets:
            self._targets[key] = TargetState(state_changed_at=time.time())
        return self._targets[key]

    def can_execute(self, action: str, target: str) -> bool:
        """
        Check if action can be executed on target.

        Args:
            action: Action type (e.g., "block_ip")
            target: Target identifier (e.g., IP address)

        Returns:
            True if action can proceed, False if circuit is open
        """
        self.stats["total_checks"] += 1
        state = self._get_state(action, target)
        now = time.time()

        if state.state == CircuitState.CLOSED:
            self.stats["allowed"] += 1
            return True

        elif state.state == CircuitState.OPEN:
            # Check if we should try half-open
            if now - state.state_changed_at >= self.recovery_timeout:
                state.state = CircuitState.HALF_OPEN
                state.state_changed_at = now
                state.successes = 0
                self.logger.info(f"Circuit half-opened for {action}:{target}")
                self.stats["allowed"] += 1
                return True
            else:
                self.stats["rejected"] += 1
                return False

        else:  # HALF_OPEN
            self.stats["allowed"] += 1
            return True

    def record_success(self, action: str, target: str) -> None:
        """Record a successful execution."""
        state = self._get_state(action, target)
        state.successes += 1
        state.failures = 0

        if state.state == CircuitState.HALF_OPEN:
            if state.successes >= self.success_threshold:
                state.state = CircuitState.CLOSED
                state.state_changed_at = time.time()
                state.successes = 0
                self.stats["circuits_closed"] += 1
                self.logger.info(f"Circuit closed for {action}:{target}")

    def record_failure(self, action: str, target: str) -> None:
        """Record a failed execution."""
        state = self._get_state(action, target)
        now = time.time()
        state.failures += 1
        state.last_failure = now

        if state.state == CircuitState.CLOSED:
            if state.failures >= self.failure_threshold:
                state.state = CircuitState.OPEN
                state.state_changed_at = now
                self.stats["circuits_opened"] += 1
                self.logger.warning(f"Circuit opened for {action}:{target}")

        elif state.state == CircuitState.HALF_OPEN:
            # Failed during recovery test, back to open
            state.state = CircuitState.OPEN
            state.state_changed_at = now
            self.logger.warning(f"Circuit re-opened for {action}:{target}")

    def execute_with_cb(
        self,
        action: str,
        target: str,
        func: Callable,
        *args,
        **kwargs
    ) -> Tuple[bool, Any, Optional[str]]:
        """
        Execute function with circuit breaker protection.

        Args:
            action: Action type
            target: Target identifier
            func: Function to execute
            *args, **kwargs: Function arguments

        Returns:
            Tuple of (success, result, error_message)
        """
        if not self.can_execute(action, target):
            return False, None, f"Circuit open for {action}:{target}"

        try:
            result = func(*args, **kwargs)
            self.record_success(action, target)
            return True, result, None
        except Exception as e:
            self.record_failure(action, target)
            return False, None, str(e)

    def reset(self, action: str, target: str) -> None:
        """Manually reset circuit for a target."""
        key = self._get_key(action, target)
        if key in self._targets:
            state = self._targets[key]
            state.state = CircuitState.CLOSED
            state.failures = 0
            state.successes = 0
            state.state_changed_at = time.time()
            self.logger.info(f"Circuit manually reset for {action}:{target}")

    def get_state(self, action: str, target: str) -> Dict[str, Any]:
        """Get current state for a target."""
        state = self._get_state(action, target)
        return {
            "state": state.state.value,
            "failures": state.failures,
            "successes": state.successes,
            "last_failure": state.last_failure
        }

    def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        """Get states for all targets."""
        return {
            key: {
                "state": s.state.value,
                "failures": s.failures,
                "successes": s.successes
            }
            for key, s in self._targets.items()
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics."""
        open_count = sum(1 for s in self._targets.values() if s.state == CircuitState.OPEN)
        return {
            **self.stats,
            "open_circuits": open_count,
            "total_targets": len(self._targets),
            "rejection_rate": self.stats["rejected"] / max(self.stats["total_checks"], 1)
        }

    def cleanup(self, max_age_hours: int = 24) -> int:
        """Remove old target states."""
        cutoff = time.time() - (max_age_hours * 3600)
        old_keys = [
            key for key, s in self._targets.items()
            if s.state_changed_at < cutoff and s.state == CircuitState.CLOSED
        ]
        for key in old_keys:
            del self._targets[key]
        return len(old_keys)
