"""
Retry mechanism with exponential backoff and circuit breaker for SOC AI Agents.
Handles transient failures and prevents cascading failures.
"""

import asyncio
import time
import logging
from typing import Dict, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import random


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, requests fail fast
    HALF_OPEN = "half_open"  # Testing if service is back


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5          # Failures before opening circuit
    recovery_timeout: int = 60          # Seconds before trying half-open
    success_threshold: int = 3          # Successes needed to close circuit
    timeout: int = 30                   # Request timeout in seconds


@dataclass
class RetryConfig:
    """Configuration for retry mechanism."""
    max_attempts: int = 3               # Maximum retry attempts
    base_delay: float = 1.0             # Base delay in seconds
    max_delay: float = 60.0             # Maximum delay in seconds
    exponential_base: float = 2.0       # Exponential backoff base
    jitter: bool = True                 # Add jitter to prevent thundering herd


@dataclass
class TargetState:
    """State tracking for a specific target (IP/user)."""
    failures: int = 0
    successes: int = 0
    last_failure_time: float = 0
    circuit_state: CircuitState = CircuitState.CLOSED
    last_state_change: float = 0


class RetryCircuitBreaker:
    """Retry mechanism with circuit breaker for handling transient failures."""
    
    def __init__(self, retry_config: RetryConfig = None, circuit_config: CircuitBreakerConfig = None):
        self.retry_config = retry_config or RetryConfig()
        self.circuit_config = circuit_config or CircuitBreakerConfig()
        self.logger = logging.getLogger("RetryCircuitBreaker")
        
        # Track state per target
        self._target_states: Dict[str, TargetState] = {}
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "retries_attempted": 0,
            "circuits_opened": 0,
            "circuits_closed": 0,
            "circuits_half_opened": 0
        }
    
    def _get_target_key(self, action_name: str, target: str) -> str:
        """Generate a key for tracking target state."""
        return f"{action_name}:{target}"
    
    def _get_target_state(self, action_name: str, target: str) -> TargetState:
        """Get or create target state."""
        key = self._get_target_key(action_name, target)
        if key not in self._target_states:
            self._target_states[key] = TargetState()
        return self._target_states[key]
    
    def _is_circuit_open(self, state: TargetState) -> bool:
        """Check if circuit should be open for this target."""
        current_time = time.time()
        
        if state.circuit_state == CircuitState.OPEN:
            # Check if we should try half-open
            if current_time - state.last_state_change >= self.circuit_config.recovery_timeout:
                state.circuit_state = CircuitState.HALF_OPEN
                state.last_state_change = current_time
                self.stats["circuits_half_opened"] += 1
                self.logger.info(f"Circuit half-opened for target: {state}")
                return False
            return True
        
        return False
    
    def _record_success(self, state: TargetState):
        """Record a successful operation."""
        state.successes += 1
        state.failures = 0  # Reset failure count on success
        
        if state.circuit_state == CircuitState.HALF_OPEN:
            if state.successes >= self.circuit_config.success_threshold:
                state.circuit_state = CircuitState.CLOSED
                state.last_state_change = time.time()
                state.successes = 0  # Reset success count
                self.stats["circuits_closed"] += 1
                self.logger.info(f"Circuit closed for target: {state}")
    
    def _record_failure(self, state: TargetState):
        """Record a failed operation."""
        current_time = time.time()
        state.failures += 1
        state.last_failure_time = current_time
        
        if state.circuit_state == CircuitState.CLOSED:
            if state.failures >= self.circuit_config.failure_threshold:
                state.circuit_state = CircuitState.OPEN
                state.last_state_change = current_time
                self.stats["circuits_opened"] += 1
                self.logger.warning(f"Circuit opened for target: {state}")
    
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt."""
        delay = self.retry_config.base_delay * (
            self.retry_config.exponential_base ** attempt
        )
        
        # Cap at max delay
        delay = min(delay, self.retry_config.max_delay)
        
        # Add jitter to prevent thundering herd
        if self.retry_config.jitter:
            jitter = random.uniform(0, delay * 0.1)
            delay += jitter
        
        return delay
    
    async def execute_with_retry(self, action_name: str, target: str, 
                               func: Callable, *args, **kwargs) -> Tuple[bool, Any, Optional[str]]:
        """Execute a function with retry and circuit breaker logic."""
        self.stats["total_requests"] += 1
        state = self._get_target_state(action_name, target)
        
        # Check circuit breaker
        if self._is_circuit_open(state):
            error_msg = f"Circuit breaker open for {action_name}:{target}"
            self.logger.warning(error_msg)
            self.stats["failed_requests"] += 1
            return False, None, error_msg
        
        last_error = None
        
        for attempt in range(self.retry_config.max_attempts):
            try:
                # Execute the function with timeout
                result = await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=self.circuit_config.timeout
                )
                
                # Success
                self._record_success(state)
                self.stats["successful_requests"] += 1
                self.logger.debug(f"Success on attempt {attempt + 1} for {action_name}:{target}")
                return True, result, None
                
            except asyncio.TimeoutError:
                last_error = f"Timeout after {self.circuit_config.timeout}s"
                self.logger.warning(f"Timeout on attempt {attempt + 1} for {action_name}:{target}")
                
            except Exception as e:
                last_error = str(e)
                self.logger.warning(f"Error on attempt {attempt + 1} for {action_name}:{target}: {e}")
            
            # If this was the last attempt, record failure
            if attempt == self.retry_config.max_attempts - 1:
                self._record_failure(state)
                self.stats["failed_requests"] += 1
                break
            
            # Wait before retry
            delay = self._calculate_delay(attempt)
            self.stats["retries_attempted"] += 1
            self.logger.debug(f"Retrying {action_name}:{target} in {delay:.2f}s")
            await asyncio.sleep(delay)
        
        return False, None, last_error
    
    def get_target_state(self, action_name: str, target: str) -> Optional[TargetState]:
        """Get the current state of a target."""
        key = self._get_target_key(action_name, target)
        return self._target_states.get(key)
    
    def get_circuit_breaker_status(self) -> Dict[str, Any]:
        """Get status of all circuit breakers."""
        status = {
            "total_targets": len(self._target_states),
            "closed_circuits": 0,
            "open_circuits": 0,
            "half_open_circuits": 0,
            "targets": {}
        }
        
        for key, state in self._target_states.items():
            if state.circuit_state == CircuitState.CLOSED:
                status["closed_circuits"] += 1
            elif state.circuit_state == CircuitState.OPEN:
                status["open_circuits"] += 1
            elif state.circuit_state == CircuitState.HALF_OPEN:
                status["half_open_circuits"] += 1
            
            status["targets"][key] = {
                "state": state.circuit_state.value,
                "failures": state.failures,
                "successes": state.successes,
                "last_failure_time": state.last_failure_time,
                "last_state_change": state.last_state_change
            }
        
        return status
    
    def get_stats(self) -> Dict[str, Any]:
        """Get retry and circuit breaker statistics."""
        return {
            **self.stats,
            "success_rate": (
                self.stats["successful_requests"] / max(self.stats["total_requests"], 1)
            ) * 100,
            "retry_rate": (
                self.stats["retries_attempted"] / max(self.stats["total_requests"], 1)
            ) * 100
        }
    
    def reset_circuit_breaker(self, action_name: str, target: str):
        """Manually reset circuit breaker for a target."""
        key = self._get_target_key(action_name, target)
        if key in self._target_states:
            state = self._target_states[key]
            state.circuit_state = CircuitState.CLOSED
            state.failures = 0
            state.successes = 0
            state.last_state_change = time.time()
            self.logger.info(f"Circuit breaker reset for {action_name}:{target}")
    
    def cleanup_old_targets(self, max_age_hours: int = 24):
        """Clean up old target states."""
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        
        old_targets = [
            key for key, state in self._target_states.items()
            if current_time - state.last_state_change > max_age_seconds
        ]
        
        for key in old_targets:
            del self._target_states[key]
        
        if old_targets:
            self.logger.info(f"Cleaned up {len(old_targets)} old target states")
