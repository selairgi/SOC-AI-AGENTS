"""
SOC Remediator Agent.

Main remediation agent that:
- Subscribes to RemediationDecision events
- Executes remediation actions (with dry_run support)
- Publishes RemediationExecuted events
- Supports rollback capabilities

Flow:
    RemediationDecision -> SOCRemediator -> RemediationExecuted
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum

# Import utilities
try:
    from ..utils import CircuitBreaker, ExecutionTracker, InputSanitizer
except ImportError:
    CircuitBreaker = None
    ExecutionTracker = None
    InputSanitizer = None


class ActionType(Enum):
    """Supported remediation action types."""
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    DISABLE_ACCOUNT = "disable_account"
    ENABLE_ACCOUNT = "enable_account"
    ISOLATE_SYSTEM = "isolate_system"
    RESTORE_SYSTEM = "restore_system"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    RESET_PASSWORD = "reset_password"
    REVOKE_TOKENS = "revoke_tokens"
    NOTIFY = "notify"
    ESCALATE = "escalate"
    MONITOR = "monitor"
    DISMISS = "dismiss"


@dataclass
class ActionResult:
    """Result of executing a remediation action."""
    success: bool
    action_type: str
    target: Dict[str, Any]
    dry_run: bool
    message: str
    timestamp: str
    rollback_info: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class RemediationRecord:
    """Record of executed remediation for rollback."""
    remediation_id: str
    correlation_id: str
    action_type: str
    target: Dict[str, Any]
    executed_at: str
    dry_run: bool
    rollback_action: Optional[str] = None
    rolled_back: bool = False


class SOCRemediator:
    """
    Main SOC Remediation Agent.

    Responsibilities:
    - Subscribe to RemediationDecision events
    - Execute remediation actions (block IP, isolate, etc.)
    - Support dry_run mode (default: True)
    - Track executed actions for rollback
    - Publish RemediationExecuted events
    """

    EVENT_REMEDIATION_DECISION = "RemediationDecision"
    EVENT_REMEDIATION_EXECUTED = "RemediationExecuted"

    # Rollback mappings
    ROLLBACK_ACTIONS = {
        "block_ip": "unblock_ip",
        "disable_account": "enable_account",
        "isolate_system": "restore_system",
        "quarantine_file": "restore_file",
        "revoke_tokens": "issue_tokens"
    }

    def __init__(
        self,
        event_bus,
        dry_run: bool = True,
        incremental_storage=None,
        action_handlers: Optional[Dict[str, Callable]] = None,
        use_circuit_breaker: bool = True,
        use_execution_tracker: bool = True,
        use_sanitizer: bool = True,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the SOC Remediator.

        Args:
            event_bus: EventBus for pub/sub
            dry_run: Default dry_run mode (True = simulate only)
            incremental_storage: Optional storage for learning
            action_handlers: Custom action handler functions
            use_circuit_breaker: Enable circuit breaker for resilience
            use_execution_tracker: Enable idempotency tracking
            use_sanitizer: Enable input sanitization
            logger: Optional logger instance
        """
        self.bus = event_bus
        self.default_dry_run = dry_run
        self.storage = incremental_storage
        self.logger = logger or logging.getLogger("SOCRemediator")

        # Initialize utilities
        self.circuit_breaker = None
        if use_circuit_breaker and CircuitBreaker:
            self.circuit_breaker = CircuitBreaker(logger=self.logger)
            self.logger.info("CircuitBreaker enabled")

        self.execution_tracker = None
        if use_execution_tracker and ExecutionTracker:
            self.execution_tracker = ExecutionTracker(logger=self.logger)
            self.logger.info("ExecutionTracker enabled")

        self.sanitizer = None
        if use_sanitizer and InputSanitizer:
            self.sanitizer = InputSanitizer(logger=self.logger)
            self.logger.info("InputSanitizer enabled")

        # Custom action handlers
        self._action_handlers: Dict[str, Callable] = action_handlers or {}

        # Register default handlers
        self._register_default_handlers()

        # Track remediation history for rollback
        self._remediation_history: Dict[str, RemediationRecord] = {}

        self._running = False

        # Statistics
        self.stats = {
            "decisions_received": 0,
            "actions_executed": 0,
            "actions_simulated": 0,
            "actions_failed": 0,
            "actions_blocked_by_cb": 0,
            "actions_skipped_idempotent": 0,
            "actions_blocked_by_sanitizer": 0,
            "rollbacks_performed": 0,
            "actions_by_type": {},
            "start_time": None
        }

    def _register_default_handlers(self) -> None:
        """Register default action handlers."""
        # These are simulation handlers - replace with real implementations
        self._action_handlers.update({
            "block_ip": self._handle_block_ip,
            "unblock_ip": self._handle_unblock_ip,
            "disable_account": self._handle_disable_account,
            "enable_account": self._handle_enable_account,
            "isolate_system": self._handle_isolate_system,
            "restore_system": self._handle_restore_system,
            "kill_process": self._handle_kill_process,
            "quarantine_file": self._handle_quarantine_file,
            "reset_password": self._handle_reset_password,
            "revoke_tokens": self._handle_revoke_tokens,
            "notify": self._handle_notify,
            "escalate": self._handle_escalate,
            "monitor": self._handle_monitor,
            "dismiss": self._handle_dismiss,
        })

    def register_handler(self, action_type: str, handler: Callable) -> None:
        """Register a custom action handler."""
        self._action_handlers[action_type] = handler
        self.logger.info(f"Registered handler for action: {action_type}")

    def start(self) -> None:
        """Start the remediator agent."""
        if self._running:
            self.logger.warning("SOCRemediator already running")
            return

        self.bus.subscribe(self.EVENT_REMEDIATION_DECISION, self._handle_decision)
        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()

        mode = "DRY-RUN" if self.default_dry_run else "LIVE"
        self.logger.info(f"SOCRemediator started in {mode} mode")

    def stop(self) -> None:
        """Stop the remediator agent."""
        if not self._running:
            return

        self.bus.unsubscribe(self.EVENT_REMEDIATION_DECISION, self._handle_decision)
        self._running = False

        self.logger.info("SOCRemediator stopped")
        self._log_stats()

    def _handle_decision(self, event: dict) -> None:
        """Handle incoming remediation decision."""
        self.stats["decisions_received"] += 1

        try:
            correlation_id = event.get("correlation_id")
            payload = event.get("payload", {})

            # Get action details
            action_type = payload.get("action", payload.get("recommended_action", "monitor"))
            target = payload.get("target", {})
            dry_run = payload.get("dry_run", self.default_dry_run)
            decision = payload.get("decision", "allow")

            # Check if action was approved
            if decision == "deny":
                self.logger.info(f"Action {action_type} denied by policy")
                self._publish_result(
                    event,
                    ActionResult(
                        success=False,
                        action_type=action_type,
                        target=target,
                        dry_run=dry_run,
                        message="Action denied by policy",
                        timestamp=datetime.now(timezone.utc).isoformat()
                    ),
                    correlation_id
                )
                return

            # Execute the action
            result = self._execute_action(
                action_type=action_type,
                target=target,
                dry_run=dry_run,
                correlation_id=correlation_id
            )

            # Store for incremental learning
            if self.storage:
                self._store_for_learning(event, result)

            # Publish result
            self._publish_result(event, result, correlation_id)

        except Exception as e:
            self.logger.error(f"Error handling remediation decision: {e}")
            self.stats["actions_failed"] += 1

    def _execute_action(
        self,
        action_type: str,
        target: Dict[str, Any],
        dry_run: bool,
        correlation_id: str
    ) -> ActionResult:
        """
        Execute a remediation action.

        Args:
            action_type: Type of action to execute
            target: Target of the action (IP, user, etc.)
            dry_run: If True, simulate only
            correlation_id: Correlation ID for tracking

        Returns:
            ActionResult with execution details
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        target_key = str(target.get("ip") or target.get("user") or target.get("host", "unknown"))

        # Sanitize input if enabled
        if self.sanitizer:
            is_valid, sanitized_target, errors = self.sanitizer.validate_target(action_type, target)
            if not is_valid:
                self.stats["actions_blocked_by_sanitizer"] += 1
                return ActionResult(
                    success=False,
                    action_type=action_type,
                    target=target,
                    dry_run=dry_run,
                    message=f"Validation failed: {'; '.join(errors)}",
                    timestamp=timestamp,
                    error="Validation failed"
                )
            target = sanitized_target

        # Check idempotency if enabled
        if self.execution_tracker and not dry_run:
            if self.execution_tracker.is_executed(action_type, target_key, correlation_id):
                self.stats["actions_skipped_idempotent"] += 1
                return ActionResult(
                    success=True,
                    action_type=action_type,
                    target=target,
                    dry_run=dry_run,
                    message="Already executed (idempotent)",
                    timestamp=timestamp
                )

        # Check circuit breaker if enabled
        if self.circuit_breaker and not dry_run:
            if not self.circuit_breaker.can_execute(action_type, target_key):
                self.stats["actions_blocked_by_cb"] += 1
                return ActionResult(
                    success=False,
                    action_type=action_type,
                    target=target,
                    dry_run=dry_run,
                    message="Circuit breaker open - too many failures",
                    timestamp=timestamp,
                    error="Circuit breaker open"
                )

        # Get handler
        handler = self._action_handlers.get(action_type)
        if not handler:
            return ActionResult(
                success=False,
                action_type=action_type,
                target=target,
                dry_run=dry_run,
                message=f"No handler for action: {action_type}",
                timestamp=timestamp,
                error="Unknown action type"
            )

        try:
            # Execute (or simulate)
            if dry_run:
                result = ActionResult(
                    success=True,
                    action_type=action_type,
                    target=target,
                    dry_run=True,
                    message=f"[DRY-RUN] Would execute: {action_type} on {target}",
                    timestamp=timestamp,
                    rollback_info=self._get_rollback_info(action_type, target)
                )
                self.stats["actions_simulated"] += 1
            else:
                # Actually execute
                result = handler(target)
                result.timestamp = timestamp
                result.dry_run = False

                # Track for rollback
                if result.success:
                    self._record_remediation(
                        correlation_id, action_type, target, dry_run
                    )
                    self.stats["actions_executed"] += 1

                    # Record in circuit breaker
                    if self.circuit_breaker:
                        self.circuit_breaker.record_success(action_type, target_key)

                    # Record in execution tracker
                    if self.execution_tracker:
                        self.execution_tracker.record(
                            action_type, target_key, correlation_id,
                            "executed", dry_run=False
                        )
                else:
                    self.stats["actions_failed"] += 1

                    # Record failure in circuit breaker
                    if self.circuit_breaker:
                        self.circuit_breaker.record_failure(action_type, target_key)

                    # Record in execution tracker
                    if self.execution_tracker:
                        self.execution_tracker.record(
                            action_type, target_key, correlation_id,
                            "failed", dry_run=False, error=result.error
                        )

            # Update action stats
            self.stats["actions_by_type"][action_type] = \
                self.stats["actions_by_type"].get(action_type, 0) + 1

            return result

        except Exception as e:
            self.logger.error(f"Action execution failed: {e}")

            # Record failure
            if self.circuit_breaker:
                self.circuit_breaker.record_failure(action_type, target_key)

            return ActionResult(
                success=False,
                action_type=action_type,
                target=target,
                dry_run=dry_run,
                message=f"Execution failed: {str(e)}",
                timestamp=timestamp,
                error=str(e)
            )

    def _get_rollback_info(self, action_type: str, target: Dict[str, Any]) -> Dict[str, Any]:
        """Get rollback information for an action."""
        rollback_action = self.ROLLBACK_ACTIONS.get(action_type)
        if rollback_action:
            return {
                "rollback_action": rollback_action,
                "target": target
            }
        return {}

    def _record_remediation(
        self,
        correlation_id: str,
        action_type: str,
        target: Dict[str, Any],
        dry_run: bool
    ) -> None:
        """Record remediation for potential rollback."""
        remediation_id = str(uuid.uuid4())[:8]
        record = RemediationRecord(
            remediation_id=remediation_id,
            correlation_id=correlation_id,
            action_type=action_type,
            target=target,
            executed_at=datetime.now(timezone.utc).isoformat(),
            dry_run=dry_run,
            rollback_action=self.ROLLBACK_ACTIONS.get(action_type)
        )
        self._remediation_history[remediation_id] = record

    def rollback(self, remediation_id: str) -> ActionResult:
        """
        Rollback a previously executed remediation.

        Args:
            remediation_id: ID of the remediation to rollback

        Returns:
            ActionResult of the rollback action
        """
        record = self._remediation_history.get(remediation_id)
        if not record:
            return ActionResult(
                success=False,
                action_type="rollback",
                target={},
                dry_run=False,
                message=f"Remediation not found: {remediation_id}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                error="Remediation not found"
            )

        if record.rolled_back:
            return ActionResult(
                success=False,
                action_type="rollback",
                target=record.target,
                dry_run=False,
                message=f"Remediation already rolled back: {remediation_id}",
                timestamp=datetime.now(timezone.utc).isoformat()
            )

        if not record.rollback_action:
            return ActionResult(
                success=False,
                action_type="rollback",
                target=record.target,
                dry_run=False,
                message=f"No rollback available for: {record.action_type}",
                timestamp=datetime.now(timezone.utc).isoformat()
            )

        # Execute rollback
        result = self._execute_action(
            action_type=record.rollback_action,
            target=record.target,
            dry_run=False,
            correlation_id=record.correlation_id
        )

        if result.success:
            record.rolled_back = True
            self.stats["rollbacks_performed"] += 1

        return result

    # ========== Default Action Handlers ==========

    def _handle_block_ip(self, target: Dict[str, Any]) -> ActionResult:
        """Block an IP address."""
        ip = target.get("ip", target.get("source_ip", ""))
        # In production: actual firewall API call
        self.logger.info(f"BLOCKING IP: {ip}")
        return ActionResult(
            success=True,
            action_type="block_ip",
            target=target,
            dry_run=False,
            message=f"IP {ip} blocked successfully",
            timestamp="",
            rollback_info={"action": "unblock_ip", "ip": ip}
        )

    def _handle_unblock_ip(self, target: Dict[str, Any]) -> ActionResult:
        """Unblock an IP address."""
        ip = target.get("ip", target.get("source_ip", ""))
        self.logger.info(f"UNBLOCKING IP: {ip}")
        return ActionResult(
            success=True,
            action_type="unblock_ip",
            target=target,
            dry_run=False,
            message=f"IP {ip} unblocked successfully",
            timestamp=""
        )

    def _handle_disable_account(self, target: Dict[str, Any]) -> ActionResult:
        """Disable a user account."""
        user = target.get("user", target.get("username", ""))
        # In production: actual IAM API call
        self.logger.info(f"DISABLING ACCOUNT: {user}")
        return ActionResult(
            success=True,
            action_type="disable_account",
            target=target,
            dry_run=False,
            message=f"Account {user} disabled successfully",
            timestamp="",
            rollback_info={"action": "enable_account", "user": user}
        )

    def _handle_enable_account(self, target: Dict[str, Any]) -> ActionResult:
        """Enable a user account."""
        user = target.get("user", target.get("username", ""))
        self.logger.info(f"ENABLING ACCOUNT: {user}")
        return ActionResult(
            success=True,
            action_type="enable_account",
            target=target,
            dry_run=False,
            message=f"Account {user} enabled successfully",
            timestamp=""
        )

    def _handle_isolate_system(self, target: Dict[str, Any]) -> ActionResult:
        """Isolate a system from the network."""
        host = target.get("host", target.get("hostname", ""))
        # In production: actual EDR/network API call
        self.logger.info(f"ISOLATING SYSTEM: {host}")
        return ActionResult(
            success=True,
            action_type="isolate_system",
            target=target,
            dry_run=False,
            message=f"System {host} isolated from network",
            timestamp="",
            rollback_info={"action": "restore_system", "host": host}
        )

    def _handle_restore_system(self, target: Dict[str, Any]) -> ActionResult:
        """Restore system network access."""
        host = target.get("host", target.get("hostname", ""))
        self.logger.info(f"RESTORING SYSTEM: {host}")
        return ActionResult(
            success=True,
            action_type="restore_system",
            target=target,
            dry_run=False,
            message=f"System {host} restored to network",
            timestamp=""
        )

    def _handle_kill_process(self, target: Dict[str, Any]) -> ActionResult:
        """Kill a running process."""
        pid = target.get("pid", "")
        host = target.get("host", "localhost")
        self.logger.info(f"KILLING PROCESS: {pid} on {host}")
        return ActionResult(
            success=True,
            action_type="kill_process",
            target=target,
            dry_run=False,
            message=f"Process {pid} killed on {host}",
            timestamp=""
        )

    def _handle_quarantine_file(self, target: Dict[str, Any]) -> ActionResult:
        """Quarantine a suspicious file."""
        file_path = target.get("file_path", "")
        host = target.get("host", "localhost")
        self.logger.info(f"QUARANTINING FILE: {file_path} on {host}")
        return ActionResult(
            success=True,
            action_type="quarantine_file",
            target=target,
            dry_run=False,
            message=f"File {file_path} quarantined on {host}",
            timestamp="",
            rollback_info={"action": "restore_file", "file_path": file_path}
        )

    def _handle_reset_password(self, target: Dict[str, Any]) -> ActionResult:
        """Force password reset for a user."""
        user = target.get("user", target.get("username", ""))
        self.logger.info(f"RESETTING PASSWORD: {user}")
        return ActionResult(
            success=True,
            action_type="reset_password",
            target=target,
            dry_run=False,
            message=f"Password reset initiated for {user}",
            timestamp=""
        )

    def _handle_revoke_tokens(self, target: Dict[str, Any]) -> ActionResult:
        """Revoke all active tokens for a user."""
        user = target.get("user", target.get("username", ""))
        self.logger.info(f"REVOKING TOKENS: {user}")
        return ActionResult(
            success=True,
            action_type="revoke_tokens",
            target=target,
            dry_run=False,
            message=f"All tokens revoked for {user}",
            timestamp=""
        )

    def _handle_notify(self, target: Dict[str, Any]) -> ActionResult:
        """Send notification about an incident."""
        recipients = target.get("recipients", ["security-team"])
        self.logger.info(f"SENDING NOTIFICATION to: {recipients}")
        return ActionResult(
            success=True,
            action_type="notify",
            target=target,
            dry_run=False,
            message=f"Notification sent to {recipients}",
            timestamp=""
        )

    def _handle_escalate(self, target: Dict[str, Any]) -> ActionResult:
        """Escalate incident to higher tier."""
        tier = target.get("tier", "tier2")
        self.logger.info(f"ESCALATING to: {tier}")
        return ActionResult(
            success=True,
            action_type="escalate",
            target=target,
            dry_run=False,
            message=f"Incident escalated to {tier}",
            timestamp=""
        )

    def _handle_monitor(self, target: Dict[str, Any]) -> ActionResult:
        """Continue monitoring without action."""
        self.logger.info("CONTINUING MONITORING")
        return ActionResult(
            success=True,
            action_type="monitor",
            target=target,
            dry_run=False,
            message="Continuing to monitor, no immediate action required",
            timestamp=""
        )

    def _handle_dismiss(self, target: Dict[str, Any]) -> ActionResult:
        """Dismiss alert as false positive."""
        self.logger.info("DISMISSING ALERT")
        return ActionResult(
            success=True,
            action_type="dismiss",
            target=target,
            dry_run=False,
            message="Alert dismissed as false positive",
            timestamp=""
        )

    # ========== Publishing & Storage ==========

    def _store_for_learning(self, event: dict, result: ActionResult) -> None:
        """Store remediation example for incremental learning."""
        try:
            example = {
                "decision_event": event,
                "execution": {
                    "action_type": result.action_type,
                    "target": result.target,
                    "success": result.success,
                    "dry_run": result.dry_run,
                    "message": result.message
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.storage.store("remediator", example)
        except Exception as e:
            self.logger.debug(f"Failed to store for learning: {e}")

    def _publish_result(
        self,
        source_event: dict,
        result: ActionResult,
        correlation_id: str
    ) -> None:
        """Publish RemediationExecuted event."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        executed_event = {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "soc_remediator",
            "payload": {
                "remediation_id": f"remediation-{event_id[:8]}",
                "action": result.action_type,
                "target": result.target,
                "success": result.success,
                "dry_run": result.dry_run,
                "message": result.message,
                "rollback_info": result.rollback_info,
                "error": result.error
            }
        }

        self.bus.publish(self.EVENT_REMEDIATION_EXECUTED, executed_event)

        mode = "[DRY-RUN]" if result.dry_run else "[EXECUTED]"
        status = "SUCCESS" if result.success else "FAILED"
        self.logger.info(f"{mode} {result.action_type}: {status} - {result.message}")

    def _log_stats(self) -> None:
        """Log statistics."""
        self.logger.info("=== SOCRemediator Statistics ===")
        self.logger.info(f"Decisions received: {self.stats['decisions_received']}")
        self.logger.info(f"Actions executed: {self.stats['actions_executed']}")
        self.logger.info(f"Actions simulated: {self.stats['actions_simulated']}")
        self.logger.info(f"Actions failed: {self.stats['actions_failed']}")
        self.logger.info(f"Rollbacks performed: {self.stats['rollbacks_performed']}")
        self.logger.info(f"Actions by type: {self.stats['actions_by_type']}")

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        return self.stats.copy()

    def get_remediation_history(self) -> List[Dict[str, Any]]:
        """Get remediation history for audit."""
        return [
            {
                "remediation_id": r.remediation_id,
                "correlation_id": r.correlation_id,
                "action_type": r.action_type,
                "target": r.target,
                "executed_at": r.executed_at,
                "dry_run": r.dry_run,
                "rolled_back": r.rolled_back
            }
            for r in self._remediation_history.values()
        ]

    def is_running(self) -> bool:
        """Check if remediator is running."""
        return self._running
