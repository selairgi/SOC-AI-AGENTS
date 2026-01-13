"""
Human Approval Agent.

Handles human approval requests for remediation actions.
Tracks pending approvals and publishes HumanDecision events.

Usage:
    from soc_core.governance import HumanApprovalAgent

    agent = HumanApprovalAgent(bus)
    agent.start()

    # Request approval
    agent.request_approval(correlation_id, action, context)

    # Process approval/rejection
    agent.approve(correlation_id, approver, reason)
    agent.reject(correlation_id, approver, reason)
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from collections import OrderedDict
import threading


@dataclass
class PendingApproval:
    """Tracks a pending human approval request."""
    correlation_id: str
    action: str
    context: Dict[str, Any]
    requested_at: str
    timeout_seconds: int = 3600
    priority: str = "medium"
    requester: str = "system"


class HumanApprovalAgent:
    """
    Agent for handling human approval workflows.

    This agent:
    - Subscribes to PolicyDecision events with require_human decisions
    - Tracks pending approvals
    - Publishes HumanDecision events when approved/rejected
    - Supports timeout for stale approvals
    """

    EVENT_POLICY_DECISION = "PolicyDecision"
    EVENT_HUMAN_DECISION = "HumanDecision"
    EVENT_APPROVAL_REQUEST = "ApprovalRequest"

    def __init__(
        self,
        event_bus,
        default_timeout: int = 3600,
        max_pending: int = 1000,
        logger: Optional[logging.Logger] = None
    ):
        self.bus = event_bus
        self.default_timeout = default_timeout
        self.max_pending = max_pending
        self.logger = logger or logging.getLogger("HumanApprovalAgent")

        # Pending approvals storage (LRU)
        self._pending: OrderedDict[str, PendingApproval] = OrderedDict()
        self._lock = threading.RLock()

        self._running = False
        self._subscribed = False

        self.stats = {
            "requests_created": 0,
            "approvals": 0,
            "rejections": 0,
            "timeouts": 0,
            "evicted": 0,
            "start_time": None,
        }

    def start(self) -> None:
        """Start the human approval agent."""
        if self._running:
            self.logger.warning("HumanApprovalAgent already running")
            return

        self.bus.subscribe(self.EVENT_POLICY_DECISION, self._handle_policy_decision)
        self._subscribed = True
        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()

        self.logger.info("HumanApprovalAgent started")

    def stop(self) -> None:
        """Stop the human approval agent."""
        if not self._running:
            return

        if self._subscribed:
            self.bus.unsubscribe(self.EVENT_POLICY_DECISION, self._handle_policy_decision)
            self._subscribed = False

        self._running = False
        self.logger.info("HumanApprovalAgent stopped")

    def _handle_policy_decision(self, event: dict) -> None:
        """Handle PolicyDecision events that require human approval."""
        payload = event.get("payload", {})
        decision = payload.get("decision")

        if decision != "require_human":
            return

        correlation_id = event.get("correlation_id")
        if not correlation_id:
            return

        # Create approval request
        self.request_approval(
            correlation_id=correlation_id,
            action=payload.get("action", "unknown"),
            context={
                "alert_id": payload.get("alert_id"),
                "reason": payload.get("reason"),
                "matched_rules": payload.get("matched_rules", []),
                "evaluated_actions": payload.get("evaluated_actions", []),
            }
        )

    def request_approval(
        self,
        correlation_id: str,
        action: str,
        context: Dict[str, Any],
        priority: str = "medium",
        requester: str = "system"
    ) -> str:
        """
        Create a human approval request.

        Args:
            correlation_id: Correlation ID for the incident
            action: The action requiring approval
            context: Additional context about the request
            priority: Request priority (low, medium, high, critical)
            requester: Who/what requested the approval

        Returns:
            The approval request ID
        """
        with self._lock:
            # Evict oldest if at capacity
            while len(self._pending) >= self.max_pending:
                oldest_id, _ = self._pending.popitem(last=False)
                self.stats["evicted"] += 1
                self.logger.warning(f"Evicted stale approval: {oldest_id}")

            pending = PendingApproval(
                correlation_id=correlation_id,
                action=action,
                context=context,
                requested_at=datetime.now(timezone.utc).isoformat(),
                timeout_seconds=self.default_timeout,
                priority=priority,
                requester=requester
            )
            self._pending[correlation_id] = pending
            self.stats["requests_created"] += 1

        # Publish approval request event
        self._publish_approval_request(pending)

        self.logger.info(
            f"Approval requested: {correlation_id[:8]}... "
            f"action={action}, priority={priority}"
        )

        return correlation_id

    def approve(
        self,
        correlation_id: str,
        approver: str,
        reason: str = ""
    ) -> bool:
        """
        Approve a pending request.

        Args:
            correlation_id: The correlation ID to approve
            approver: Who approved the request
            reason: Reason for approval

        Returns:
            True if approved, False if not found
        """
        with self._lock:
            if correlation_id not in self._pending:
                self.logger.warning(f"No pending approval for {correlation_id}")
                return False

            pending = self._pending.pop(correlation_id)

        self._publish_human_decision(
            pending=pending,
            approved=True,
            approver=approver,
            reason=reason
        )

        self.stats["approvals"] += 1
        self.logger.info(f"Approved: {correlation_id[:8]}... by {approver}")

        return True

    def reject(
        self,
        correlation_id: str,
        approver: str,
        reason: str = ""
    ) -> bool:
        """
        Reject a pending request.

        Args:
            correlation_id: The correlation ID to reject
            approver: Who rejected the request
            reason: Reason for rejection

        Returns:
            True if rejected, False if not found
        """
        with self._lock:
            if correlation_id not in self._pending:
                self.logger.warning(f"No pending approval for {correlation_id}")
                return False

            pending = self._pending.pop(correlation_id)

        self._publish_human_decision(
            pending=pending,
            approved=False,
            approver=approver,
            reason=reason
        )

        self.stats["rejections"] += 1
        self.logger.info(f"Rejected: {correlation_id[:8]}... by {approver}")

        return True

    def _publish_approval_request(self, pending: PendingApproval) -> None:
        """Publish an ApprovalRequest event."""
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": pending.correlation_id,
            "timestamp": pending.requested_at,
            "producer": "human_approval_agent",
            "payload": {
                "action": pending.action,
                "context": pending.context,
                "priority": pending.priority,
                "requester": pending.requester,
                "timeout_seconds": pending.timeout_seconds,
            }
        }
        self.bus.publish(self.EVENT_APPROVAL_REQUEST, event)

    def _publish_human_decision(
        self,
        pending: PendingApproval,
        approved: bool,
        approver: str,
        reason: str
    ) -> None:
        """Publish a HumanDecision event."""
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": pending.correlation_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "producer": "human_approval_agent",
            "payload": {
                "approved": approved,
                "approver": approver,
                "reason": reason,
                "action": pending.action,
                "context": pending.context,
                "requested_at": pending.requested_at,
                "decision_time_seconds": self._calculate_decision_time(pending.requested_at),
            }
        }
        self.bus.publish(self.EVENT_HUMAN_DECISION, event)

    def _calculate_decision_time(self, requested_at: str) -> float:
        """Calculate time between request and decision."""
        try:
            requested = datetime.fromisoformat(requested_at.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            return (now - requested).total_seconds()
        except:
            return 0.0

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get list of pending approval requests."""
        with self._lock:
            return [
                {
                    "correlation_id": p.correlation_id,
                    "action": p.action,
                    "priority": p.priority,
                    "requested_at": p.requested_at,
                    "context": p.context,
                }
                for p in self._pending.values()
            ]

    def get_pending_count(self) -> int:
        """Get count of pending approvals."""
        with self._lock:
            return len(self._pending)

    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        return {
            **self.stats,
            "pending_count": self.get_pending_count(),
        }
