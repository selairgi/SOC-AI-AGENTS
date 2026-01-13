"""
SOC Pipeline Orchestrator.

Manages the complete SOC workflow with 3 main agents + governance.

Flow:
    1. RawLogEvent (input)
    2. SOCDetector -> AlertDetected
    3. SOCAnalyst -> AnalysisCompleted
    4. PolicyAgent -> PolicyDecision
    5. ConsensusAgent -> RemediationDecision
    6. HumanApproval (if required) -> HumanDecision
    7. SOCRemediator -> RemediationExecuted

All events tracked in IncidentStateManager.
Incremental learning data stored for offline training.
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Events
from ..events import EventBus

# Main agents
from ..agents import SOCDetector, SOCAnalyst, SOCRemediator

# Governance
from ..governance import PolicyAgent, ConsensusAgent, HumanApprovalAgent

# State management
from ..state import IncidentStateManager

# Learning
from ..learning import IncrementalStorage


class SOCPipelineOrchestrator:
    """
    Orchestrates the complete SOC pipeline.

    This class:
    - Initializes all agents with shared EventBus
    - Manages agent lifecycle (start/stop)
    - Provides API for submitting events
    - Tracks all incidents via IncidentStateManager
    - Supports dry_run mode (default: True)

    Usage:
        orchestrator = SOCPipelineOrchestrator(dry_run=True)
        orchestrator.start()

        # Submit a raw log event
        result = orchestrator.submit_log({
            "message": "Failed login attempt from 192.168.1.100",
            "source": "auth_service",
            "source_ip": "192.168.1.100"
        })

        # Query incident state
        incident = orchestrator.get_incident(result["correlation_id"])

        orchestrator.stop()
    """

    def __init__(
        self,
        dry_run: bool = True,
        policy_path: Optional[str] = None,
        data_path: Optional[str] = None,
        max_incidents: int = 10000,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the SOC Pipeline.

        Args:
            dry_run: If True, remediation actions are simulated only
            policy_path: Path to policy JSON file (optional)
            data_path: Path for incremental learning data (optional)
            max_incidents: Maximum incidents to track in memory
            logger: Optional logger instance
        """
        self.dry_run = dry_run
        self.logger = logger or logging.getLogger("SOCPipeline")

        # Create shared EventBus
        self.bus = EventBus()

        # Create incremental storage for learning
        self.storage = IncrementalStorage(base_path=data_path)

        # Create state manager
        self.state_manager = IncidentStateManager(
            event_bus=self.bus,
            max_incidents=max_incidents,
            logger=logging.getLogger("IncidentStateManager")
        )

        # Create main agents (the 3 core agents)
        self.detector = SOCDetector(
            event_bus=self.bus,
            incremental_storage=self.storage,
            logger=logging.getLogger("SOCDetector")
        )

        self.analyst = SOCAnalyst(
            event_bus=self.bus,
            incremental_storage=self.storage,
            logger=logging.getLogger("SOCAnalyst")
        )

        self.remediator = SOCRemediator(
            event_bus=self.bus,
            dry_run=dry_run,
            incremental_storage=self.storage,
            logger=logging.getLogger("SOCRemediator")
        )

        # Create governance agents
        self.policy_agent = PolicyAgent(
            event_bus=self.bus,
            policy_path=policy_path,
            logger=logging.getLogger("PolicyAgent")
        )

        self.consensus_agent = ConsensusAgent(
            event_bus=self.bus,
            logger=logging.getLogger("ConsensusAgent")
        )

        self.human_approval = HumanApprovalAgent(
            event_bus=self.bus,
            logger=logging.getLogger("HumanApprovalAgent")
        )

        # Wire up the remediation proposal flow
        # AnalysisCompleted -> RemediationProposed
        self.bus.subscribe("AnalysisCompleted", self._on_analysis_completed)

        self._running = False
        self.logger.info(f"SOCPipeline initialized (dry_run={dry_run})")

    def start(self) -> None:
        """Start all agents and begin processing."""
        if self._running:
            self.logger.warning("Pipeline already running")
            return

        # Start state manager first
        self.state_manager.start()

        # Start main agents
        self.detector.start()
        self.analyst.start()
        self.remediator.start()

        # Start governance agents
        self.policy_agent.start()
        self.consensus_agent.start()
        self.human_approval.start()

        self._running = True
        mode = "DRY-RUN" if self.dry_run else "LIVE"
        self.logger.info(f"SOC Pipeline started in {mode} mode")

    def stop(self) -> None:
        """Stop all agents."""
        if not self._running:
            return

        # Stop in reverse order
        self.human_approval.stop()
        self.consensus_agent.stop()
        self.policy_agent.stop()

        self.remediator.stop()
        self.analyst.stop()
        self.detector.stop()

        self.state_manager.stop()

        self._running = False
        self.logger.info("SOC Pipeline stopped")

    def _on_analysis_completed(self, event: dict) -> None:
        """
        Bridge between AnalysisCompleted and RemediationProposed.

        This creates a remediation proposal based on the analyst's recommendation.
        """
        try:
            correlation_id = event.get("correlation_id")
            payload = event.get("payload", {})

            verdict = payload.get("verdict")
            recommended_action = payload.get("recommended_action", "monitor")
            risk_level = payload.get("risk_level", "low")

            # Only propose remediation for true positives or high-risk needs_investigation
            if verdict == "false_positive":
                self.logger.debug(f"Skipping remediation for false positive: {correlation_id}")
                return

            if verdict == "needs_investigation" and risk_level not in ("high", "critical"):
                self.logger.debug(f"Skipping remediation for low-risk investigation: {correlation_id}")
                return

            # Create remediation proposal
            proposal_event = {
                "event_id": str(uuid.uuid4()),
                "correlation_id": correlation_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "producer": "pipeline_orchestrator",
                "payload": {
                    "playbook_id": f"playbook-{str(uuid.uuid4())[:8]}",
                    "alert_id": payload.get("alert_id"),
                    "threat_type": payload.get("threat_type", "unknown"),
                    "proposed_actions": [
                        {
                            "action_id": str(uuid.uuid4())[:8],
                            "action_type": recommended_action,
                            "target": payload.get("context", {}),
                            "priority": 1
                        }
                    ],
                    "requires_approval": risk_level in ("high", "critical"),
                    "dry_run": self.dry_run,
                    "analysis_summary": {
                        "verdict": verdict,
                        "risk_level": risk_level,
                        "certainty_score": payload.get("certainty_score", 0)
                    }
                }
            }

            self.bus.publish("RemediationProposed", proposal_event)
            self.logger.debug(f"Remediation proposed for {correlation_id}: {recommended_action}")

        except Exception as e:
            self.logger.error(f"Error creating remediation proposal: {e}")

    # ========== Public API ==========

    def submit_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit a raw log event for processing.

        Args:
            log_data: Dictionary with log data (message, source, source_ip, etc.)

        Returns:
            Dictionary with correlation_id and event_id for tracking
        """
        if not self._running:
            raise RuntimeError("Pipeline not running. Call start() first.")

        event_id = str(uuid.uuid4())
        correlation_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        raw_event = {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "external",
            "payload": log_data
        }

        self.bus.publish("RawLogEvent", raw_event)

        self.logger.info(f"Log submitted: {correlation_id[:8]}...")

        return {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp
        }

    def submit_batch(self, logs: list) -> list:
        """
        Submit multiple log events.

        Args:
            logs: List of log data dictionaries

        Returns:
            List of submission results
        """
        return [self.submit_log(log) for log in logs]

    def get_incident(self, correlation_id: str) -> Optional[Dict[str, Any]]:
        """Get incident state by correlation_id."""
        return self.state_manager.get_incident(correlation_id)

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> list:
        """List incidents with optional filtering."""
        return self.state_manager.list_incidents(
            status=status,
            severity=severity,
            limit=limit
        )

    def get_pending_approvals(self) -> list:
        """Get incidents waiting for human approval."""
        return self.human_approval.get_pending_approvals()

    def approve_action(self, request_id: str, approver: str = "admin") -> bool:
        """
        Approve a pending remediation action.

        Args:
            request_id: The approval request ID
            approver: Name of the approver

        Returns:
            True if approved successfully
        """
        return self.human_approval.approve(request_id, approver)

    def reject_action(self, request_id: str, reason: str, rejector: str = "admin") -> bool:
        """
        Reject a pending remediation action.

        Args:
            request_id: The approval request ID
            reason: Reason for rejection
            rejector: Name of the rejector

        Returns:
            True if rejected successfully
        """
        return self.human_approval.reject(request_id, reason, rejector)

    def rollback_remediation(self, remediation_id: str) -> Dict[str, Any]:
        """
        Rollback a previously executed remediation.

        Args:
            remediation_id: The remediation ID to rollback

        Returns:
            Result of the rollback operation
        """
        result = self.remediator.rollback(remediation_id)
        return {
            "success": result.success,
            "action": result.action_type,
            "message": result.message
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics."""
        return {
            "running": self._running,
            "dry_run": self.dry_run,
            "detector": self.detector.get_stats(),
            "analyst": self.analyst.get_stats(),
            "remediator": self.remediator.get_stats(),
            "policy_agent": self.policy_agent.get_stats(),
            "consensus_agent": self.consensus_agent.get_stats(),
            "state_manager": self.state_manager.get_stats()
        }

    def get_remediation_history(self) -> list:
        """Get history of executed remediations."""
        return self.remediator.get_remediation_history()

    def reload_policy(self) -> bool:
        """Hot-reload the policy file."""
        return self.policy_agent.reload_policy()

    def get_policy_info(self) -> Dict[str, Any]:
        """Get information about the loaded policy."""
        return self.policy_agent.get_policy_info()

    def is_running(self) -> bool:
        """Check if the pipeline is running."""
        return self._running

    # ========== Context Manager ==========

    def __enter__(self):
        """Start pipeline when entering context."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop pipeline when exiting context."""
        self.stop()
        return False
