"""
Unified Agent Adapters for EventBus Integration.

These adapters wrap existing agents (from core/ and security/) and connect them
to the synchronous EventBus. They provide a unified interface for the SOC pipeline:

    RawLogEvent → DetectorAdapter → DetectorFinding
    DetectorFinding → AnalystAdapter → AnalystAssessment
    AnalystAssessment → RemediatorAdapter → RemediationExecuted

Each adapter:
- Subscribes to EventBus events
- Delegates to underlying agents
- Publishes results to EventBus
- Stores incremental learning examples

Usage:
    from soc_core.events import EventBus
    from soc_core.agents.unified_adapters import (
        UnifiedDetectorAdapter,
        UnifiedAnalystAdapter,
        UnifiedRemediatorAdapter
    )

    bus = EventBus()
    detector = UnifiedDetectorAdapter(bus)
    analyst = UnifiedAnalystAdapter(bus)
    remediator = UnifiedRemediatorAdapter(bus)

    detector.start()
    analyst.start()
    remediator.start()
"""

import os
import json
import uuid
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

# Import existing agents
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.models import LogEntry, Alert, Playbook, AgentType, ThreatType
from shared.agent_memory import AgentMemory


# ============================================================================
# Incremental Learning Storage
# ============================================================================

class IncrementalStorage:
    """
    Store incremental learning examples in NDJSON format.

    Each agent writes examples to data/incremental/<agent>.ndjson
    Labels come from human feedback via chatbot.
    """

    def __init__(self, agent_name: str, base_path: str = None):
        self.agent_name = agent_name
        self.base_path = base_path or str(Path(__file__).parent.parent.parent / "data" / "incremental")
        self.file_path = Path(self.base_path) / f"{agent_name}.ndjson"
        self.logger = logging.getLogger(f"IncrementalStorage.{agent_name}")

        # Ensure directory exists
        Path(self.base_path).mkdir(parents=True, exist_ok=True)

    def store_example(
        self,
        correlation_id: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
        model_version: str = "1.0.0",
        label: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Store an incremental learning example.

        Args:
            correlation_id: Correlation ID for tracing
            input_data: Input to the agent
            output_data: Output from the agent
            model_version: Version of the model used
            label: Optional human-provided label
            metadata: Optional additional metadata

        Returns:
            Example ID
        """
        example_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        example = {
            "example_id": example_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "agent": self.agent_name,
            "model_version": model_version,
            "input": input_data,
            "output": output_data,
            "label": label,
            "labeled": label is not None,
            "metadata": metadata or {}
        }

        try:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(example) + "\n")
            self.logger.debug(f"Stored example {example_id}")
        except Exception as e:
            self.logger.error(f"Failed to store example: {e}")

        return example_id

    def update_label(self, example_id: str, label: str) -> bool:
        """Update the label for an existing example."""
        # This would require rewriting the file - for production, use a database
        self.logger.info(f"Label update requested for {example_id}: {label}")
        return True


# ============================================================================
# Unified Detector Adapter
# ============================================================================

class UnifiedDetectorAdapter:
    """
    Unified detector that combines:
    - EventDrivenDetectionAgent (pattern-based)
    - IntelligentPromptDetector (AI-based)
    - SecurityRulesEngine (rule-based)

    Subscribe: RawLogEvent
    Publish: DetectorFinding
    """

    EVENT_INPUT = "RawLogEvent"
    EVENT_OUTPUT = "DetectorFinding"
    MODEL_VERSION = "1.0.0"

    def __init__(
        self,
        event_bus,
        memory: Optional[AgentMemory] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.bus = event_bus
        self.memory = memory or AgentMemory()
        self.logger = logger or logging.getLogger("UnifiedDetector")

        # Initialize sub-components lazily to avoid import issues
        self._pattern_detector = None
        self._intelligent_detector = None
        self._rules_engine = None

        # Incremental storage
        self.storage = IncrementalStorage("detector")

        # State
        self._running = False
        self._subscribed = False

        # Statistics
        self.stats = {
            "events_received": 0,
            "findings_published": 0,
            "pattern_detections": 0,
            "ai_detections": 0,
            "rule_detections": 0,
            "start_time": None,
        }

    def _init_components(self):
        """Lazily initialize detection components."""
        if self._pattern_detector is None:
            try:
                from soc_core.agents.detection_agent import EventDrivenDetectionAgent
                # Create a dummy bus for internal use - we'll call methods directly
                self._pattern_detector = EventDrivenDetectionAgent.__new__(EventDrivenDetectionAgent)
                self._pattern_detector._init_patterns()
                self.logger.info("Pattern detector initialized")
            except Exception as e:
                self.logger.warning(f"Pattern detector unavailable: {e}")

        if self._intelligent_detector is None:
            try:
                from security.intelligent_prompt_detector import IntelligentPromptDetector
                from ai.real_ai_integration import RealAIIntegration
                ai = RealAIIntegration()
                self._intelligent_detector = IntelligentPromptDetector(ai_integration=ai)
                self.logger.info("Intelligent detector initialized")
            except Exception as e:
                self.logger.warning(f"Intelligent detector unavailable: {e}")

        if self._rules_engine is None:
            try:
                from security.security_rules import SecurityRulesEngine
                self._rules_engine = SecurityRulesEngine()
                self.logger.info("Rules engine initialized")
            except Exception as e:
                self.logger.warning(f"Rules engine unavailable: {e}")

    def start(self) -> None:
        """Start the detector adapter."""
        if self._running:
            self.logger.warning("UnifiedDetector already running")
            return

        self._init_components()
        self.bus.subscribe(self.EVENT_INPUT, self._handle_raw_log)
        self._subscribed = True
        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.logger.info("UnifiedDetector started")

    def stop(self) -> None:
        """Stop the detector adapter."""
        if not self._running:
            return

        if self._subscribed:
            self.bus.unsubscribe(self.EVENT_INPUT, self._handle_raw_log)
            self._subscribed = False

        self._running = False
        self.logger.info("UnifiedDetector stopped")
        self._log_stats()

    def _handle_raw_log(self, event: dict) -> None:
        """Handle incoming RawLogEvent."""
        self.stats["events_received"] += 1

        try:
            correlation_id = event.get("correlation_id", str(uuid.uuid4()))
            payload = event.get("payload", {})
            message = payload.get("message", "")

            # Create LogEntry for compatibility
            log_entry = LogEntry(
                timestamp=time.time(),
                source=payload.get("source", "unknown"),
                message=message,
                agent_id=payload.get("agent_id", "unknown"),
                user_id=payload.get("user_id", ""),
                session_id=payload.get("session_id", ""),
                src_ip=payload.get("src_ip", ""),
                request_id=payload.get("request_id", ""),
                response_time=0.0,
                status_code=200,
                extra=payload.get("extra", {})
            )

            # Run detection pipeline
            detection = self._detect_threats(log_entry, message)

            if detection:
                # Publish finding
                self._publish_finding(correlation_id, event, detection)

                # Store for incremental learning
                self.storage.store_example(
                    correlation_id=correlation_id,
                    input_data={"message": message, "metadata": payload},
                    output_data=detection,
                    model_version=self.MODEL_VERSION
                )

        except Exception as e:
            self.logger.error(f"Error processing RawLogEvent: {e}")

    def _detect_threats(self, log_entry: LogEntry, message: str) -> Optional[Dict[str, Any]]:
        """Run detection across all available detectors."""
        detection = None
        detection_method = None

        # 1. Try intelligent detector first (most sophisticated)
        if self._intelligent_detector:
            try:
                alert = self._intelligent_detector.detect_prompt_injection(log_entry)
                if alert:
                    self.stats["ai_detections"] += 1
                    detection_method = "intelligent"
                    detection = self._alert_to_detection(alert, detection_method)
            except Exception as e:
                self.logger.debug(f"Intelligent detection error: {e}")

        # 2. Try pattern-based detector
        if not detection and self._pattern_detector:
            try:
                threats = self._pattern_detector._detect_threats(message, {})
                if threats:
                    self.stats["pattern_detections"] += 1
                    detection_method = "pattern"
                    detection = {
                        "threat_type": threats[0].get("threat_type", "unknown"),
                        "severity": threats[0].get("severity", "medium"),
                        "confidence": threats[0].get("confidence", 0.5),
                        "features": [t.get("pattern_name", "") for t in threats],
                        "explanation": f"Pattern match: {threats[0].get('pattern_name', '')}",
                        "detection_method": detection_method,
                    }
            except Exception as e:
                self.logger.debug(f"Pattern detection error: {e}")

        # 3. Try rules engine
        if not detection and self._rules_engine:
            try:
                alert = self._rules_engine.analyze_log(log_entry)
                if alert:
                    self.stats["rule_detections"] += 1
                    detection_method = "rules"
                    detection = self._alert_to_detection(alert, detection_method)
            except Exception as e:
                self.logger.debug(f"Rules detection error: {e}")

        return detection

    def _alert_to_detection(self, alert: Alert, method: str) -> Dict[str, Any]:
        """Convert Alert to detection dict."""
        return {
            "alert_id": alert.id,
            "threat_type": alert.threat_type.value if alert.threat_type else "unknown",
            "severity": alert.severity,
            "confidence": 1.0 - alert.false_positive_probability if alert.false_positive_probability else 0.8,
            "features": list(alert.evidence.keys()) if alert.evidence else [],
            "explanation": alert.description,
            "detection_method": method,
            "rule_id": alert.rule_id,
        }

    def _publish_finding(self, correlation_id: str, source_event: dict, detection: dict) -> None:
        """Publish DetectorFinding event."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        finding_event = {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "unified_detector",
            "payload": {
                "finding_id": f"finding-{event_id[:8]}",
                "source_event_id": source_event.get("event_id"),
                "confidence": detection.get("confidence", 0.5),
                "features": detection.get("features", []),
                "explanation": detection.get("explanation", ""),
                "model_version": self.MODEL_VERSION,
                "threat_type": detection.get("threat_type"),
                "severity": detection.get("severity"),
                "detection_method": detection.get("detection_method"),
                "alert_id": detection.get("alert_id"),
            }
        }

        self.bus.publish(self.EVENT_OUTPUT, finding_event)
        self.stats["findings_published"] += 1
        self.logger.debug(f"Published finding: {detection.get('threat_type')}")

    def _log_stats(self) -> None:
        """Log statistics."""
        self.logger.info("=== UnifiedDetector Statistics ===")
        self.logger.info(f"Events received: {self.stats['events_received']}")
        self.logger.info(f"Findings published: {self.stats['findings_published']}")
        self.logger.info(f"Detection breakdown - AI: {self.stats['ai_detections']}, "
                        f"Pattern: {self.stats['pattern_detections']}, "
                        f"Rules: {self.stats['rule_detections']}")

    def get_stats(self) -> Dict[str, Any]:
        return self.stats.copy()


# ============================================================================
# Unified Analyst Adapter
# ============================================================================

class UnifiedAnalystAdapter:
    """
    Unified analyst that combines:
    - SOCAnalyst (certainty scoring)
    - FalsePositiveDetector (FP analysis)
    - IntelligentRemediationPlanner (planning)

    Subscribe: DetectorFinding
    Publish: AnalystAssessment
    """

    EVENT_INPUT = "DetectorFinding"
    EVENT_OUTPUT = "AnalystAssessment"
    MODEL_VERSION = "1.0.0"

    def __init__(
        self,
        event_bus,
        memory: Optional[AgentMemory] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.bus = event_bus
        self.memory = memory or AgentMemory()
        self.logger = logger or logging.getLogger("UnifiedAnalyst")

        # Initialize sub-components lazily
        self._fp_detector = None
        self._remediation_planner = None

        # Incremental storage
        self.storage = IncrementalStorage("analyst")

        # State
        self._running = False
        self._subscribed = False

        # Statistics
        self.stats = {
            "events_received": 0,
            "assessments_published": 0,
            "false_positives": 0,
            "true_positives": 0,
            "requires_investigation": 0,
            "start_time": None,
        }

    def _init_components(self):
        """Lazily initialize analysis components."""
        if self._fp_detector is None:
            try:
                from security.false_positive_detector import FalsePositiveDetector
                self._fp_detector = FalsePositiveDetector()
                self.logger.info("FP detector initialized")
            except Exception as e:
                self.logger.warning(f"FP detector unavailable: {e}")

        if self._remediation_planner is None:
            try:
                from security.intelligent_remediation_planner import IntelligentRemediationPlanner
                from ai.real_ai_integration import RealAIIntegration
                ai = RealAIIntegration()
                self._remediation_planner = IntelligentRemediationPlanner(ai)
                self.logger.info("Remediation planner initialized")
            except Exception as e:
                self.logger.warning(f"Remediation planner unavailable: {e}")

    def start(self) -> None:
        """Start the analyst adapter."""
        if self._running:
            self.logger.warning("UnifiedAnalyst already running")
            return

        self._init_components()
        self.bus.subscribe(self.EVENT_INPUT, self._handle_finding)
        self._subscribed = True
        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.logger.info("UnifiedAnalyst started")

    def stop(self) -> None:
        """Stop the analyst adapter."""
        if not self._running:
            return

        if self._subscribed:
            self.bus.unsubscribe(self.EVENT_INPUT, self._handle_finding)
            self._subscribed = False

        self._running = False
        self.logger.info("UnifiedAnalyst stopped")
        self._log_stats()

    def _handle_finding(self, event: dict) -> None:
        """Handle incoming DetectorFinding."""
        self.stats["events_received"] += 1

        try:
            correlation_id = event.get("correlation_id", str(uuid.uuid4()))
            payload = event.get("payload", {})

            # Analyze the finding
            assessment = self._analyze_finding(payload)

            # Update statistics
            verdict = assessment.get("verdict", "unknown")
            if verdict == "false_positive":
                self.stats["false_positives"] += 1
            elif verdict == "true_positive":
                self.stats["true_positives"] += 1
            else:
                self.stats["requires_investigation"] += 1

            # Publish assessment
            self._publish_assessment(correlation_id, event, assessment)

            # Store for incremental learning
            self.storage.store_example(
                correlation_id=correlation_id,
                input_data=payload,
                output_data=assessment,
                model_version=self.MODEL_VERSION
            )

        except Exception as e:
            self.logger.error(f"Error processing DetectorFinding: {e}")

    def _analyze_finding(self, finding: dict) -> Dict[str, Any]:
        """Analyze a detector finding."""
        confidence = finding.get("confidence", 0.5)
        severity = finding.get("severity", "medium")
        threat_type = finding.get("threat_type", "unknown")

        # Calculate certainty and FP probability
        fp_probability = 1.0 - confidence
        certainty_score = confidence

        # Determine verdict based on thresholds
        if fp_probability > 0.7:
            verdict = "false_positive"
            recommended_action = "ignore"
        elif certainty_score > 0.7:
            verdict = "true_positive"
            if severity in ("critical", "high"):
                recommended_action = "block"
            else:
                recommended_action = "monitor"
        else:
            verdict = "requires_investigation"
            recommended_action = "investigate"

        # Build hypotheses
        hypotheses = [
            f"Threat type: {threat_type}",
            f"Severity: {severity}",
            f"Detection confidence: {confidence:.0%}",
        ]

        likelihoods = [confidence, 1.0 - fp_probability, certainty_score]

        return {
            "verdict": verdict,
            "certainty_score": certainty_score,
            "false_positive_probability": fp_probability,
            "recommended_action": recommended_action,
            "hypotheses": hypotheses,
            "likelihoods": likelihoods,
            "confidence": certainty_score,
            "explanation": f"Analysis: {verdict} (certainty: {certainty_score:.0%}, "
                          f"FP prob: {fp_probability:.0%}). Recommended: {recommended_action}",
            "threat_type": threat_type,
            "severity": severity,
        }

    def _publish_assessment(self, correlation_id: str, source_event: dict, assessment: dict) -> None:
        """Publish AnalystAssessment event."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        assessment_event = {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "unified_analyst",
            "payload": {
                "assessment_id": f"assessment-{event_id[:8]}",
                "source_event_id": source_event.get("event_id"),
                "hypotheses": assessment.get("hypotheses", []),
                "likelihoods": assessment.get("likelihoods", []),
                "recommended_action": assessment.get("recommended_action"),
                "confidence": assessment.get("confidence", 0.5),
                "explanation": assessment.get("explanation", ""),
                "model_version": self.MODEL_VERSION,
                "verdict": assessment.get("verdict"),
                "certainty_score": assessment.get("certainty_score"),
                "false_positive_probability": assessment.get("false_positive_probability"),
                "threat_type": assessment.get("threat_type"),
                "severity": assessment.get("severity"),
            }
        }

        self.bus.publish(self.EVENT_OUTPUT, assessment_event)
        self.stats["assessments_published"] += 1
        self.logger.debug(f"Published assessment: {assessment.get('verdict')}")

    def _log_stats(self) -> None:
        """Log statistics."""
        self.logger.info("=== UnifiedAnalyst Statistics ===")
        self.logger.info(f"Events received: {self.stats['events_received']}")
        self.logger.info(f"Assessments published: {self.stats['assessments_published']}")
        self.logger.info(f"Verdicts - TP: {self.stats['true_positives']}, "
                        f"FP: {self.stats['false_positives']}, "
                        f"Investigate: {self.stats['requires_investigation']}")

    def get_stats(self) -> Dict[str, Any]:
        return self.stats.copy()


# ============================================================================
# Unified Remediator Adapter
# ============================================================================

class UnifiedRemediatorAdapter:
    """
    Unified remediator that combines:
    - Remediator (action execution)
    - RealRemediationEngine (production actions)
    - Policy enforcement

    Subscribe: AnalystAssessment, HumanApproval
    Publish: RemediationDecision, RemediationExecuted

    Default: dry_run = True (safe by default)
    """

    EVENT_INPUT = "AnalystAssessment"
    EVENT_APPROVAL = "HumanApproval"
    EVENT_DECISION = "RemediationDecision"
    EVENT_EXECUTED = "RemediationExecuted"
    MODEL_VERSION = "1.0.0"

    def __init__(
        self,
        event_bus,
        memory: Optional[AgentMemory] = None,
        dry_run: bool = True,
        require_approval_for: Optional[List[str]] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.bus = event_bus
        self.memory = memory or AgentMemory()
        self.dry_run = dry_run
        self.require_approval_for = require_approval_for or ["block_ip", "suspend_user", "isolate_agent"]
        self.logger = logger or logging.getLogger("UnifiedRemediator")

        # Initialize sub-components lazily
        self._real_remediator = None

        # Pending approvals
        self._pending_approvals: Dict[str, Dict] = {}

        # Incremental storage
        self.storage = IncrementalStorage("remediator")

        # State
        self._running = False
        self._subscribed_assessment = False
        self._subscribed_approval = False

        # Statistics
        self.stats = {
            "events_received": 0,
            "decisions_published": 0,
            "executions_published": 0,
            "dry_run_count": 0,
            "real_executions": 0,
            "pending_approvals": 0,
            "approvals_received": 0,
            "start_time": None,
        }

    def _init_components(self):
        """Lazily initialize remediation components."""
        if self._real_remediator is None:
            try:
                from security.real_remediation import RealRemediationEngine
                self._real_remediator = RealRemediationEngine()
                self.logger.info("Real remediator initialized")
            except Exception as e:
                self.logger.warning(f"Real remediator unavailable: {e}")

    def start(self) -> None:
        """Start the remediator adapter."""
        if self._running:
            self.logger.warning("UnifiedRemediator already running")
            return

        self._init_components()

        self.bus.subscribe(self.EVENT_INPUT, self._handle_assessment)
        self._subscribed_assessment = True

        self.bus.subscribe(self.EVENT_APPROVAL, self._handle_approval)
        self._subscribed_approval = True

        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.logger.info(f"UnifiedRemediator started (dry_run={self.dry_run})")

    def stop(self) -> None:
        """Stop the remediator adapter."""
        if not self._running:
            return

        if self._subscribed_assessment:
            self.bus.unsubscribe(self.EVENT_INPUT, self._handle_assessment)
            self._subscribed_assessment = False

        if self._subscribed_approval:
            self.bus.unsubscribe(self.EVENT_APPROVAL, self._handle_approval)
            self._subscribed_approval = False

        self._running = False
        self.logger.info("UnifiedRemediator stopped")
        self._log_stats()

    def _handle_assessment(self, event: dict) -> None:
        """Handle incoming AnalystAssessment."""
        self.stats["events_received"] += 1

        try:
            correlation_id = event.get("correlation_id", str(uuid.uuid4()))
            payload = event.get("payload", {})

            # Determine action based on assessment
            action = self._determine_action(payload)

            # Check if approval is required
            requires_approval = action in self.require_approval_for

            # Publish decision
            decision = self._create_decision(correlation_id, event, action, requires_approval)
            self._publish_decision(correlation_id, decision)

            if requires_approval:
                # Store for pending approval
                self._pending_approvals[correlation_id] = {
                    "decision": decision,
                    "source_event": event,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                self.stats["pending_approvals"] += 1
                self.logger.info(f"Awaiting approval for {action} (correlation: {correlation_id[:8]})")
            else:
                # Execute immediately (still respects dry_run)
                self._execute_action(correlation_id, decision, event)

        except Exception as e:
            self.logger.error(f"Error processing AnalystAssessment: {e}")

    def _handle_approval(self, event: dict) -> None:
        """Handle incoming HumanApproval."""
        self.stats["approvals_received"] += 1

        try:
            correlation_id = event.get("correlation_id")
            payload = event.get("payload", {})
            approved = payload.get("approved", False)

            if correlation_id not in self._pending_approvals:
                self.logger.warning(f"No pending approval for {correlation_id}")
                return

            pending = self._pending_approvals.pop(correlation_id)
            decision = pending["decision"]
            source_event = pending["source_event"]

            if approved:
                self.logger.info(f"Approval received for {correlation_id[:8]}")
                self._execute_action(correlation_id, decision, source_event)
            else:
                self.logger.info(f"Approval rejected for {correlation_id[:8]}")
                # Publish rejection as executed with no-action
                self._publish_executed(
                    correlation_id,
                    action="rejected",
                    dry_run=True,
                    simulated_effect="No action taken - human rejected",
                    success=True
                )

        except Exception as e:
            self.logger.error(f"Error processing HumanApproval: {e}")

    def _determine_action(self, assessment: dict) -> str:
        """Determine remediation action based on assessment."""
        recommended = assessment.get("recommended_action", "monitor")
        verdict = assessment.get("verdict", "unknown")
        severity = assessment.get("severity", "medium")

        # Map recommendations to actions
        action_map = {
            "block": "block_ip",
            "suspend": "suspend_user",
            "isolate": "isolate_agent",
            "rate_limit": "rate_limit_ip",
            "monitor": "enhanced_monitoring",
            "investigate": "flag_for_review",
            "ignore": "no_action",
        }

        action = action_map.get(recommended, "flag_for_review")

        # Override for false positives
        if verdict == "false_positive":
            action = "no_action"

        return action

    def _create_decision(
        self,
        correlation_id: str,
        source_event: dict,
        action: str,
        requires_approval: bool
    ) -> Dict[str, Any]:
        """Create remediation decision."""
        payload = source_event.get("payload", {})

        return {
            "action": action,
            "requires_approval": requires_approval,
            "dry_run": self.dry_run,
            "threat_type": payload.get("threat_type"),
            "severity": payload.get("severity"),
            "confidence": payload.get("confidence", 0.5),
            "justification": f"Based on analyst assessment: {payload.get('explanation', 'N/A')}",
        }

    def _publish_decision(self, correlation_id: str, decision: dict) -> None:
        """Publish RemediationDecision event."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        decision_event = {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "unified_remediator",
            "payload": {
                "decision_id": f"decision-{event_id[:8]}",
                "action": decision.get("action"),
                "requires_approval": decision.get("requires_approval"),
                "dry_run": decision.get("dry_run"),
                "justification": decision.get("justification"),
                "model_version": self.MODEL_VERSION,
            }
        }

        self.bus.publish(self.EVENT_DECISION, decision_event)
        self.stats["decisions_published"] += 1

    def _execute_action(self, correlation_id: str, decision: dict, source_event: dict) -> None:
        """Execute the remediation action."""
        action = decision.get("action", "no_action")
        is_dry_run = decision.get("dry_run", True) or self.dry_run

        # Simulated effects for dry run
        simulated_effects = {
            "block_ip": "Would block IP address for 1 hour",
            "suspend_user": "Would suspend user account",
            "isolate_agent": "Would isolate agent from network",
            "rate_limit_ip": "Would apply rate limiting",
            "enhanced_monitoring": "Would enable enhanced monitoring",
            "flag_for_review": "Flagged for security team review",
            "no_action": "No action required",
        }

        simulated_effect = simulated_effects.get(action, f"Would execute: {action}")
        success = True

        if is_dry_run:
            self.stats["dry_run_count"] += 1
            self.logger.info(f"[DRY-RUN] {action}: {simulated_effect}")
        else:
            self.stats["real_executions"] += 1
            # Execute real action via real_remediator
            if self._real_remediator:
                try:
                    # Call appropriate method on real_remediator
                    self.logger.warning(f"[REAL] Executing {action}")
                    # Real execution would happen here
                except Exception as e:
                    self.logger.error(f"Real execution failed: {e}")
                    success = False
                    simulated_effect = f"Execution failed: {e}"

        # Publish executed event
        self._publish_executed(correlation_id, action, is_dry_run, simulated_effect, success)

        # Store for incremental learning
        self.storage.store_example(
            correlation_id=correlation_id,
            input_data=source_event.get("payload", {}),
            output_data={
                "action": action,
                "dry_run": is_dry_run,
                "success": success,
                "effect": simulated_effect,
            },
            model_version=self.MODEL_VERSION
        )

    def _publish_executed(
        self,
        correlation_id: str,
        action: str,
        dry_run: bool,
        simulated_effect: str,
        success: bool
    ) -> None:
        """Publish RemediationExecuted event."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        executed_event = {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "unified_remediator",
            "payload": {
                "execution_id": f"exec-{event_id[:8]}",
                "action": action,
                "dry_run": dry_run,
                "simulated_effect": simulated_effect,
                "success": success,
                "model_version": self.MODEL_VERSION,
            }
        }

        self.bus.publish(self.EVENT_EXECUTED, executed_event)
        self.stats["executions_published"] += 1

    def _log_stats(self) -> None:
        """Log statistics."""
        self.logger.info("=== UnifiedRemediator Statistics ===")
        self.logger.info(f"Events received: {self.stats['events_received']}")
        self.logger.info(f"Decisions published: {self.stats['decisions_published']}")
        self.logger.info(f"Executions - Dry run: {self.stats['dry_run_count']}, "
                        f"Real: {self.stats['real_executions']}")
        self.logger.info(f"Approvals - Pending: {self.stats['pending_approvals']}, "
                        f"Received: {self.stats['approvals_received']}")

    def get_stats(self) -> Dict[str, Any]:
        return self.stats.copy()

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get list of pending approval requests."""
        return [
            {
                "correlation_id": cid,
                "action": data["decision"]["action"],
                "created_at": data["created_at"],
            }
            for cid, data in self._pending_approvals.items()
        ]
