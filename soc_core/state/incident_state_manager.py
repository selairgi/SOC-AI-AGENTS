"""
Incident State Manager - Central state tracking for SOC incidents.

This component:
- Subscribes to ALL events on the EventBus
- Maintains incident state by correlation_id
- Stores all pipeline outputs without decision logic
- Provides query interface for chatbot/UI

IMPORTANT: This is NOT an agent - it only observes and records, never decides.

Usage:
    from soc_core.events import EventBus
    from soc_core.state import IncidentStateManager

    bus = EventBus()
    state_manager = IncidentStateManager(bus)
    state_manager.start()

    # Query incidents
    incident = state_manager.get_incident(correlation_id)
    all_incidents = state_manager.list_incidents()
"""

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from collections import OrderedDict
from pathlib import Path


@dataclass
class IncidentTimeline:
    """Single event in the incident timeline."""
    timestamp: str
    event_type: str
    producer: str
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IncidentState:
    """Complete state of an incident tracked by correlation_id."""
    correlation_id: str
    created_at: str
    updated_at: str
    status: str = "open"  # open, analyzing, remediating, resolved, closed

    # Pipeline outputs
    raw_event: Optional[Dict[str, Any]] = None
    detector_output: Optional[Dict[str, Any]] = None
    analyst_output: Optional[Dict[str, Any]] = None
    risk_assessment: Optional[Dict[str, Any]] = None
    policy_decision: Optional[Dict[str, Any]] = None
    remediation_decision: Optional[Dict[str, Any]] = None
    remediation_execution: Optional[Dict[str, Any]] = None
    human_approval: Optional[Dict[str, Any]] = None

    # Explainability
    explanations: List[str] = field(default_factory=list)
    timeline: List[IncidentTimeline] = field(default_factory=list)

    # Metadata
    alert_id: Optional[str] = None
    severity: Optional[str] = None
    threat_type: Optional[str] = None
    confidence: float = 0.0
    dry_run: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        # Convert timeline objects to dicts
        result['timeline'] = [asdict(t) if hasattr(t, '__dataclass_fields__') else t for t in self.timeline]
        return result


class IncidentStateManager:
    """
    Central state manager for SOC incidents.

    This component observes all events on the bus and maintains
    a complete picture of each incident's state. It does NOT
    make any decisions - it only records and provides query access.

    Thread-safe with LRU eviction for memory management.
    """

    # Event types to subscribe to
    TRACKED_EVENTS = [
        "RawLogEvent",
        "DetectorFinding",
        "AlertDetected",
        "ContextEnriched",
        "AnalysisCompleted",
        "AnalystAssessment",
        "RiskAssessment",
        "PolicyDecision",
        "RemediationProposed",
        "RemediationDecision",
        "RemediationExecuted",
        "HumanApproval",
    ]

    def __init__(
        self,
        event_bus,
        max_incidents: int = 10000,
        persist_path: Optional[str] = None,
        logger: logging.Logger = None
    ):
        """
        Initialize the incident state manager.

        Args:
            event_bus: EventBus instance to subscribe to
            max_incidents: Maximum incidents to keep in memory (LRU eviction)
            persist_path: Optional path to persist incidents to disk
            logger: Optional logger instance
        """
        self.bus = event_bus
        self.max_incidents = max_incidents
        self.persist_path = persist_path
        self.logger = logger or logging.getLogger("IncidentStateManager")

        # Incident storage with LRU ordering
        self._incidents: OrderedDict[str, IncidentState] = OrderedDict()
        self._lock = threading.RLock()

        # Track subscriptions for cleanup
        self._subscribed = False
        self._handlers: Dict[str, callable] = {}

        # Statistics
        self.stats = {
            "events_received": 0,
            "incidents_created": 0,
            "incidents_updated": 0,
            "incidents_evicted": 0,
            "start_time": None,
        }

    def start(self) -> None:
        """Start listening to events on the bus."""
        if self._subscribed:
            self.logger.warning("IncidentStateManager already started")
            return

        # Subscribe to all tracked event types
        for event_type in self.TRACKED_EVENTS:
            handler = self._create_handler(event_type)
            self._handlers[event_type] = handler
            self.bus.subscribe(event_type, handler)

        self._subscribed = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.logger.info(f"IncidentStateManager started, tracking {len(self.TRACKED_EVENTS)} event types")

    def stop(self) -> None:
        """Stop listening to events."""
        if not self._subscribed:
            return

        for event_type, handler in self._handlers.items():
            self.bus.unsubscribe(event_type, handler)

        self._handlers.clear()
        self._subscribed = False

        # Persist if configured
        if self.persist_path:
            self._persist_incidents()

        self.logger.info("IncidentStateManager stopped")
        self._log_stats()

    def _create_handler(self, event_type: str) -> callable:
        """Create an event handler for a specific event type."""
        def handler(event: dict) -> None:
            self._handle_event(event_type, event)
        return handler

    def _handle_event(self, event_type: str, event: dict) -> None:
        """Handle an incoming event and update incident state."""
        self.stats["events_received"] += 1

        try:
            correlation_id = event.get("correlation_id")
            if not correlation_id:
                self.logger.debug(f"Event {event_type} missing correlation_id, skipping")
                return

            with self._lock:
                # Get or create incident
                incident = self._get_or_create_incident(correlation_id)

                # Update incident based on event type
                self._update_incident(incident, event_type, event)

                # Move to end (LRU)
                self._incidents.move_to_end(correlation_id)

        except Exception as e:
            self.logger.error(f"Error handling {event_type}: {e}")

    def _get_or_create_incident(self, correlation_id: str) -> IncidentState:
        """Get existing incident or create new one."""
        if correlation_id in self._incidents:
            return self._incidents[correlation_id]

        # Evict oldest if at capacity
        while len(self._incidents) >= self.max_incidents:
            oldest_id, _ = self._incidents.popitem(last=False)
            self.stats["incidents_evicted"] += 1
            self.logger.debug(f"Evicted incident: {oldest_id}")

        # Create new incident
        now = datetime.now(timezone.utc).isoformat()
        incident = IncidentState(
            correlation_id=correlation_id,
            created_at=now,
            updated_at=now
        )
        self._incidents[correlation_id] = incident
        self.stats["incidents_created"] += 1

        return incident

    def _update_incident(self, incident: IncidentState, event_type: str, event: dict) -> None:
        """Update incident state based on event type."""
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        self.stats["incidents_updated"] += 1

        payload = event.get("payload", {})
        producer = event.get("producer", "unknown")
        timestamp = event.get("timestamp", incident.updated_at)

        # Add to timeline
        timeline_entry = IncidentTimeline(
            timestamp=timestamp,
            event_type=event_type,
            producer=producer,
            summary=self._create_summary(event_type, payload),
            details={"event_id": event.get("event_id")}
        )
        incident.timeline.append(timeline_entry)

        # Update specific fields based on event type
        if event_type == "RawLogEvent":
            incident.raw_event = event
            incident.status = "open"
            incident.explanations.append(f"Raw event received from {producer}")

        elif event_type in ("DetectorFinding", "AlertDetected"):
            incident.detector_output = event
            incident.status = "analyzing"
            incident.alert_id = payload.get("alert_id")
            incident.severity = payload.get("severity")
            incident.threat_type = payload.get("threat_type")
            incident.confidence = payload.get("confidence", 0.0)
            incident.explanations.append(
                f"Threat detected: {payload.get('threat_type', 'unknown')} "
                f"(severity: {incident.severity}, confidence: {incident.confidence:.0%})"
            )

        elif event_type in ("AnalysisCompleted", "AnalystAssessment"):
            incident.analyst_output = event
            incident.explanations.append(
                f"Analysis: {payload.get('verdict', payload.get('recommended_action', 'unknown'))} "
                f"(certainty: {payload.get('certainty_score', payload.get('confidence', 0)):.0%})"
            )

        elif event_type == "RiskAssessment":
            incident.risk_assessment = event
            incident.explanations.append(
                f"Risk: {payload.get('overall_risk_level', 'unknown')} "
                f"(score: {payload.get('risk_score_numeric', 0):.0f})"
            )

        elif event_type == "PolicyDecision":
            incident.policy_decision = event
            incident.explanations.append(
                f"Policy decision: {payload.get('decision', 'unknown')} - {payload.get('reason', '')}"
            )

        elif event_type in ("RemediationProposed", "RemediationDecision"):
            incident.remediation_decision = event
            incident.status = "remediating"
            incident.dry_run = payload.get("dry_run", True)
            action = payload.get("action", payload.get("proposed_actions", "unknown"))
            incident.explanations.append(f"Remediation decided: {action}")

        elif event_type == "RemediationExecuted":
            incident.remediation_execution = event
            incident.status = "resolved"
            incident.dry_run = payload.get("dry_run", True)
            incident.explanations.append(
                f"Remediation executed: {payload.get('action', 'unknown')} "
                f"(dry_run: {incident.dry_run})"
            )

        elif event_type == "HumanApproval":
            incident.human_approval = event
            approved = payload.get("approved", False)
            incident.explanations.append(
                f"Human {'approved' if approved else 'rejected'} remediation"
            )

    def _create_summary(self, event_type: str, payload: dict) -> str:
        """Create a human-readable summary for timeline entry."""
        summaries = {
            "RawLogEvent": f"Log received: {payload.get('message', '')[:50]}...",
            "DetectorFinding": f"Detection: {payload.get('threat_type', 'unknown')}",
            "AlertDetected": f"Alert: {payload.get('severity', 'unknown')} - {payload.get('threat_type', '')}",
            "AnalysisCompleted": f"Verdict: {payload.get('verdict', 'unknown')}",
            "AnalystAssessment": f"Assessment: {payload.get('recommended_action', 'unknown')}",
            "RiskAssessment": f"Risk: {payload.get('overall_risk_level', 'unknown')}",
            "PolicyDecision": f"Policy: {payload.get('decision', 'unknown')}",
            "RemediationDecision": f"Decision: {payload.get('action', 'pending')}",
            "RemediationExecuted": f"Executed: {payload.get('action', 'unknown')}",
            "HumanApproval": f"Human: {'Approved' if payload.get('approved') else 'Rejected'}",
        }
        return summaries.get(event_type, f"{event_type}: {str(payload)[:50]}...")

    # ========== Query Interface ==========

    def get_incident(self, correlation_id: str) -> Optional[Dict[str, Any]]:
        """
        Get incident state by correlation_id.

        Args:
            correlation_id: The correlation ID to look up

        Returns:
            Incident state as dictionary, or None if not found
        """
        with self._lock:
            incident = self._incidents.get(correlation_id)
            if incident:
                return incident.to_dict()
            return None

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List incidents with optional filtering.

        Args:
            status: Filter by status (open, analyzing, remediating, resolved)
            severity: Filter by severity
            limit: Maximum number of incidents to return
            offset: Number of incidents to skip

        Returns:
            List of incident dictionaries
        """
        with self._lock:
            incidents = list(self._incidents.values())

            # Apply filters
            if status:
                incidents = [i for i in incidents if i.status == status]
            if severity:
                incidents = [i for i in incidents if i.severity == severity]

            # Sort by updated_at descending (most recent first)
            incidents.sort(key=lambda x: x.updated_at, reverse=True)

            # Apply pagination
            incidents = incidents[offset:offset + limit]

            return [i.to_dict() for i in incidents]

    def get_incident_count(self) -> int:
        """Get total number of tracked incidents."""
        with self._lock:
            return len(self._incidents)

    def get_timeline(self, correlation_id: str) -> List[Dict[str, Any]]:
        """Get the timeline for a specific incident."""
        with self._lock:
            incident = self._incidents.get(correlation_id)
            if incident:
                return [asdict(t) for t in incident.timeline]
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get state manager statistics."""
        with self._lock:
            return {
                **self.stats,
                "current_incidents": len(self._incidents),
                "max_incidents": self.max_incidents,
            }

    # ========== Persistence ==========

    def _persist_incidents(self) -> None:
        """Persist incidents to disk."""
        if not self.persist_path:
            return

        try:
            path = Path(self.persist_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with self._lock:
                data = {
                    cid: incident.to_dict()
                    for cid, incident in self._incidents.items()
                }

            with open(path, 'w') as f:
                json.dump(data, f, indent=2)

            self.logger.info(f"Persisted {len(data)} incidents to {path}")

        except Exception as e:
            self.logger.error(f"Failed to persist incidents: {e}")

    def _log_stats(self) -> None:
        """Log statistics."""
        stats = self.get_stats()
        self.logger.info("=== IncidentStateManager Statistics ===")
        self.logger.info(f"Events received: {stats['events_received']}")
        self.logger.info(f"Incidents created: {stats['incidents_created']}")
        self.logger.info(f"Incidents updated: {stats['incidents_updated']}")
        self.logger.info(f"Incidents evicted: {stats['incidents_evicted']}")
        self.logger.info(f"Current incidents: {stats['current_incidents']}")
