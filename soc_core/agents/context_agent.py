"""
Context Agent for alert enrichment.

This agent subscribes to AlertDetected events, maintains incident context,
and publishes ContextEnriched events. It is fully optional and does not
affect existing alert processing flows.

Usage:
    from soc_core.events import EventBus
    from soc_core.agents import ContextAgent

    bus = EventBus()
    context_agent = ContextAgent(bus)
    context_agent.start()

    # Alerts will be automatically enriched with context
    # Subscribe to ContextEnriched to receive enriched alerts
    bus.subscribe("ContextEnriched", my_handler)
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field


@dataclass
class IncidentState:
    """Internal state for tracking an incident."""
    incident_id: str
    correlation_id: str
    first_seen: str
    last_seen: str
    alert_count: int = 0
    threat_types: Set[str] = field(default_factory=set)
    severities: List[str] = field(default_factory=list)
    agent_ids: Set[str] = field(default_factory=set)
    user_ids: Set[str] = field(default_factory=set)
    src_ips: Set[str] = field(default_factory=set)
    alert_timestamps: List[float] = field(default_factory=list)


class ContextAgent:
    """
    Context enrichment agent that tracks incidents and enriches alerts.

    This agent:
    - Subscribes to AlertDetected events
    - Maintains in-memory state for incidents grouped by correlation_id
    - Tracks similar alert counts, timestamps, and sources
    - Publishes ContextEnriched events with additional context

    The agent is fully optional - the pipeline works without it.
    """

    # Event type constants
    EVENT_ALERT_DETECTED = "AlertDetected"
    EVENT_CONTEXT_ENRICHED = "ContextEnriched"

    # Severity ordering for max calculation
    SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(
        self,
        event_bus,
        logger: logging.Logger = None,
        max_incidents: int = 10000,
        escalation_threshold: int = 3
    ):
        """
        Initialize the context agent.

        Args:
            event_bus: The EventBus instance to use for pub/sub
            logger: Optional logger instance
            max_incidents: Maximum number of incidents to track (LRU eviction)
            escalation_threshold: Number of alerts in short time to consider escalating
        """
        self.bus = event_bus
        self.logger = logger or logging.getLogger("ContextAgent")
        self.max_incidents = max_incidents
        self.escalation_threshold = escalation_threshold

        self._running = False
        self._subscribed = False

        # In-memory state: correlation_id -> IncidentState
        self._incidents: Dict[str, IncidentState] = {}
        self._incident_order: List[str] = []  # For LRU eviction

        # Statistics
        self.stats = {
            "alerts_received": 0,
            "events_enriched": 0,
            "incidents_created": 0,
            "incidents_updated": 0,
            "incidents_evicted": 0,
            "start_time": None,
            "stop_time": None
        }

    def start(self) -> None:
        """
        Start the context agent.

        Subscribes to AlertDetected events on the event bus.
        """
        if self._running:
            self.logger.warning("ContextAgent is already running")
            return

        self.bus.subscribe(self.EVENT_ALERT_DETECTED, self._handle_alert_detected)
        self._subscribed = True
        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.stats["stop_time"] = None

        self.logger.info("ContextAgent started")

    def stop(self) -> None:
        """
        Stop the context agent.

        Unsubscribes from the event bus. State is preserved.
        """
        if not self._running:
            self.logger.warning("ContextAgent is not running")
            return

        if self._subscribed:
            self.bus.unsubscribe(self.EVENT_ALERT_DETECTED, self._handle_alert_detected)
            self._subscribed = False

        self._running = False
        self.stats["stop_time"] = datetime.now(timezone.utc).isoformat()

        self.logger.info(f"ContextAgent stopped. Tracking {len(self._incidents)} incidents.")
        self._log_statistics()

    def is_running(self) -> bool:
        """Check if the agent is currently running."""
        return self._running

    def clear_state(self) -> None:
        """Clear all incident state. Useful for testing or reset."""
        self._incidents.clear()
        self._incident_order.clear()
        self.logger.info("ContextAgent state cleared")

    def get_incident(self, correlation_id: str) -> Optional[Dict[str, Any]]:
        """
        Get incident state by correlation_id.

        Args:
            correlation_id: The correlation ID to look up

        Returns:
            Incident state dict or None if not found
        """
        incident = self._incidents.get(correlation_id)
        if incident:
            return {
                "incident_id": incident.incident_id,
                "correlation_id": incident.correlation_id,
                "first_seen": incident.first_seen,
                "last_seen": incident.last_seen,
                "alert_count": incident.alert_count,
                "threat_types": list(incident.threat_types),
                "max_severity": self._get_max_severity(incident.severities),
                "agent_ids": list(incident.agent_ids),
                "user_ids": list(incident.user_ids),
                "src_ips": list(incident.src_ips)
            }
        return None

    def get_incident_count(self) -> int:
        """Get the number of tracked incidents."""
        return len(self._incidents)

    def _handle_alert_detected(self, event: dict) -> None:
        """
        Handle incoming AlertDetected event.

        Args:
            event: The alert event dict
        """
        self.stats["alerts_received"] += 1

        try:
            correlation_id = event.get("correlation_id")
            if not correlation_id:
                self.logger.debug("Alert missing correlation_id, generating one")
                correlation_id = str(uuid.uuid4())

            timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())
            payload = event.get("payload", {})

            # Update or create incident state
            is_new = correlation_id not in self._incidents
            incident = self._get_or_create_incident(correlation_id, timestamp)

            # Update incident with alert data
            self._update_incident(incident, payload, timestamp)

            if is_new:
                self.stats["incidents_created"] += 1
            else:
                self.stats["incidents_updated"] += 1

            # Create and publish enriched event
            enriched_event = self._create_enriched_event(event, incident, is_new)
            self.bus.publish(self.EVENT_CONTEXT_ENRICHED, enriched_event)
            self.stats["events_enriched"] += 1

            self.logger.debug(
                f"Enriched alert for incident {incident.incident_id}: "
                f"{incident.alert_count} alerts, "
                f"max_severity={self._get_max_severity(incident.severities)}"
            )

        except Exception as e:
            self.logger.error(f"Error processing alert: {e}")

    def _get_or_create_incident(
        self,
        correlation_id: str,
        timestamp: str
    ) -> IncidentState:
        """Get existing incident or create new one."""
        if correlation_id in self._incidents:
            # Move to end of LRU list
            if correlation_id in self._incident_order:
                self._incident_order.remove(correlation_id)
            self._incident_order.append(correlation_id)
            return self._incidents[correlation_id]

        # Evict oldest if at capacity
        if len(self._incidents) >= self.max_incidents:
            self._evict_oldest()

        # Create new incident
        incident = IncidentState(
            incident_id=f"inc-{str(uuid.uuid4())[:8]}",
            correlation_id=correlation_id,
            first_seen=timestamp,
            last_seen=timestamp
        )
        self._incidents[correlation_id] = incident
        self._incident_order.append(correlation_id)

        return incident

    def _evict_oldest(self) -> None:
        """Evict the oldest incident (LRU)."""
        if self._incident_order:
            oldest_id = self._incident_order.pop(0)
            if oldest_id in self._incidents:
                del self._incidents[oldest_id]
                self.stats["incidents_evicted"] += 1
                self.logger.debug(f"Evicted oldest incident: {oldest_id}")

    def _update_incident(
        self,
        incident: IncidentState,
        payload: dict,
        timestamp: str
    ) -> None:
        """Update incident state with new alert data."""
        incident.alert_count += 1
        incident.last_seen = timestamp

        # Track timestamp for escalation detection
        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
            incident.alert_timestamps.append(ts)
            # Keep only recent timestamps (last hour)
            cutoff = ts - 3600
            incident.alert_timestamps = [t for t in incident.alert_timestamps if t > cutoff]
        except (ValueError, TypeError):
            pass

        # Extract threat type
        threat_type = payload.get("threat_type")
        if threat_type:
            incident.threat_types.add(threat_type)

        # Extract severity
        severity = payload.get("severity")
        if severity:
            incident.severities.append(severity)

        # Extract source information
        source = payload.get("source", {})
        if source:
            agent_id = source.get("agent_id")
            if agent_id:
                incident.agent_ids.add(agent_id)

            user_id = source.get("user_id")
            if user_id:
                incident.user_ids.add(user_id)

            src_ip = source.get("src_ip")
            if src_ip:
                incident.src_ips.add(src_ip)

    def _create_enriched_event(
        self,
        source_event: dict,
        incident: IncidentState,
        is_new: bool
    ) -> dict:
        """Create a ContextEnriched event."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = source_event.get("payload", {})

        # Calculate time span
        time_span = 0.0
        try:
            first = datetime.fromisoformat(incident.first_seen.replace("Z", "+00:00"))
            last = datetime.fromisoformat(incident.last_seen.replace("Z", "+00:00"))
            time_span = (last - first).total_seconds()
        except (ValueError, TypeError):
            pass

        # Detect escalation (many alerts in short time)
        is_escalating = self._detect_escalation(incident)

        return {
            "event_id": event_id,
            "correlation_id": incident.correlation_id,
            "timestamp": timestamp,
            "producer": "context_agent",
            "payload": {
                "alert_id": payload.get("alert_id", f"alert-{event_id[:8]}"),
                "incident_id": incident.incident_id,
                "original_alert": payload,
                "context": {
                    "similar_alert_count": incident.alert_count,
                    "first_seen": incident.first_seen,
                    "last_seen": incident.last_seen,
                    "is_new_incident": is_new,
                    "is_escalating": is_escalating,
                    "threat_types_seen": list(incident.threat_types),
                    "sources_involved": {
                        "agent_ids": list(incident.agent_ids),
                        "user_ids": list(incident.user_ids),
                        "src_ips": list(incident.src_ips)
                    },
                    "max_severity": self._get_max_severity(incident.severities),
                    "time_span_seconds": time_span
                }
            }
        }

    def _get_max_severity(self, severities: List[str]) -> str:
        """Get the maximum severity from a list."""
        if not severities:
            return "low"

        max_sev = "low"
        max_order = 0
        for sev in severities:
            order = self.SEVERITY_ORDER.get(sev.lower(), 0)
            if order > max_order:
                max_order = order
                max_sev = sev.lower()

        return max_sev

    def _detect_escalation(self, incident: IncidentState) -> bool:
        """
        Detect if alert frequency is escalating.

        Returns True if there are many alerts in a short time window.
        """
        if len(incident.alert_timestamps) < self.escalation_threshold:
            return False

        # Check if recent alerts are clustered (within last 5 minutes)
        if len(incident.alert_timestamps) >= 2:
            recent = incident.alert_timestamps[-self.escalation_threshold:]
            time_window = recent[-1] - recent[0]
            # If N alerts in less than 5 minutes, consider escalating
            if time_window < 300:
                return True

        return False

    def _log_statistics(self) -> None:
        """Log agent statistics."""
        self.logger.info("=== ContextAgent Statistics ===")
        self.logger.info(f"Alerts received: {self.stats['alerts_received']}")
        self.logger.info(f"Events enriched: {self.stats['events_enriched']}")
        self.logger.info(f"Incidents created: {self.stats['incidents_created']}")
        self.logger.info(f"Incidents updated: {self.stats['incidents_updated']}")
        self.logger.info(f"Incidents evicted: {self.stats['incidents_evicted']}")
        self.logger.info(f"Active incidents: {len(self._incidents)}")

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        stats = self.stats.copy()
        stats["active_incidents"] = len(self._incidents)
        return stats
