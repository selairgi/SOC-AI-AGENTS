"""
Event-driven Detection Agent.

This agent subscribes to RawLogEvent and publishes AlertDetected events
using the new event bus infrastructure. It operates independently of
the existing SOCBuilder agent.

Usage:
    from soc_core.events import EventBus
    from soc_core.agents import EventDrivenDetectionAgent

    bus = EventBus()
    agent = EventDrivenDetectionAgent(bus)
    agent.start()

    # Publish a raw log event
    bus.publish("RawLogEvent", {...})

    # Agent will automatically detect threats and publish AlertDetected events
    agent.stop()
"""

import re
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Callable


class EventDrivenDetectionAgent:
    """
    Event-driven detection agent that processes raw log events and
    publishes security alerts.

    This agent:
    - Subscribes to RawLogEvent on the event bus
    - Applies pattern-based threat detection
    - Publishes AlertDetected events when threats are found
    - Can be started/stopped independently
    """

    # Event type constants
    EVENT_RAW_LOG = "RawLogEvent"
    EVENT_ALERT_DETECTED = "AlertDetected"

    # Built-in detection patterns (simplified subset for demonstration)
    DEFAULT_PATTERNS: List[Dict[str, Any]] = [
        {
            "id": "PI001",
            "name": "Prompt Injection - Ignore Instructions",
            "pattern": r"(?i)(ignore|disregard|forget)\s+(previous|all|your)\s+(instructions?|rules?|guidelines?)",
            "threat_type": "prompt_injection",
            "severity": "high",
            "confidence": 0.85
        },
        {
            "id": "PI002",
            "name": "Prompt Injection - Role Override",
            "pattern": r"(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+.*(admin|root|system)",
            "threat_type": "prompt_injection",
            "severity": "high",
            "confidence": 0.80
        },
        {
            "id": "PI003",
            "name": "Prompt Injection - Jailbreak",
            "pattern": r"(?i)(jailbreak|dan\s+mode|developer\s+mode|bypass\s+safety)",
            "threat_type": "prompt_injection",
            "severity": "critical",
            "confidence": 0.90
        },
        {
            "id": "DE001",
            "name": "Data Exfiltration - Extract Request",
            "pattern": r"(?i)(extract|dump|export|show\s+me)\s+(all|every)?\s*(passwords?|credentials?|api\s*keys?|tokens?|secrets?)",
            "threat_type": "data_exfiltration",
            "severity": "critical",
            "confidence": 0.90
        },
        {
            "id": "DE002",
            "name": "Data Exfiltration - Database Access",
            "pattern": r"(?i)(show|list|extract|dump)\s+(all)?\s*(patient|user|customer|account)\s*(records?|data|info)",
            "threat_type": "data_exfiltration",
            "severity": "high",
            "confidence": 0.85
        },
        {
            "id": "MI001",
            "name": "Malicious Input - Command Injection",
            "pattern": r"(?i)(sudo|rm\s+-rf|chmod\s+777|exec\s*\(|eval\s*\(|system\s*\()",
            "threat_type": "malicious_input",
            "severity": "critical",
            "confidence": 0.95
        },
        {
            "id": "MI002",
            "name": "Malicious Input - XSS Attempt",
            "pattern": r"(?i)<\s*script[^>]*>|javascript\s*:|on\w+\s*=",
            "threat_type": "malicious_input",
            "severity": "high",
            "confidence": 0.90
        },
    ]

    def __init__(
        self,
        event_bus,
        patterns: List[Dict[str, Any]] = None,
        logger: logging.Logger = None
    ):
        """
        Initialize the detection agent.

        Args:
            event_bus: The EventBus instance to use for pub/sub
            patterns: Optional custom detection patterns (uses defaults if None)
            logger: Optional logger instance
        """
        self.bus = event_bus
        self.patterns = patterns or self.DEFAULT_PATTERNS
        self.logger = logger or logging.getLogger("EventDrivenDetectionAgent")

        self._running = False
        self._subscribed = False

        # Compile regex patterns for efficiency
        self._compiled_patterns = []
        for pattern_def in self.patterns:
            try:
                compiled = re.compile(pattern_def["pattern"])
                self._compiled_patterns.append({
                    **pattern_def,
                    "_compiled": compiled
                })
            except re.error as e:
                self.logger.warning(f"Invalid pattern {pattern_def['id']}: {e}")

        # Statistics
        self.stats = {
            "events_received": 0,
            "alerts_published": 0,
            "patterns_matched": {},
            "start_time": None,
            "stop_time": None
        }

    def start(self) -> None:
        """
        Start the detection agent.

        Subscribes to RawLogEvent on the event bus.
        """
        if self._running:
            self.logger.warning("Agent is already running")
            return

        self.bus.subscribe(self.EVENT_RAW_LOG, self._handle_raw_log_event)
        self._subscribed = True
        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.stats["stop_time"] = None

        self.logger.info(
            f"EventDrivenDetectionAgent started with {len(self._compiled_patterns)} patterns"
        )

    def stop(self) -> None:
        """
        Stop the detection agent.

        Unsubscribes from the event bus.
        """
        if not self._running:
            self.logger.warning("Agent is not running")
            return

        if self._subscribed:
            self.bus.unsubscribe(self.EVENT_RAW_LOG, self._handle_raw_log_event)
            self._subscribed = False

        self._running = False
        self.stats["stop_time"] = datetime.now(timezone.utc).isoformat()

        self.logger.info("EventDrivenDetectionAgent stopped")
        self._log_statistics()

    def is_running(self) -> bool:
        """Check if the agent is currently running."""
        return self._running

    def _handle_raw_log_event(self, event: dict) -> None:
        """
        Handle incoming RawLogEvent.

        Args:
            event: The raw log event dict
        """
        self.stats["events_received"] += 1

        try:
            payload = event.get("payload", {})
            message = payload.get("message", "")

            if not message:
                self.logger.debug("Received event with empty message, skipping")
                return

            # Detect threats
            detections = self._detect_threats(message, payload)

            # Publish alerts for each detection
            for detection in detections:
                alert_event = self._create_alert_event(event, detection)
                self.bus.publish(self.EVENT_ALERT_DETECTED, alert_event)
                self.stats["alerts_published"] += 1

                self.logger.warning(
                    f"Alert published: {detection['pattern_name']} "
                    f"(severity: {detection['severity']}, confidence: {detection['confidence']})"
                )

        except Exception as e:
            self.logger.error(f"Error processing event: {e}")

    def _detect_threats(
        self,
        message: str,
        payload: dict
    ) -> List[Dict[str, Any]]:
        """
        Detect threats in the message using compiled patterns.

        Args:
            message: The log message to analyze
            payload: The full event payload for context

        Returns:
            List of detection results
        """
        detections = []

        for pattern_def in self._compiled_patterns:
            compiled = pattern_def["_compiled"]
            match = compiled.search(message)

            if match:
                pattern_id = pattern_def["id"]
                self.stats["patterns_matched"][pattern_id] = \
                    self.stats["patterns_matched"].get(pattern_id, 0) + 1

                detections.append({
                    "pattern_id": pattern_id,
                    "pattern_name": pattern_def["name"],
                    "threat_type": pattern_def["threat_type"],
                    "severity": pattern_def["severity"],
                    "confidence": pattern_def["confidence"],
                    "matched_text": match.group(0),
                    "match_start": match.start(),
                    "match_end": match.end()
                })

        return detections

    def _create_alert_event(
        self,
        source_event: dict,
        detection: Dict[str, Any]
    ) -> dict:
        """
        Create an AlertDetected event from a detection result.

        Args:
            source_event: The original RawLogEvent
            detection: The detection result

        Returns:
            AlertDetected event dict conforming to schema
        """
        event_id = str(uuid.uuid4())
        correlation_id = source_event.get("correlation_id", str(uuid.uuid4()))
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = source_event.get("payload", {})

        return {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "event_driven_detection_agent",
            "payload": {
                "alert_id": f"alert-{event_id[:8]}",
                "severity": detection["severity"],
                "threat_type": detection["threat_type"],
                "confidence": detection["confidence"],
                "source": {
                    "agent_id": payload.get("agent_id"),
                    "user_id": payload.get("user_id"),
                    "src_ip": payload.get("src_ip"),
                    "session_id": payload.get("session_id")
                },
                "evidence": {
                    "matched_patterns": [detection["pattern_id"]],
                    "matched_text": detection["matched_text"],
                    "raw_input": payload.get("message", "")[:500],  # Truncate for safety
                    "detection_method": "pattern_matching",
                    "pattern_name": detection["pattern_name"]
                }
            }
        }

    def _log_statistics(self) -> None:
        """Log agent statistics."""
        self.logger.info("=== EventDrivenDetectionAgent Statistics ===")
        self.logger.info(f"Events received: {self.stats['events_received']}")
        self.logger.info(f"Alerts published: {self.stats['alerts_published']}")

        if self.stats["patterns_matched"]:
            self.logger.info("Patterns matched:")
            for pattern_id, count in self.stats["patterns_matched"].items():
                self.logger.info(f"  - {pattern_id}: {count} times")

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        return self.stats.copy()

    def add_pattern(self, pattern_def: Dict[str, Any]) -> bool:
        """
        Add a custom detection pattern at runtime.

        Args:
            pattern_def: Pattern definition with id, name, pattern, threat_type, severity, confidence

        Returns:
            True if pattern was added successfully
        """
        required_keys = {"id", "name", "pattern", "threat_type", "severity", "confidence"}
        if not required_keys.issubset(pattern_def.keys()):
            self.logger.error(f"Pattern missing required keys: {required_keys - pattern_def.keys()}")
            return False

        try:
            compiled = re.compile(pattern_def["pattern"])
            self._compiled_patterns.append({
                **pattern_def,
                "_compiled": compiled
            })
            self.patterns.append(pattern_def)
            self.logger.info(f"Added pattern: {pattern_def['id']}")
            return True
        except re.error as e:
            self.logger.error(f"Invalid regex pattern: {e}")
            return False
