"""
SOC Detector Agent.

Main detection agent that:
- Subscribes to RawLogEvent
- Analyzes logs for threats using ML/rules
- Publishes AlertDetected events with confidence scores
- Stores incremental data for learning

Flow:
    RawLogEvent -> SOCDetector -> AlertDetected
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

# Import SemanticDetector for cosine similarity detection
try:
    from ..utils import SemanticDetector
    HAS_SEMANTIC = True
except ImportError:
    SemanticDetector = None
    HAS_SEMANTIC = False


@dataclass
class DetectionResult:
    """Result of threat detection analysis."""
    is_threat: bool
    threat_type: Optional[str]
    severity: str  # low, medium, high, critical
    confidence: float  # 0.0 - 1.0
    features: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    explanation: str = ""


class SOCDetector:
    """
    Main SOC Detection Agent.

    Responsibilities:
    - Subscribe to RawLogEvent
    - Detect threats using rules + ML models
    - Publish AlertDetected with confidence/features
    - Store incremental data for offline training
    """

    EVENT_RAW_LOG = "RawLogEvent"
    EVENT_ALERT_DETECTED = "AlertDetected"

    # Threat patterns (simplified - in production, use ML models)
    THREAT_PATTERNS = {
        "brute_force": {
            "keywords": ["failed login", "authentication failure", "invalid password"],
            "threshold": 5,
            "severity": "high"
        },
        "sql_injection": {
            "keywords": ["' or '1'='1", "union select", "drop table", "--", "';"],
            "threshold": 1,
            "severity": "critical"
        },
        "xss": {
            "keywords": ["<script>", "javascript:", "onerror=", "onload="],
            "threshold": 1,
            "severity": "high"
        },
        "command_injection": {
            "keywords": ["; ls", "| cat", "&& rm", "$(", "`"],
            "threshold": 1,
            "severity": "critical"
        },
        "suspicious_access": {
            "keywords": ["403", "401", "unauthorized", "forbidden"],
            "threshold": 10,
            "severity": "medium"
        },
        "data_exfiltration": {
            "keywords": ["large download", "bulk export", "database dump"],
            "threshold": 1,
            "severity": "critical"
        },
        "malware": {
            "keywords": ["malware", "virus", "trojan", "ransomware", "crypto"],
            "threshold": 1,
            "severity": "critical"
        },
        "port_scan": {
            "keywords": ["port scan", "nmap", "syn scan", "connection refused"],
            "threshold": 3,
            "severity": "medium"
        }
    }

    def __init__(
        self,
        event_bus,
        incremental_storage=None,
        model_path: Optional[str] = None,
        use_semantic: bool = True,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the SOC Detector.

        Args:
            event_bus: EventBus for pub/sub
            incremental_storage: Optional IncrementalStorage for learning
            model_path: Optional path to trained ML model
            use_semantic: Enable semantic (cosine similarity) detection
            logger: Optional logger instance
        """
        self.bus = event_bus
        self.storage = incremental_storage
        self.model_path = model_path
        self.logger = logger or logging.getLogger("SOCDetector")

        self._running = False
        self._model = None

        # Initialize SemanticDetector for hybrid detection
        self.semantic_detector = None
        if use_semantic and HAS_SEMANTIC and SemanticDetector:
            try:
                self.semantic_detector = SemanticDetector(logger=self.logger)
                self.logger.info("SemanticDetector enabled (hybrid mode)")
            except Exception as e:
                self.logger.warning(f"SemanticDetector failed to init: {e}")

        # Statistics
        self.stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "threats_by_type": {},
            "semantic_detections": 0,
            "keyword_detections": 0,
            "start_time": None
        }

    def start(self) -> None:
        """Start the detector agent."""
        if self._running:
            self.logger.warning("SOCDetector already running")
            return

        # Load ML model if available
        self._load_model()

        # Subscribe to raw log events
        self.bus.subscribe(self.EVENT_RAW_LOG, self._handle_raw_log)
        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()

        self.logger.info("SOCDetector started")

    def stop(self) -> None:
        """Stop the detector agent."""
        if not self._running:
            return

        self.bus.unsubscribe(self.EVENT_RAW_LOG, self._handle_raw_log)
        self._running = False

        self.logger.info("SOCDetector stopped")
        self._log_stats()

    def _load_model(self) -> None:
        """Load ML model if path provided."""
        if self.model_path:
            try:
                # In production: load actual ML model
                # self._model = joblib.load(self.model_path)
                self.logger.info(f"Model loaded from {self.model_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load model: {e}, using rules only")

    def _handle_raw_log(self, event: dict) -> None:
        """Handle incoming raw log event."""
        self.stats["events_processed"] += 1

        try:
            correlation_id = event.get("correlation_id", str(uuid.uuid4()))
            payload = event.get("payload", {})

            # Extract log data
            log_message = payload.get("message", "")
            log_source = payload.get("source", "unknown")
            source_ip = payload.get("source_ip", "")
            user = payload.get("user", "")

            # Analyze for threats
            result = self._analyze(
                message=log_message,
                source=log_source,
                source_ip=source_ip,
                user=user,
                metadata=payload
            )

            # Store for incremental learning (regardless of threat)
            if self.storage:
                self._store_for_learning(event, result)

            # Only publish alert if threat detected
            if result.is_threat:
                self._publish_alert(event, result, correlation_id)

        except Exception as e:
            self.logger.error(f"Error processing log: {e}")

    def _analyze(
        self,
        message: str,
        source: str,
        source_ip: str,
        user: str,
        metadata: Dict[str, Any]
    ) -> DetectionResult:
        """
        Analyze log for threats using HYBRID detection.

        Uses combination of:
        1. Rule-based pattern matching (fast, specific)
        2. Semantic similarity detection (intelligent, catches paraphrasing)
        3. ML model (if available)

        Args:
            message: Log message content
            source: Log source identifier
            source_ip: Source IP address
            user: User associated with log
            metadata: Additional metadata

        Returns:
            DetectionResult with threat details
        """
        message_lower = message.lower()
        features = self._extract_features(message, source_ip, user, metadata)

        # === SCORING SYSTEM ===
        # Keywords alone should NOT trigger alerts
        # They contribute to a score that needs confirmation

        threat_scores = {}  # threat_type -> score details
        detection_methods = []

        # === STEP 1: Check for EDUCATIONAL/LEGITIMATE context ===
        # These patterns indicate the user is ASKING about attacks, not performing them
        educational_patterns = [
            "explain", "what is", "what's", "how does", "how do",
            "tell me about", "describe", "define", "example of",
            "qu'est-ce que", "explique", "comment fonctionne",
            "c'est quoi", "définition", "exemple de"
        ]
        is_educational = any(p in message_lower for p in educational_patterns)

        # Quotes often indicate discussing a concept, not executing it
        has_quotes = ("'" in message or '"' in message or "«" in message)

        # Question mark indicates inquiry
        is_question = "?" in message

        # Calculate context modifier (reduces threat score)
        context_modifier = 1.0
        context_reasons = []
        if is_educational:
            context_modifier -= 0.4
            context_reasons.append("educational_context")
        if has_quotes and is_educational:
            context_modifier -= 0.2
            context_reasons.append("quoted_concept")
        if is_question and is_educational:
            context_modifier -= 0.1
            context_reasons.append("inquiry_format")

        context_modifier = max(0.1, context_modifier)  # Minimum 10% of original score

        # === STEP 2: Semantic Detection (Cosine Similarity) ===
        semantic_score = 0.0
        semantic_match = None
        if self.semantic_detector:
            semantic_match = self.semantic_detector.analyze(message)
            if semantic_match.similarity > 0.4:  # Lower threshold, just for scoring
                semantic_score = semantic_match.similarity
                threat_type = semantic_match.threat_type

                if threat_type not in threat_scores:
                    threat_scores[threat_type] = {"score": 0, "signals": [], "severity": "medium"}

                # Semantic contributes 50% of score
                adjusted_semantic = semantic_score * 0.5 * context_modifier
                threat_scores[threat_type]["score"] += adjusted_semantic
                threat_scores[threat_type]["signals"].append(f"semantic:{semantic_score:.2f}")
                detection_methods.append("semantic")

        # === STEP 3: Keyword Pattern Matching (SCORING, not deciding) ===
        for threat_type, pattern_info in self.THREAT_PATTERNS.items():
            matches = sum(
                1 for kw in pattern_info["keywords"]
                if kw.lower() in message_lower
            )

            if matches > 0:
                if threat_type not in threat_scores:
                    threat_scores[threat_type] = {"score": 0, "signals": [], "severity": pattern_info["severity"]}

                # Keywords contribute based on match count, but LESS than semantic
                # 1 match = 0.15, 2 matches = 0.25, 3+ matches = 0.35
                keyword_contribution = min(0.35, 0.10 + (matches * 0.10))
                adjusted_keyword = keyword_contribution * context_modifier

                threat_scores[threat_type]["score"] += adjusted_keyword
                threat_scores[threat_type]["signals"].append(f"keyword:{matches}")
                threat_scores[threat_type]["severity"] = pattern_info["severity"]
                detection_methods.append("keyword")

        # === STEP 4: Determine if it's a REAL threat ===
        # Need score > 0.5 to be considered a threat
        # This prevents keywords alone from triggering (max keyword = 0.35)
        THREAT_THRESHOLD = 0.50

        detected_threats = []
        for threat_type, data in threat_scores.items():
            final_score = data["score"]

            # Boost if multiple methods agree
            if "semantic" in str(data["signals"]) and "keyword" in str(data["signals"]):
                final_score = min(0.95, final_score + 0.15)
                data["signals"].append("multi_signal_boost")

            if final_score >= THREAT_THRESHOLD:
                detected_threats.append({
                    "type": threat_type,
                    "severity": data["severity"],
                    "matches": len(data["signals"]),
                    "confidence": final_score,
                    "method": "hybrid",
                    "signals": data["signals"],
                    "context_modifier": context_modifier,
                    "context_reasons": context_reasons
                })
                self.stats["semantic_detections" if "semantic" in str(data["signals"]) else "keyword_detections"] += 1

        # ML model prediction (if available)
        ml_confidence = 0.0
        if self._model:
            try:
                # In production: actual ML inference
                # ml_prediction = self._model.predict_proba(features)
                # ml_confidence = ml_prediction[0][1]
                pass
            except Exception as e:
                self.logger.debug(f"ML prediction failed: {e}")

        # Combine HYBRID results (semantic + keyword + ML)
        if detected_threats:
            # Sort by confidence first, then severity
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            detected_threats.sort(
                key=lambda x: (x.get("confidence", 0.5), severity_order.get(x["severity"], 0)),
                reverse=True
            )

            primary_threat = detected_threats[0]
            base_confidence = primary_threat.get("confidence", 0.7)

            # Boost confidence if both methods agree
            if len(detected_threats) > 1:
                methods = set(t.get("method") for t in detected_threats)
                if len(methods) > 1:  # Multiple methods detected same threat type
                    base_confidence = min(0.98, base_confidence + 0.1)

            # Combine with ML confidence
            if ml_confidence > 0:
                final_confidence = (base_confidence * 0.7) + (ml_confidence * 0.3)
            else:
                final_confidence = base_confidence

            # Build explanation
            method_str = primary_threat.get("method", "rule")
            if method_str == "semantic":
                explanation = f"Semantic match: '{primary_threat.get('matched_pattern', '')}' (sim={primary_threat.get('confidence', 0):.2f})"
            else:
                explanation = f"Detected {primary_threat['type']} with {primary_threat['matches']} keyword matches"

            return DetectionResult(
                is_threat=True,
                threat_type=primary_threat["type"],
                severity=primary_threat["severity"],
                confidence=final_confidence,
                features=features,
                indicators=[t["type"] for t in detected_threats],
                explanation=explanation
            )

        # Check ML-only detection
        if ml_confidence > 0.7:
            return DetectionResult(
                is_threat=True,
                threat_type="ml_detected_anomaly",
                severity="medium",
                confidence=ml_confidence,
                features=features,
                indicators=["ml_anomaly"],
                explanation="ML model detected anomalous behavior"
            )

        return DetectionResult(
            is_threat=False,
            threat_type=None,
            severity="low",
            confidence=0.0,
            features=features,
            indicators=[],
            explanation="No threat detected"
        )

    def _extract_features(
        self,
        message: str,
        source_ip: str,
        user: str,
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract features for ML model and storage."""
        return {
            "message_length": len(message),
            "has_special_chars": any(c in message for c in ["'", '"', ";", "|", "&"]),
            "has_ip": bool(source_ip),
            "has_user": bool(user),
            "source_ip": source_ip,
            "user": user,
            "hour_of_day": datetime.now().hour,
            "day_of_week": datetime.now().weekday(),
            # In production: more sophisticated features
            # - IP reputation score
            # - User risk score
            # - Historical patterns
            # - Geo-location
        }

    def _store_for_learning(self, event: dict, result: DetectionResult) -> None:
        """Store detection example for incremental learning."""
        try:
            example = {
                "raw_event": event,
                "features": result.features,
                "detection": {
                    "is_threat": result.is_threat,
                    "threat_type": result.threat_type,
                    "severity": result.severity,
                    "confidence": result.confidence
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.storage.store("detector", example)
        except Exception as e:
            self.logger.debug(f"Failed to store for learning: {e}")

    def _publish_alert(
        self,
        source_event: dict,
        result: DetectionResult,
        correlation_id: str
    ) -> None:
        """Publish AlertDetected event."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        alert_event = {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "soc_detector",
            "payload": {
                "alert_id": f"alert-{event_id[:8]}",
                "threat_type": result.threat_type,
                "severity": result.severity,
                "confidence": result.confidence,
                "features": result.features,
                "indicators": result.indicators,
                "explanation": result.explanation,
                "source_event": {
                    "event_id": source_event.get("event_id"),
                    "source": source_event.get("payload", {}).get("source"),
                    "source_ip": source_event.get("payload", {}).get("source_ip"),
                    "user": source_event.get("payload", {}).get("user")
                }
            }
        }

        self.bus.publish(self.EVENT_ALERT_DETECTED, alert_event)
        self.stats["alerts_generated"] += 1
        self.stats["threats_by_type"][result.threat_type] = \
            self.stats["threats_by_type"].get(result.threat_type, 0) + 1

        self.logger.info(
            f"Alert generated: {result.threat_type} "
            f"(severity={result.severity}, confidence={result.confidence:.2f})"
        )

    def _log_stats(self) -> None:
        """Log statistics."""
        self.logger.info("=== SOCDetector Statistics ===")
        self.logger.info(f"Events processed: {self.stats['events_processed']}")
        self.logger.info(f"Alerts generated: {self.stats['alerts_generated']}")
        self.logger.info(f"Threats by type: {self.stats['threats_by_type']}")

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        return self.stats.copy()

    def is_running(self) -> bool:
        """Check if detector is running."""
        return self._running
