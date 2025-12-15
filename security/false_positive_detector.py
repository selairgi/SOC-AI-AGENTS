"""
False Positive Detection System
Uses ML-based techniques and confidence scoring to reduce false positive alerts
"""

import re
import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, Counter
import json

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import Alert, LogEntry, ThreatType


@dataclass
class FalsePositiveScore:
    """False positive confidence score"""
    alert_id: str
    false_positive_probability: float
    confidence_factors: Dict[str, float]
    reasoning: List[str]
    recommended_action: str  # "block", "investigate", "ignore", "escalate"


class FalsePositiveDetector:
    """
    Advanced false positive detection using multiple signals:
    1. Pattern legitimacy scoring
    2. User behavior analysis
    3. Context-aware detection
    4. Historical false positive learning
    5. Confidence thresholds
    """

    def __init__(self):
        self.logger = logging.getLogger("FalsePositiveDetector")

        # User behavior tracking
        self.user_history = defaultdict(lambda: {
            "interactions": 0,
            "alerts_triggered": 0,
            "false_positives": 0,
            "legitimate_threats": 0,
            "first_seen": time.time(),
            "patterns": Counter()
        })

        # Session tracking
        self.session_context = defaultdict(lambda: {
            "messages": [],
            "alerts": [],
            "conversation_flow": []
        })

        # False positive patterns learned over time
        self.known_false_positive_patterns = [
            # Common legitimate queries that might trigger false positives
            r"how (do|can) (i|you)",
            r"what (is|are|does)",
            r"tell me (about|how)",
            r"explain (the|how|why)",
            r"show me (how|what)",
            r"can you help",
            r"i (want|need) to (know|understand|learn)",
        ]

        # Legitimate context keywords
        self.legitimate_context_keywords = [
            "help", "tutorial", "learn", "understand", "explain",
            "question", "wondering", "curious", "information"
        ]

        # High-confidence threat indicators
        self.high_confidence_threat_indicators = [
            r"ignore (all )?previous (instructions|prompts)",
            r"forget (all )?previous (instructions|rules)",
            r"(you are|act as|pretend to be) (now|a)",
            r"system\.prompt|system_prompt",
            r"<\|.*?\|>",  # Special tokens
            r"[\[\{].*?(system|admin|root).*?[\]\}]",
            r"sudo|chmod|rm -rf|DROP TABLE",
            r"(show|give|tell).*(password|api[_\s]key|secret|token|credential)",
        ]

        # Confidence thresholds
        self.thresholds = {
            "very_high_confidence": 0.9,  # Definite threat
            "high_confidence": 0.7,       # Likely threat
            "medium_confidence": 0.5,     # Needs investigation
            "low_confidence": 0.3,        # Likely false positive
            "very_low_confidence": 0.1    # Definite false positive
        }

        # Statistics
        self.stats = {
            "total_analyzed": 0,
            "false_positives_detected": 0,
            "high_confidence_threats": 0,
            "medium_confidence": 0,
            "low_confidence": 0
        }

    def analyze_alert(
        self,
        alert: Alert,
        log: LogEntry,
        user_context: Optional[Dict[str, Any]] = None
    ) -> FalsePositiveScore:
        """
        Analyze an alert to determine if it's a false positive.

        Args:
            alert: The security alert to analyze
            log: The log entry that triggered the alert
            user_context: Additional user context

        Returns:
            FalsePositiveScore with analysis results
        """
        self.stats["total_analyzed"] += 1
        self.logger.debug(f"Analyzing alert {alert.id} for false positives")

        confidence_factors = {}
        reasoning = []

        # Factor 1: Pattern legitimacy (30% weight)
        # NOTE: pattern_score represents how LEGITIMATE the message looks (0=suspicious, 1=legitimate)
        # We need to INVERT it to get threat confidence (1=threatening, 0=benign)
        pattern_score, pattern_reasoning = self._analyze_pattern_legitimacy(
            log.message, alert.threat_type
        )
        # Invert: if message looks legitimate (high pattern_score), threat confidence should be LOW
        confidence_factors["pattern_legitimacy"] = (1.0 - pattern_score) * 0.30
        reasoning.extend(pattern_reasoning)

        # Factor 2: User behavior (25% weight)
        # NOTE: user_score represents how TRUSTWORTHY the user is (0=suspicious, 1=trustworthy)
        # We need to INVERT it to get threat confidence
        user_score, user_reasoning = self._analyze_user_behavior(
            log.user_id, log.session_id, alert
        )
        # Invert: if user is trustworthy (high user_score), threat confidence should be LOW
        confidence_factors["user_behavior"] = (1.0 - user_score) * 0.25
        reasoning.extend(user_reasoning)

        # Factor 3: Context awareness (25% weight)
        # NOTE: context_score represents how NATURAL/BENIGN the message looks (0=suspicious, 1=natural)
        # We need to INVERT it to get threat confidence
        context_score, context_reasoning = self._analyze_context(
            log, alert, user_context
        )
        # Invert: if message looks natural (high context_score), threat confidence should be LOW
        confidence_factors["context_awareness"] = (1.0 - context_score) * 0.25
        reasoning.extend(context_reasoning)

        # Factor 4: Threat confidence indicators (20% weight)
        threat_score, threat_reasoning = self._analyze_threat_indicators(
            log.message, alert.threat_type
        )
        confidence_factors["threat_indicators"] = threat_score * 0.20
        reasoning.extend(threat_reasoning)

        # Calculate overall false positive probability
        # Lower score = more likely to be false positive
        # Higher score = more likely to be real threat
        threat_confidence = sum(confidence_factors.values())
        false_positive_probability = 1.0 - threat_confidence

        # Update alert with false positive probability
        alert.false_positive_probability = false_positive_probability

        # Determine recommended action
        recommended_action = self._determine_action(threat_confidence, alert.severity)

        # Update user history
        self._update_user_history(log.user_id, alert, false_positive_probability)

        # Update session context
        self._update_session_context(log.session_id, log.message, alert)

        # Update statistics
        if false_positive_probability > 0.7:
            self.stats["false_positives_detected"] += 1
        elif threat_confidence > 0.7:
            self.stats["high_confidence_threats"] += 1
        elif threat_confidence > 0.4:
            self.stats["medium_confidence"] += 1
        else:
            self.stats["low_confidence"] += 1

        self.logger.info(
            f"Alert {alert.id}: FP probability={false_positive_probability:.2f}, "
            f"Action={recommended_action}"
        )

        return FalsePositiveScore(
            alert_id=alert.id,
            false_positive_probability=false_positive_probability,
            confidence_factors=confidence_factors,
            reasoning=reasoning,
            recommended_action=recommended_action
        )

    def _analyze_pattern_legitimacy(
        self,
        message: str,
        threat_type: ThreatType
    ) -> Tuple[float, List[str]]:
        """Analyze if the pattern matches legitimate queries"""
        reasoning = []
        message_lower = message.lower()

        # Check for known false positive patterns
        legitimate_match_count = 0
        for pattern in self.known_false_positive_patterns:
            if re.search(pattern, message_lower):
                legitimate_match_count += 1

        if legitimate_match_count > 0:
            reasoning.append(
                f"Matches {legitimate_match_count} legitimate query pattern(s)"
            )

        # Check for legitimate context
        legitimate_keywords = sum(
            1 for keyword in self.legitimate_context_keywords
            if keyword in message_lower
        )

        if legitimate_keywords > 0:
            reasoning.append(
                f"Contains {legitimate_keywords} legitimate context keyword(s)"
            )

        # Natural language indicators
        has_question_mark = "?" in message
        proper_grammar = self._check_basic_grammar(message)

        if has_question_mark:
            reasoning.append("Formatted as a question")

        if proper_grammar:
            reasoning.append("Uses proper grammar structure")

        # Calculate score (0 = suspicious, 1 = legitimate)
        score = (
            (legitimate_match_count * 0.3) +
            (legitimate_keywords * 0.2) +
            (0.2 if has_question_mark else 0) +
            (0.3 if proper_grammar else 0)
        )

        return min(1.0, score), reasoning

    def _analyze_user_behavior(
        self,
        user_id: str,
        session_id: str,
        alert: Alert
    ) -> Tuple[float, List[str]]:
        """Analyze user's historical behavior"""
        reasoning = []
        user_data = self.user_history[user_id]

        # New user - moderate score
        if user_data["interactions"] < 5:
            reasoning.append("New user - limited history")
            return 0.5, reasoning

        # Calculate false positive rate for this user
        if user_data["alerts_triggered"] > 0:
            fp_rate = user_data["false_positives"] / user_data["alerts_triggered"]
        else:
            fp_rate = 0.0

        # High false positive rate = lower confidence in this alert
        if fp_rate > 0.5:
            reasoning.append(f"User has high FP rate: {fp_rate:.1%}")

        # Check session context
        session_data = self.session_context[session_id]
        if len(session_data["messages"]) > 3:
            # Established conversation - less likely to be attack
            reasoning.append("Established conversation context")

        # Calculate score
        interaction_factor = min(1.0, user_data["interactions"] / 20)
        fp_factor = 1.0 - fp_rate
        session_factor = min(1.0, len(session_data["messages"]) / 10)

        score = (interaction_factor * 0.4 + fp_factor * 0.4 + session_factor * 0.2)

        return score, reasoning

    def _analyze_context(
        self,
        log: LogEntry,
        alert: Alert,
        user_context: Optional[Dict[str, Any]]
    ) -> Tuple[float, List[str]]:
        """Analyze contextual factors"""
        reasoning = []
        message = log.message

        # Message length analysis
        word_count = len(message.split())
        if word_count < 3:
            reasoning.append("Very short message - higher suspicion")
            length_score = 0.3
        elif word_count > 50:
            reasoning.append("Long message - complex attack or legitimate query")
            length_score = 0.5
        else:
            reasoning.append("Normal message length")
            length_score = 0.7

        # Special characters analysis
        special_char_ratio = sum(1 for c in message if not c.isalnum() and c != ' ') / len(message)
        if special_char_ratio > 0.3:
            reasoning.append(f"High special character ratio: {special_char_ratio:.1%}")
            char_score = 0.3
        else:
            char_score = 0.8

        # Check for natural conversation flow
        natural_flow = self._check_natural_flow(message)
        if natural_flow:
            reasoning.append("Natural conversation flow detected")
            flow_score = 0.9
        else:
            flow_score = 0.5

        # Response time analysis (if available)
        if log.response_time and log.response_time < 0.1:
            reasoning.append("Very fast response - potential automation")
            time_score = 0.3
        else:
            time_score = 0.8

        score = (length_score * 0.3 + char_score * 0.3 + flow_score * 0.2 + time_score * 0.2)
        return score, reasoning

    def _analyze_threat_indicators(
        self,
        message: str,
        threat_type: ThreatType
    ) -> Tuple[float, List[str]]:
        """Analyze high-confidence threat indicators"""
        reasoning = []
        message_lower = message.lower()

        # Check for high-confidence threat patterns
        threat_matches = 0
        matched_patterns = []

        for pattern in self.high_confidence_threat_indicators:
            match = re.search(pattern, message_lower, re.IGNORECASE)
            if match:
                threat_matches += 1
                matched_patterns.append(pattern[:50])

        if threat_matches > 0:
            reasoning.append(
                f"Matched {threat_matches} high-confidence threat pattern(s)"
            )

        # Specific threat type analysis
        if threat_type == ThreatType.PROMPT_INJECTION:
            if any(keyword in message_lower for keyword in ["ignore", "forget", "override", "disregard"]):
                reasoning.append("Contains prompt injection keywords")
                threat_matches += 1

        elif threat_type == ThreatType.DATA_EXFILTRATION:
            if any(keyword in message_lower for keyword in ["password", "api key", "secret", "token"]):
                reasoning.append("Contains data exfiltration keywords")
                threat_matches += 1

        elif threat_type == ThreatType.SYSTEM_MANIPULATION:
            if any(keyword in message_lower for keyword in ["sudo", "chmod", "rm", "delete", "drop"]):
                reasoning.append("Contains system manipulation keywords")
                threat_matches += 1

        # Calculate threat confidence
        score = min(1.0, threat_matches * 0.4)
        return score, reasoning

    def _check_basic_grammar(self, message: str) -> bool:
        """Basic grammar check"""
        # Simple heuristics
        words = message.split()
        if len(words) < 2:
            return False

        # Check for capitalization
        has_capital = any(c.isupper() for c in message)

        # Check for punctuation
        has_punctuation = any(c in '.!?' for c in message)

        return has_capital or has_punctuation

    def _check_natural_flow(self, message: str) -> bool:
        """Check if message has natural conversation flow"""
        # Check for common conversational starters
        conversational_starters = [
            "i want", "i need", "can you", "could you", "would you",
            "please", "how do", "what is", "why", "when", "where"
        ]

        message_lower = message.lower()
        return any(starter in message_lower for starter in conversational_starters)

    def _determine_action(self, threat_confidence: float, severity: str) -> str:
        """Determine recommended action based on confidence and severity"""
        if threat_confidence >= self.thresholds["very_high_confidence"]:
            return "block"
        elif threat_confidence >= self.thresholds["high_confidence"]:
            if severity in ["critical", "high"]:
                return "block"
            else:
                return "investigate"
        elif threat_confidence >= self.thresholds["medium_confidence"]:
            return "investigate"
        elif threat_confidence >= self.thresholds["low_confidence"]:
            return "monitor"
        else:
            return "ignore"

    def _update_user_history(
        self,
        user_id: str,
        alert: Alert,
        false_positive_probability: float
    ):
        """Update user history with alert information"""
        user_data = self.user_history[user_id]
        user_data["interactions"] += 1
        user_data["alerts_triggered"] += 1

        if false_positive_probability > 0.7:
            user_data["false_positives"] += 1
        elif false_positive_probability < 0.3:
            user_data["legitimate_threats"] += 1

        # Track pattern
        user_data["patterns"][alert.threat_type.value] += 1

    def _update_session_context(
        self,
        session_id: str,
        message: str,
        alert: Alert
    ):
        """Update session context"""
        session_data = self.session_context[session_id]
        session_data["messages"].append({
            "timestamp": time.time(),
            "message": message[:100],  # Store first 100 chars
            "alert_triggered": True
        })
        session_data["alerts"].append(alert.id)

        # Keep only last 20 messages
        if len(session_data["messages"]) > 20:
            session_data["messages"] = session_data["messages"][-20:]

    def mark_as_false_positive(self, alert_id: str, user_id: str):
        """Manually mark an alert as false positive for learning"""
        user_data = self.user_history[user_id]
        user_data["false_positives"] += 1
        self.logger.info(f"Alert {alert_id} marked as false positive for user {user_id}")

    def mark_as_legitimate_threat(self, alert_id: str, user_id: str):
        """Manually mark an alert as legitimate threat for learning"""
        user_data = self.user_history[user_id]
        user_data["legitimate_threats"] += 1
        self.logger.info(f"Alert {alert_id} marked as legitimate threat for user {user_id}")

    def get_user_risk_score(self, user_id: str) -> Dict[str, Any]:
        """Get risk score for a user"""
        user_data = self.user_history[user_id]

        if user_data["alerts_triggered"] == 0:
            risk_level = "low"
            risk_score = 0.1
        else:
            threat_rate = (
                user_data["legitimate_threats"] / user_data["alerts_triggered"]
            )
            if threat_rate > 0.7:
                risk_level = "high"
                risk_score = 0.9
            elif threat_rate > 0.4:
                risk_level = "medium"
                risk_score = 0.6
            else:
                risk_level = "low"
                risk_score = 0.3

        return {
            "user_id": user_id,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "total_interactions": user_data["interactions"],
            "alerts_triggered": user_data["alerts_triggered"],
            "false_positives": user_data["false_positives"],
            "legitimate_threats": user_data["legitimate_threats"],
            "threat_patterns": dict(user_data["patterns"].most_common(5))
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get false positive detector statistics"""
        return {
            **self.stats,
            "false_positive_rate": (
                self.stats["false_positives_detected"] / self.stats["total_analyzed"]
                if self.stats["total_analyzed"] > 0 else 0
            ),
            "high_confidence_rate": (
                self.stats["high_confidence_threats"] / self.stats["total_analyzed"]
                if self.stats["total_analyzed"] > 0 else 0
            )
        }
