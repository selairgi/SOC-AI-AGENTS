"""
False Positive Detector - Simplified version for SOC Core.

Uses pattern analysis and context scoring to reduce false positive alerts.
"""

import re
import logging
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import time


@dataclass
class FPScore:
    """False positive analysis result."""
    is_false_positive: bool
    confidence: float  # 0.0 - 1.0 (threat confidence)
    fp_probability: float  # 0.0 - 1.0
    factors: Dict[str, float] = field(default_factory=dict)
    reasoning: List[str] = field(default_factory=list)
    recommended_action: str = "investigate"  # block, investigate, monitor, ignore


class FalsePositiveDetector:
    """
    Detects false positives using multiple signals:
    - Pattern legitimacy scoring
    - User behavior analysis
    - Context awareness
    - Threat indicator strength
    """

    # Patterns that indicate legitimate queries
    LEGITIMATE_PATTERNS = [
        r"how (do|can) (i|you)",
        r"what (is|are|does)",
        r"tell me (about|how)",
        r"explain (the|how|why)",
        r"can you help",
        r"i (want|need) to (know|understand)",
    ]

    # High-confidence threat indicators
    THREAT_INDICATORS = [
        r"ignore (all )?previous",
        r"forget (all )?previous",
        r"system\.prompt|system_prompt",
        r"<\|.*?\|>",
        r"sudo|chmod|rm -rf|DROP TABLE",
        r"(show|give).*(password|api.?key|secret|token)",
        r"' or '1'='1|union select|--",
        r"<script>|javascript:|onerror=",
    ]

    # Legitimate context keywords
    CONTEXT_KEYWORDS = [
        "help", "tutorial", "learn", "understand", "explain",
        "question", "wondering", "curious", "information"
    ]

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("FPDetector")

        # User behavior tracking
        self.user_history: Dict[str, Dict] = defaultdict(lambda: {
            "interactions": 0,
            "alerts": 0,
            "false_positives": 0,
            "threats": 0,
            "first_seen": time.time()
        })

        # Stats
        self.stats = {
            "analyzed": 0,
            "fp_detected": 0,
            "threats_confirmed": 0
        }

    def analyze(
        self,
        message: str,
        threat_type: str,
        severity: str = "medium",
        user_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> FPScore:
        """
        Analyze if an alert is a false positive.

        Args:
            message: The log/message content
            threat_type: Type of threat detected
            severity: Alert severity
            user_id: Optional user identifier
            context: Additional context

        Returns:
            FPScore with analysis results
        """
        self.stats["analyzed"] += 1
        context = context or {}

        factors = {}
        reasoning = []

        # Factor 1: Pattern legitimacy (30%)
        legit_score, legit_reasons = self._check_legitimate_patterns(message)
        factors["pattern_legitimacy"] = legit_score * 0.30
        reasoning.extend(legit_reasons)

        # Factor 2: Threat indicators (30%)
        threat_score, threat_reasons = self._check_threat_indicators(message, threat_type)
        factors["threat_indicators"] = threat_score * 0.30
        reasoning.extend(threat_reasons)

        # Factor 3: Context analysis (20%)
        context_score, context_reasons = self._analyze_context(message, context)
        factors["context"] = context_score * 0.20
        reasoning.extend(context_reasons)

        # Factor 4: User behavior (20%)
        if user_id:
            user_score, user_reasons = self._analyze_user(user_id)
            factors["user_behavior"] = user_score * 0.20
            reasoning.extend(user_reasons)
        else:
            factors["user_behavior"] = 0.10  # Neutral

        # Calculate threat confidence
        threat_confidence = sum(factors.values())
        fp_probability = 1.0 - threat_confidence

        # Determine if false positive
        is_fp = fp_probability > 0.65

        # Update stats
        if is_fp:
            self.stats["fp_detected"] += 1
        elif threat_confidence > 0.7:
            self.stats["threats_confirmed"] += 1

        # Update user history
        if user_id:
            self._update_user_history(user_id, is_fp)

        # Determine action
        action = self._determine_action(threat_confidence, severity)

        return FPScore(
            is_false_positive=is_fp,
            confidence=threat_confidence,
            fp_probability=fp_probability,
            factors=factors,
            reasoning=reasoning,
            recommended_action=action
        )

    def _check_legitimate_patterns(self, message: str) -> Tuple[float, List[str]]:
        """Check for patterns indicating legitimate queries."""
        message_lower = message.lower()
        reasoning = []

        # Count legitimate pattern matches
        legit_matches = sum(
            1 for p in self.LEGITIMATE_PATTERNS
            if re.search(p, message_lower)
        )

        # Count context keywords
        keyword_matches = sum(
            1 for kw in self.CONTEXT_KEYWORDS
            if kw in message_lower
        )

        # Check grammar/structure
        has_question = "?" in message
        has_proper_structure = len(message.split()) >= 3

        if legit_matches > 0:
            reasoning.append(f"Matches {legit_matches} legitimate pattern(s)")
        if keyword_matches > 0:
            reasoning.append(f"Contains {keyword_matches} context keyword(s)")
        if has_question:
            reasoning.append("Formatted as question")

        # Higher score = more legitimate = lower threat
        # We INVERT this for threat confidence
        legitimacy = min(1.0, (
            legit_matches * 0.25 +
            keyword_matches * 0.15 +
            (0.2 if has_question else 0) +
            (0.15 if has_proper_structure else 0)
        ))

        # Return inverted score (1-legitimacy = threat contribution)
        return 1.0 - legitimacy, reasoning

    def _check_threat_indicators(self, message: str, threat_type: str) -> Tuple[float, List[str]]:
        """Check for high-confidence threat indicators."""
        message_lower = message.lower()
        reasoning = []

        matches = 0
        for pattern in self.THREAT_INDICATORS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                matches += 1

        if matches > 0:
            reasoning.append(f"Matched {matches} threat indicator(s)")

        # Additional threat-specific checks
        threat_keywords = {
            "sql_injection": ["select", "union", "drop", "--", "'"],
            "xss": ["script", "onerror", "onload", "javascript"],
            "command_injection": [";", "|", "&", "`", "$("],
            "prompt_injection": ["ignore", "forget", "override", "pretend"],
        }

        if threat_type in threat_keywords:
            keyword_hits = sum(
                1 for kw in threat_keywords[threat_type]
                if kw in message_lower
            )
            if keyword_hits >= 2:
                matches += 1
                reasoning.append(f"Multiple {threat_type} keywords found")

        # Calculate threat score (0-1)
        threat_score = min(1.0, matches * 0.35)
        return threat_score, reasoning

    def _analyze_context(self, message: str, context: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Analyze contextual factors."""
        reasoning = []
        score = 0.5  # Neutral default

        # Message length
        word_count = len(message.split())
        if word_count < 3:
            reasoning.append("Very short message - suspicious")
            score += 0.2
        elif word_count > 30:
            reasoning.append("Long message - mixed signal")

        # Special characters ratio
        if len(message) > 0:
            special_ratio = sum(1 for c in message if not c.isalnum() and c != ' ') / len(message)
            if special_ratio > 0.25:
                reasoning.append(f"High special char ratio: {special_ratio:.0%}")
                score += 0.2

        # Source IP analysis
        source_ip = context.get("source_ip", "")
        if source_ip in ["127.0.0.1", "localhost", "::1"]:
            reasoning.append("Localhost source - likely testing")
            score -= 0.3

        return max(0, min(1, score)), reasoning

    def _analyze_user(self, user_id: str) -> Tuple[float, List[str]]:
        """Analyze user behavior history."""
        user = self.user_history[user_id]
        reasoning = []

        # New user
        if user["interactions"] < 5:
            reasoning.append("New user - limited history")
            return 0.5, reasoning

        # Calculate FP rate
        if user["alerts"] > 0:
            fp_rate = user["false_positives"] / user["alerts"]
            threat_rate = user["threats"] / user["alerts"]

            if fp_rate > 0.6:
                reasoning.append(f"User has high FP rate: {fp_rate:.0%}")
                return 0.3, reasoning  # Lower threat score
            elif threat_rate > 0.5:
                reasoning.append(f"User has high threat rate: {threat_rate:.0%}")
                return 0.8, reasoning  # Higher threat score

        return 0.5, reasoning

    def _update_user_history(self, user_id: str, is_fp: bool) -> None:
        """Update user history with result."""
        user = self.user_history[user_id]
        user["interactions"] += 1
        user["alerts"] += 1
        if is_fp:
            user["false_positives"] += 1
        else:
            user["threats"] += 1

    def _determine_action(self, confidence: float, severity: str) -> str:
        """Determine recommended action."""
        if confidence >= 0.85:
            return "block"
        elif confidence >= 0.65:
            return "block" if severity in ("high", "critical") else "investigate"
        elif confidence >= 0.45:
            return "investigate"
        elif confidence >= 0.25:
            return "monitor"
        else:
            return "ignore"

    def mark_false_positive(self, user_id: str) -> None:
        """Manually mark last alert as false positive."""
        if user_id in self.user_history:
            self.user_history[user_id]["false_positives"] += 1

    def mark_threat(self, user_id: str) -> None:
        """Manually mark last alert as confirmed threat."""
        if user_id in self.user_history:
            self.user_history[user_id]["threats"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        total = self.stats["analyzed"]
        return {
            **self.stats,
            "fp_rate": self.stats["fp_detected"] / total if total > 0 else 0,
            "threat_rate": self.stats["threats_confirmed"] / total if total > 0 else 0
        }
