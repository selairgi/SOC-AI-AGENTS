"""
Adaptive Learning System - Continuous Improvement from Feedback
Learns from:
- False Positives confirmed by users
- Unjustified blocks (legitimate queries blocked)
- Successful attacks that bypassed detection
"""

import json
import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict

@dataclass
class FeedbackSample:
    """Sample with human feedback"""
    message: str
    predicted_label: str  # "safe", "threat", "investigate"
    actual_label: str  # Ground truth from human
    timestamp: float
    fp_probability: float
    confidence: float
    detection_method: str
    reasoning: List[str]
    session_id: str
    user_id: str

class AdaptiveLearningSystem:
    """
    Learns from operator feedback to improve detection over time.
    """

    def __init__(self, cache_dir: str = "security/.cache"):
        self.logger = logging.getLogger("AdaptiveLearning")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.feedback_file = self.cache_dir / "feedback_samples.pkl"
        self.pattern_file = self.cache_dir / "learned_patterns.json"

        # Load existing feedback
        self.feedback_samples: List[FeedbackSample] = self._load_feedback()
        self.learned_patterns = self._load_patterns()

        # Statistics
        self.stats = {
            "total_feedback": 0,
            "false_positives_learned": 0,
            "missed_threats_learned": 0,
            "patterns_extracted": 0
        }

    def add_feedback(self, sample: FeedbackSample):
        """
        Add a feedback sample from operator review.

        Args:
            sample: Feedback with ground truth label
        """
        self.feedback_samples.append(sample)
        self.stats["total_feedback"] += 1

        # Categorize feedback
        if sample.predicted_label == "threat" and sample.actual_label == "safe":
            # False positive - blocked legitimate message
            self.stats["false_positives_learned"] += 1
            self._learn_false_positive_pattern(sample)
            self.logger.info(f"📚 Learned FP: '{sample.message[:50]}...'")

        elif sample.predicted_label in ["safe", "investigate"] and sample.actual_label == "threat":
            # Missed threat - attack bypassed detection
            self.stats["missed_threats_learned"] += 1
            self._learn_threat_pattern(sample)
            self.logger.warning(f"⚠️ Learned missed threat: '{sample.message[:50]}...'")

        # Save every 10 samples
        if len(self.feedback_samples) % 10 == 0:
            self._save_feedback()
            self._save_patterns()

    def _learn_false_positive_pattern(self, sample: FeedbackSample):
        """Extract patterns from false positives to avoid future FPs"""
        message_lower = sample.message.lower()

        # Extract common FP indicators
        fp_indicators = {
            "educational_phrases": [],
            "legitimate_contexts": [],
            "safe_question_patterns": []
        }

        # Educational phrases
        educational_keywords = ["what is", "explain", "how does", "concept of", "learn about", "understand"]
        for keyword in educational_keywords:
            if keyword in message_lower:
                fp_indicators["educational_phrases"].append(keyword)

        # Legitimate contexts (e.g., discussing security in academic context)
        if "'" in sample.message or '"' in sample.message:
            # Content in quotes = discussing/asking about something
            fp_indicators["legitimate_contexts"].append("quoted_content")

        # Safe question patterns
        if message_lower.startswith(("what", "how", "why", "when", "where")):
            fp_indicators["safe_question_patterns"].append(message_lower.split()[0])

        # Store in learned patterns
        if "false_positive_indicators" not in self.learned_patterns:
            self.learned_patterns["false_positive_indicators"] = defaultdict(int)

        for category, patterns in fp_indicators.items():
            for pattern in patterns:
                key = f"{category}:{pattern}"
                self.learned_patterns["false_positive_indicators"][key] = \
                    self.learned_patterns["false_positive_indicators"].get(key, 0) + 1

    def _learn_threat_pattern(self, sample: FeedbackSample):
        """Extract patterns from missed threats to improve detection"""
        message_lower = sample.message.lower()

        # Extract attack patterns
        threat_patterns = {
            "bypass_keywords": [],
            "obfuscation_techniques": [],
            "social_engineering": []
        }

        # Common bypass keywords
        bypass_keywords = ["workaround", "alternative", "different way", "instead", "trick", "bypass"]
        for keyword in bypass_keywords:
            if keyword in message_lower:
                threat_patterns["bypass_keywords"].append(keyword)

        # Obfuscation (e.g., l33t speak, unicode tricks)
        if any(char in sample.message for char in ["@", "3", "1", "0", "$"]):
            threat_patterns["obfuscation_techniques"].append("l33t_speak")

        # Social engineering
        urgency_words = ["urgent", "immediately", "asap", "emergency", "critical"]
        authority_words = ["admin", "manager", "ceo", "authorized", "permission"]

        if any(word in message_lower for word in urgency_words):
            threat_patterns["social_engineering"].append("urgency")
        if any(word in message_lower for word in authority_words):
            threat_patterns["social_engineering"].append("authority")

        # Store in learned patterns
        if "threat_indicators" not in self.learned_patterns:
            self.learned_patterns["threat_indicators"] = defaultdict(int)

        for category, patterns in threat_patterns.items():
            for pattern in patterns:
                key = f"{category}:{pattern}"
                self.learned_patterns["threat_indicators"][key] = \
                    self.learned_patterns["threat_indicators"].get(key, 0) + 1

        self.stats["patterns_extracted"] += 1

    def get_fp_boost(self, message: str) -> float:
        """
        Calculate FP probability boost based on learned patterns.

        Returns:
            float: Boost value (0.0 to 0.3) to add to FP probability
        """
        if "false_positive_indicators" not in self.learned_patterns:
            return 0.0

        message_lower = message.lower()
        boost = 0.0

        for pattern_key, count in self.learned_patterns["false_positive_indicators"].items():
            category, pattern = pattern_key.split(":", 1)

            if pattern in message_lower:
                # More occurrences in feedback = stronger indicator
                weight = min(0.1, count * 0.02)
                boost += weight

        return min(0.3, boost)  # Cap at 30% boost

    def get_threat_boost(self, message: str) -> float:
        """
        Calculate threat probability boost based on learned patterns.

        Returns:
            float: Boost value (0.0 to 0.3) to add to threat probability
        """
        if "threat_indicators" not in self.learned_patterns:
            return 0.0

        message_lower = message.lower()
        boost = 0.0

        for pattern_key, count in self.learned_patterns["threat_indicators"].items():
            category, pattern = pattern_key.split(":", 1)

            if pattern in message_lower:
                # More occurrences in feedback = stronger indicator
                weight = min(0.15, count * 0.03)
                boost += weight

        return min(0.3, boost)  # Cap at 30% boost

    def get_statistics(self) -> Dict[str, Any]:
        """Get learning statistics"""
        return {
            **self.stats,
            "fp_patterns_learned": len([k for k in self.learned_patterns.get("false_positive_indicators", {})]),
            "threat_patterns_learned": len([k for k in self.learned_patterns.get("threat_indicators", {})]),
            "total_samples": len(self.feedback_samples)
        }

    def _load_feedback(self) -> List[FeedbackSample]:
        """Load feedback samples from disk"""
        if self.feedback_file.exists():
            try:
                with open(self.feedback_file, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load feedback: {e}")
        return []

    def _save_feedback(self):
        """Save feedback samples to disk"""
        try:
            with open(self.feedback_file, 'wb') as f:
                pickle.dump(self.feedback_samples, f)
            self.logger.info(f"💾 Saved {len(self.feedback_samples)} feedback samples")
        except Exception as e:
            self.logger.error(f"Failed to save feedback: {e}")

    def _load_patterns(self) -> Dict[str, Any]:
        """Load learned patterns from disk"""
        if self.pattern_file.exists():
            try:
                with open(self.pattern_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load patterns: {e}")
        return {}

    def _save_patterns(self):
        """Save learned patterns to disk"""
        try:
            with open(self.pattern_file, 'w') as f:
                # Convert defaultdict to regular dict for JSON
                patterns_dict = {}
                for key, value in self.learned_patterns.items():
                    if isinstance(value, defaultdict):
                        patterns_dict[key] = dict(value)
                    else:
                        patterns_dict[key] = value
                json.dump(patterns_dict, f, indent=2)
            self.logger.info(f"💾 Saved {self.stats['patterns_extracted']} learned patterns")
        except Exception as e:
            self.logger.error(f"Failed to save patterns: {e}")
