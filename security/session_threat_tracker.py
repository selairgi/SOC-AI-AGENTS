"""
Session-Based Threat Tracking - Detect Slow Prompt Injection
Tracks cumulative threat signals across multiple messages in a session.
Detects progressive attacks that bypass single-message analysis.
"""

import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import deque

@dataclass
class MessageSignal:
    """Single message threat signal"""
    timestamp: float
    message: str
    threat_score: float  # 0.0-1.0
    fp_probability: float
    detection_method: str
    suspicious_keywords: List[str] = field(default_factory=list)
    intent_type: Optional[str] = None

@dataclass
class SessionRisk:
    """Cumulative risk assessment for a session"""
    session_id: str
    user_id: str
    risk_score: float  # 0.0-1.0 cumulative
    message_count: int
    threat_messages: int
    escalation_pattern: bool  # Messages getting progressively more dangerous
    slow_injection_detected: bool
    reasoning: List[str] = field(default_factory=list)

class SessionThreatTracker:
    """
    Tracks threat signals across multiple messages in a session.
    Detects:
    - Slow prompt injection (gradual escalation)
    - Context manipulation (building up attack over time)
    - Probing behavior (testing defenses)
    """

    def __init__(self, window_size: int = 10, session_timeout: int = 1800):
        """
        Args:
            window_size: Number of recent messages to track per session
            session_timeout: Seconds of inactivity before session expires
        """
        self.logger = logging.getLogger("SessionTracker")
        self.window_size = window_size
        self.session_timeout = session_timeout

        # Session message history: session_id -> deque of MessageSignals
        self.sessions: Dict[str, deque] = {}

        # Session metadata
        self.session_metadata: Dict[str, Dict[str, Any]] = {}

        # Statistics
        self.stats = {
            "sessions_tracked": 0,
            "slow_injections_detected": 0,
            "escalation_patterns_detected": 0,
            "sessions_expired": 0
        }

    def track_message(self, session_id: str, user_id: str, message: str,
                     threat_score: float, fp_probability: float,
                     detection_method: str, suspicious_keywords: List[str] = None,
                     intent_type: Optional[str] = None) -> SessionRisk:
        """
        Track a new message in the session and calculate cumulative risk.

        Returns:
            SessionRisk: Updated risk assessment for the session
        """
        # Initialize session if new
        if session_id not in self.sessions:
            self.sessions[session_id] = deque(maxlen=self.window_size)
            self.session_metadata[session_id] = {
                "user_id": user_id,
                "start_time": time.time(),
                "last_activity": time.time()
            }
            self.stats["sessions_tracked"] += 1
        else:
            self.session_metadata[session_id]["last_activity"] = time.time()

        # Add message signal
        signal = MessageSignal(
            timestamp=time.time(),
            message=message[:200],  # Store truncated for privacy
            threat_score=threat_score,
            fp_probability=fp_probability,
            detection_method=detection_method,
            suspicious_keywords=suspicious_keywords or [],
            intent_type=intent_type
        )
        self.sessions[session_id].append(signal)

        # Calculate session risk
        return self._calculate_session_risk(session_id, user_id)

    def _calculate_session_risk(self, session_id: str, user_id: str) -> SessionRisk:
        """Calculate cumulative risk for a session"""
        signals = list(self.sessions[session_id])
        message_count = len(signals)

        if message_count == 0:
            return SessionRisk(
                session_id=session_id,
                user_id=user_id,
                risk_score=0.0,
                message_count=0,
                threat_messages=0,
                escalation_pattern=False,
                slow_injection_detected=False
            )

        # Count threat messages
        threat_messages = sum(1 for s in signals if s.threat_score > 0.3)

        # Calculate cumulative risk score
        # Recent messages weighted more heavily
        total_weighted_score = 0.0
        total_weight = 0.0

        for i, signal in enumerate(signals):
            # Exponential decay: recent messages matter more
            recency_weight = 1.0 + (i / len(signals))  # 1.0 to 2.0
            total_weighted_score += signal.threat_score * recency_weight
            total_weight += recency_weight

        cumulative_score = total_weighted_score / total_weight if total_weight > 0 else 0.0

        # Detect escalation pattern
        escalation_pattern = self._detect_escalation(signals)
        if escalation_pattern:
            cumulative_score += 0.2  # Boost for escalation
            self.stats["escalation_patterns_detected"] += 1

        # Detect slow injection
        slow_injection = self._detect_slow_injection(signals)
        if slow_injection:
            cumulative_score += 0.3  # Significant boost
            self.stats["slow_injections_detected"] += 1

        # Generate reasoning
        reasoning = []
        if message_count >= 5:
            reasoning.append(f"Session has {message_count} messages with {threat_messages} suspicious")
        if escalation_pattern:
            reasoning.append("⚠️ Escalation pattern detected - threat severity increasing")
        if slow_injection:
            reasoning.append("🚨 SLOW INJECTION DETECTED - Progressive attack across multiple messages")
        if cumulative_score > 0.5:
            reasoning.append(f"Cumulative risk score: {cumulative_score:.2f}")

        return SessionRisk(
            session_id=session_id,
            user_id=user_id,
            risk_score=min(1.0, cumulative_score),
            message_count=message_count,
            threat_messages=threat_messages,
            escalation_pattern=escalation_pattern,
            slow_injection_detected=slow_injection,
            reasoning=reasoning
        )

    def _detect_escalation(self, signals: List[MessageSignal]) -> bool:
        """
        Detect if threat scores are escalating over time.
        Returns True if messages are getting progressively more dangerous.
        """
        if len(signals) < 3:
            return False

        # Look at last 5 messages
        recent_signals = signals[-5:]

        # Calculate trend: are scores increasing?
        scores = [s.threat_score for s in recent_signals]

        # Simple escalation: each message more dangerous than previous
        escalating = all(scores[i] <= scores[i+1] for i in range(len(scores)-1))

        # Alternative: average of last 3 > average of first 3 in window
        if len(recent_signals) >= 4:
            first_half_avg = sum(scores[:len(scores)//2]) / (len(scores)//2)
            second_half_avg = sum(scores[len(scores)//2:]) / (len(scores) - len(scores)//2)
            escalating = escalating or (second_half_avg > first_half_avg + 0.2)

        return escalating

    def _detect_slow_injection(self, signals: List[MessageSignal]) -> bool:
        """
        Detect slow prompt injection:
        - Multiple messages with weak individual signals
        - But together form a coherent attack pattern
        - E.g., first message sets context, later messages exploit it
        """
        if len(signals) < 4:
            return False

        # Pattern 1: Context building then exploitation
        # Early messages: low threat but set up attack context
        # Later messages: exploit the context

        early_msgs = signals[:len(signals)//2]
        later_msgs = signals[len(signals)//2:]

        # Check for progressive keyword escalation
        early_keywords = set()
        later_keywords = set()

        for signal in early_msgs:
            early_keywords.update(signal.suspicious_keywords)
        for signal in later_msgs:
            later_keywords.update(signal.suspicious_keywords)

        # Attack keywords that appear in later messages but not early
        attack_keywords = {"ignore", "override", "bypass", "forget", "system", "instructions",
                          "reveal", "show", "secret", "password", "admin", "root"}

        new_attack_keywords = later_keywords.intersection(attack_keywords) - early_keywords

        # Pattern 2: Probing then attacking
        # Multiple low-threat messages (probing) followed by high-threat
        probing_phase = sum(1 for s in early_msgs if 0.1 < s.threat_score < 0.4) >= 2
        attack_phase = any(s.threat_score > 0.5 for s in later_msgs)

        slow_injection = (len(new_attack_keywords) >= 2) or (probing_phase and attack_phase)

        if slow_injection:
            self.logger.warning(f"🎯 Slow injection detected: {len(new_attack_keywords)} new attack keywords in later messages")

        return slow_injection

    def cleanup_expired_sessions(self):
        """Remove sessions that have been inactive"""
        current_time = time.time()
        expired_sessions = []

        for session_id, metadata in self.session_metadata.items():
            if current_time - metadata["last_activity"] > self.session_timeout:
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            del self.sessions[session_id]
            del self.session_metadata[session_id]
            self.stats["sessions_expired"] += 1

        if expired_sessions:
            self.logger.info(f"🧹 Cleaned up {len(expired_sessions)} expired sessions")

    def get_session_risk(self, session_id: str) -> Optional[SessionRisk]:
        """Get current risk for a session"""
        if session_id not in self.sessions:
            return None

        user_id = self.session_metadata[session_id]["user_id"]
        return self._calculate_session_risk(session_id, user_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get tracking statistics"""
        return {
            **self.stats,
            "active_sessions": len(self.sessions),
            "total_messages_tracked": sum(len(signals) for signals in self.sessions.values())
        }
