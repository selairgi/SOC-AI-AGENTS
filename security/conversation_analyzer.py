"""
Conversation-Level Threat Analyzer
Detects multi-turn attacks that span multiple messages in a conversation.
"""

import logging
import time
from typing import Dict, List, Optional, Deque
from collections import deque, defaultdict
from dataclasses import dataclass, field

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import Alert, LogEntry, ThreatType


@dataclass
class ConversationMessage:
    """A single message in a conversation"""
    timestamp: float
    message: str
    user_id: str
    agent_id: str
    src_ip: Optional[str] = None


@dataclass
class ConversationContext:
    """Context for a conversation session"""
    session_id: str
    messages: Deque[ConversationMessage] = field(default_factory=lambda: deque(maxlen=20))
    first_message_time: float = 0.0
    last_message_time: float = 0.0
    user_id: Optional[str] = None
    src_ip: Optional[str] = None
    threat_indicators: List[str] = field(default_factory=list)


class ConversationAnalyzer:
    """
    Analyzes conversations to detect multi-turn attacks.

    Multi-turn attacks are sophisticated attacks that:
    1. Build context over multiple messages
    2. Gradually escalate permissions/access
    3. Use social engineering across conversation
    4. Extract information piece by piece
    """

    def __init__(self, window_size: int = 20, session_timeout: int = 1800):
        """
        Args:
            window_size: Number of messages to keep in history per session
            session_timeout: Seconds before a session is considered expired (default 30 min)
        """
        self.logger = logging.getLogger("ConversationAnalyzer")
        self.window_size = window_size
        self.session_timeout = session_timeout

        # Session storage: session_id -> ConversationContext
        self.conversations: Dict[str, ConversationContext] = {}

        # Multi-turn attack patterns
        self.multi_turn_patterns = {
            "progressive_probing": {
                "indicators": [
                    ["what", "can", "you", "do"],
                    ["tell", "me", "about", "your"],
                    ["show", "me", "how"],
                    ["now", "do", "this"]
                ],
                "description": "Progressive information gathering followed by exploitation",
                "min_messages": 3
            },
            "trust_building": {
                "indicators": [
                    ["hello", "hi", "hey"],
                    ["help", "me", "with"],
                    ["can", "you", "please"],
                    ["ignore", "forget", "disregard"]
                ],
                "description": "Building rapport before malicious request",
                "min_messages": 3
            },
            "permission_escalation": {
                "indicators": [
                    ["what", "are", "your", "rules"],
                    ["can", "you", "bypass"],
                    ["remove", "restrictions"],
                    ["admin", "mode", "developer"]
                ],
                "description": "Gradual escalation of permission requests",
                "min_messages": 2
            },
            "context_switching": {
                "indicators": [
                    ["imagine", "pretend", "role"],
                    ["new", "conversation", "fresh"],
                    ["forget", "previous", "reset"],
                    ["now", "you", "are"]
                ],
                "description": "Attempting to reset context and inject new role",
                "min_messages": 2
            },
            "information_extraction": {
                "indicators": [
                    ["what", "is", "your"],
                    ["tell", "me", "about"],
                    ["show", "display", "reveal"],
                    ["secret", "password", "key", "prompt"]
                ],
                "description": "Sequential information extraction attempts",
                "min_messages": 2
            }
        }

        # Statistics
        self.stats = {
            "total_sessions": 0,
            "active_sessions": 0,
            "multi_turn_attacks_detected": 0,
            "messages_analyzed": 0,
            "average_messages_per_session": 0.0
        }

    def add_message(self, log: LogEntry) -> Optional[ConversationContext]:
        """
        Add a message to the conversation history.

        Returns:
            Updated conversation context
        """
        session_id = log.session_id or f"session_{log.user_id}_{int(time.time()/3600)}"

        # Clean up expired sessions
        self._cleanup_expired_sessions()

        # Get or create conversation context
        if session_id not in self.conversations:
            self.conversations[session_id] = ConversationContext(
                session_id=session_id,
                first_message_time=time.time(),
                user_id=log.user_id,
                src_ip=log.src_ip
            )
            self.stats["total_sessions"] += 1

        context = self.conversations[session_id]

        # Add message to conversation
        message = ConversationMessage(
            timestamp=log.timestamp or time.time(),
            message=log.message or "",
            user_id=log.user_id or "",
            agent_id=log.agent_id or "",
            src_ip=log.src_ip
        )

        context.messages.append(message)
        context.last_message_time = time.time()

        self.stats["messages_analyzed"] += 1
        self.stats["active_sessions"] = len(self.conversations)

        # Update average
        total_messages = sum(len(ctx.messages) for ctx in self.conversations.values())
        self.stats["average_messages_per_session"] = total_messages / len(self.conversations)

        return context

    def analyze_conversation(self, session_id: str) -> Optional[Alert]:
        """
        Analyze a conversation for multi-turn attack patterns.

        Returns:
            Alert if multi-turn attack detected, None otherwise
        """
        if session_id not in self.conversations:
            return None

        context = self.conversations[session_id]

        # Need at least 2 messages for multi-turn analysis
        if len(context.messages) < 2:
            return None

        # Check each multi-turn pattern
        for pattern_name, pattern in self.multi_turn_patterns.items():
            if self._matches_multi_turn_pattern(context, pattern_name, pattern):
                return self._create_multi_turn_alert(context, pattern_name, pattern)

        return None

    def _matches_multi_turn_pattern(
        self,
        context: ConversationContext,
        pattern_name: str,
        pattern: Dict
    ) -> bool:
        """Check if conversation matches a multi-turn attack pattern"""
        messages = list(context.messages)
        min_messages = pattern.get("min_messages", 2)

        # Need enough messages
        if len(messages) < min_messages:
            return False

        indicators = pattern.get("indicators", [])
        matched_indicators = 0

        # Check how many indicator groups are matched in the conversation
        for indicator_group in indicators:
            # Check if any message matches this indicator group
            for message in messages:
                message_lower = message.message.lower()
                # Check if all words in indicator group appear in message
                if any(word in message_lower for word in indicator_group):
                    matched_indicators += 1
                    break  # Found match for this indicator group

        # Pattern matches if we found enough indicators
        # Require at least min_messages indicators to be present
        return matched_indicators >= min_messages

    def _create_multi_turn_alert(
        self,
        context: ConversationContext,
        pattern_name: str,
        pattern: Dict
    ) -> Alert:
        """Create an alert for a detected multi-turn attack"""
        self.stats["multi_turn_attacks_detected"] += 1

        # Build evidence from conversation
        messages_summary = []
        for i, msg in enumerate(list(context.messages)[-5:], 1):  # Last 5 messages
            messages_summary.append(f"{i}. {msg.message[:100]}...")

        alert_id = f"AL-{int(time.time()*1000)}-MULTITURN"

        return Alert(
            id=alert_id,
            timestamp=time.time(),
            severity="high",
            title=f"Multi-Turn Attack: {pattern_name.replace('_', ' ').title()}",
            description=f"{pattern['description']}. "
                       f"Detected across {len(context.messages)} messages in session. "
                       f"Pattern: {pattern_name}",
            threat_type=ThreatType.PROMPT_INJECTION,
            agent_id=context.messages[-1].agent_id if context.messages else None,
            rule_id="MULTI_TURN_ATTACK",
            evidence={
                "conversation_summary": messages_summary,
                "session_id": context.session_id,
                "user_id": context.user_id,
                "src_ip": context.src_ip,
                "message_count": len(context.messages),
                "pattern": pattern_name,
                "session_duration": time.time() - context.first_message_time,
                "confidence": 0.85
            },
            false_positive_probability=0.15
        )

    def analyze_log(self, log: LogEntry) -> Optional[Alert]:
        """
        Convenience method: add message and analyze in one call.

        Returns:
            Alert if threat detected, None otherwise
        """
        context = self.add_message(log)
        if not context:
            return None

        return self.analyze_conversation(context.session_id)

    def _cleanup_expired_sessions(self):
        """Remove expired sessions to prevent memory bloat"""
        current_time = time.time()
        expired = []

        for session_id, context in self.conversations.items():
            if current_time - context.last_message_time > self.session_timeout:
                expired.append(session_id)

        for session_id in expired:
            del self.conversations[session_id]
            self.logger.debug(f"Cleaned up expired session: {session_id}")

    def get_conversation_context(self, session_id: str) -> Optional[ConversationContext]:
        """Get conversation context for a session"""
        return self.conversations.get(session_id)

    def get_recent_messages(self, session_id: str, count: int = 10) -> List[ConversationMessage]:
        """Get recent messages from a conversation"""
        context = self.conversations.get(session_id)
        if not context:
            return []

        messages = list(context.messages)
        return messages[-count:]

    def clear_session(self, session_id: str):
        """Clear a specific session"""
        if session_id in self.conversations:
            del self.conversations[session_id]
            self.logger.info(f"Cleared session: {session_id}")

    def get_statistics(self) -> Dict:
        """Get analyzer statistics"""
        return {
            **self.stats,
            "active_conversations": [
                {
                    "session_id": ctx.session_id,
                    "message_count": len(ctx.messages),
                    "duration": time.time() - ctx.first_message_time,
                    "user_id": ctx.user_id
                }
                for ctx in list(self.conversations.values())[:10]  # Top 10
            ]
        }
