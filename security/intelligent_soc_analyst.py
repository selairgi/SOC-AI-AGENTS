"""
Intelligent SOC Analyst - Acts like a real security analyst
Verifies alerts, analyzes context, and makes informed decisions before remediation.

This analyst:
1. Verifies if alerts are real threats or just tests
2. Analyzes source context (localhost, test env, production)
3. Checks for patterns and behaviors
4. Makes decisions with reasoning
5. Learns from past decisions
"""

import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import Alert, Playbook, ThreatType, LogEntry


@dataclass
class AnalystDecision:
    """Decision made by the SOC analyst"""
    decision: str  # "approve_remediation", "reject_test", "investigate", "ignore"
    confidence: float  # 0.0 to 1.0
    reasoning: List[str]  # Why this decision was made
    context_flags: Dict[str, bool]  # Flags about the context
    recommended_action: Optional[str] = None
    alert_id: Optional[str] = None


@dataclass
class ContextAnalysis:
    """Analysis of the environment context"""
    is_localhost: bool = False
    is_test_environment: bool = False
    is_production: bool = False
    is_internal_ip: bool = False
    is_repeated_pattern: bool = False
    environment_type: str = "unknown"  # "localhost", "test", "staging", "production"


class IntelligentSOCAnalyst:
    """
    Intelligent SOC Analyst that acts like a real security analyst.

    Responsibilities:
    1. Verify alert legitimacy
    2. Analyze environmental context
    3. Detect test vs real attacks
    4. Make informed remediation decisions
    5. Provide reasoning for all decisions
    """

    def __init__(self):
        self.logger = logging.getLogger("IntelligentSOCAnalyst")

        # Known localhost/test indicators
        self.localhost_ips = {
            "127.0.0.1", "::1", "0.0.0.0", "localhost",
            "127.0.0.0/8"  # Loopback range
        }

        self.internal_ip_ranges = [
            "192.168.",  # Private class C
            "10.",       # Private class A
            "172.16.",   # Private class B (partial)
            "172.17.",   # Docker default
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31."    # Private class B end
        ]

        # Test environment indicators
        self.test_indicators = [
            "test", "testing", "sandbox", "dev", "development",
            "staging", "demo", "local", "localhost", "example",
            "sample", "training", "lab", "debug"
        ]

        # Production indicators
        self.production_indicators = [
            "prod", "production", "live", "www", "api",
            "app", "web", "service", "main", "master"
        ]

        # Track patterns and history
        self.alert_history = deque(maxlen=1000)  # Last 1000 alerts
        self.user_patterns = defaultdict(list)  # user_id -> list of alerts
        self.ip_patterns = defaultdict(list)    # ip -> list of alerts

        # Decision statistics
        self.stats = {
            "total_alerts_analyzed": 0,
            "approved_for_remediation": 0,
            "rejected_as_test": 0,
            "marked_for_investigation": 0,
            "ignored_benign": 0,
            "localhost_detections": 0,
            "test_env_detections": 0,
            "production_threats": 0
        }

        # Learning data - track decision correctness
        self.decision_feedback = defaultdict(list)  # decision_id -> feedback

    def analyze_alert(self, alert: Alert) -> AnalystDecision:
        """
        Main analysis function - acts like a real SOC analyst.

        Process:
        1. Analyze context (where is this coming from?)
        2. Verify legitimacy (is this a real attack or test?)
        3. Check patterns (have we seen this before?)
        4. Make decision with reasoning
        5. Recommend action
        """
        self.stats["total_alerts_analyzed"] += 1

        # Extract context from alert
        src_ip = alert.evidence.get("log", {}).get("src_ip", "")
        user_id = alert.evidence.get("log", {}).get("user_id", "")
        session_id = alert.evidence.get("log", {}).get("session_id", "")
        message = alert.evidence.get("log", {}).get("message", "")

        # Step 1: Analyze environment context
        context = self._analyze_context(src_ip, user_id, session_id, message)

        # Step 2: Build reasoning
        reasoning = []
        context_flags = {}

        # Check for localhost
        if context.is_localhost:
            reasoning.append(f"Source IP is localhost ({src_ip}) - likely testing/development")
            context_flags["localhost"] = True
            self.stats["localhost_detections"] += 1

        # Check for test environment
        if context.is_test_environment:
            reasoning.append(f"Environment indicators suggest TEST environment")
            context_flags["test_environment"] = True
            self.stats["test_env_detections"] += 1

        # Check for internal IP
        if context.is_internal_ip and not context.is_localhost:
            reasoning.append(f"Internal IP address ({src_ip}) - corporate network")
            context_flags["internal_ip"] = True

        # Check for production
        if context.is_production:
            reasoning.append(f"Production environment detected - HIGH PRIORITY")
            context_flags["production"] = True
            self.stats["production_threats"] += 1

        # Step 3: Analyze alert severity and confidence
        severity = alert.severity.lower()
        fp_probability = alert.false_positive_probability
        confidence_score = 1.0 - fp_probability

        reasoning.append(f"Alert severity: {severity.upper()}")
        reasoning.append(f"Confidence score: {confidence_score:.1%}")

        if fp_probability > 0.7:
            reasoning.append(f"High false positive probability ({fp_probability:.1%}) - likely benign")

        # Step 4: Check for repeated patterns
        context.is_repeated_pattern = self._check_repeated_pattern(src_ip, user_id, alert)
        if context.is_repeated_pattern:
            reasoning.append("Repeated attack pattern detected from this source")
            context_flags["repeated_pattern"] = True

        # Step 5: Make decision based on all factors
        decision, action = self._make_decision(
            alert=alert,
            context=context,
            severity=severity,
            confidence_score=confidence_score,
            fp_probability=fp_probability,
            reasoning=reasoning
        )

        # Step 6: Create analyst decision
        analyst_decision = AnalystDecision(
            decision=decision,
            confidence=confidence_score,
            reasoning=reasoning,
            context_flags=context_flags,
            recommended_action=action,
            alert_id=alert.id
        )

        # Update statistics
        if decision == "approve_remediation":
            self.stats["approved_for_remediation"] += 1
        elif decision == "reject_test":
            self.stats["rejected_as_test"] += 1
        elif decision == "investigate":
            self.stats["marked_for_investigation"] += 1
        elif decision == "ignore":
            self.stats["ignored_benign"] += 1

        # Store in history
        self.alert_history.append({
            "alert_id": alert.id,
            "timestamp": time.time(),
            "decision": decision,
            "context": context,
            "src_ip": src_ip,
            "user_id": user_id
        })

        # Store in pattern tracking
        if src_ip:
            self.ip_patterns[src_ip].append(alert.id)
        if user_id:
            self.user_patterns[user_id].append(alert.id)

        self.logger.info(f"Analyst Decision: {decision} for alert {alert.id}")
        self.logger.info(f"Reasoning: {'; '.join(reasoning)}")

        return analyst_decision

    def _analyze_context(self, src_ip: str, user_id: str, session_id: str, message: str) -> ContextAnalysis:
        """Analyze the environment context"""
        context = ContextAnalysis()

        # Check if localhost
        if src_ip in self.localhost_ips or src_ip.startswith("127."):
            context.is_localhost = True
            context.environment_type = "localhost"

        # Check if internal IP
        if src_ip and any(src_ip.startswith(prefix) for prefix in self.internal_ip_ranges):
            context.is_internal_ip = True

        # Check for test environment indicators in various fields
        check_fields = [src_ip, user_id, session_id, message]
        test_score = 0
        prod_score = 0

        for field in check_fields:
            if not field:
                continue
            field_lower = str(field).lower()

            # Check for test indicators
            for indicator in self.test_indicators:
                if indicator in field_lower:
                    test_score += 1

            # Check for production indicators
            for indicator in self.production_indicators:
                if indicator in field_lower:
                    prod_score += 1

        # Determine environment type
        if context.is_localhost:
            context.is_test_environment = True
            context.environment_type = "localhost"
        elif test_score > prod_score:
            context.is_test_environment = True
            context.environment_type = "test"
        elif prod_score > 0:
            context.is_production = True
            context.environment_type = "production"
        elif context.is_internal_ip:
            context.environment_type = "internal"
        else:
            context.is_production = True  # Assume production if unknown external
            context.environment_type = "production"

        return context

    def _check_repeated_pattern(self, src_ip: str, user_id: str, alert: Alert) -> bool:
        """Check if this is a repeated attack pattern"""
        # Check IP history
        if src_ip and src_ip in self.ip_patterns:
            ip_alerts = self.ip_patterns[src_ip]
            if len(ip_alerts) >= 3:  # 3+ alerts from same IP
                return True

        # Check user history
        if user_id and user_id in self.user_patterns:
            user_alerts = self.user_patterns[user_id]
            if len(user_alerts) >= 3:  # 3+ alerts from same user
                return True

        return False

    def _make_decision(
        self,
        alert: Alert,
        context: ContextAnalysis,
        severity: str,
        confidence_score: float,
        fp_probability: float,
        reasoning: List[str]
    ) -> Tuple[str, Optional[str]]:
        """
        Make the final decision - like a real SOC analyst would.

        Decision logic:
        1. Localhost/Test → Reject (don't remediate, log only)
        2. High FP probability → Ignore
        3. Low confidence → Investigate
        4. Production + High severity + High confidence → Approve remediation
        5. Internal IP + Medium severity → Investigate
        6. Everything else → Context-based decision
        """

        # Rule 1: NEVER remediate localhost (highest priority)
        if context.is_localhost:
            reasoning.append("🔒 DECISION: Reject - Localhost detected, this is testing/development")
            reasoning.append("Action: Log event for record, no blocking")
            return "reject_test", "log_only"

        # Rule 2: Test environment - monitor but don't block
        if context.is_test_environment and not context.is_production:
            reasoning.append("🧪 DECISION: Reject - Test environment detected")
            reasoning.append("Action: Monitor and log, suitable for testing")
            return "reject_test", "monitor"

        # Rule 3: Very high false positive probability
        if fp_probability > 0.8:
            reasoning.append("✓ DECISION: Ignore - Very high false positive probability")
            reasoning.append("Action: Log for review, no action needed")
            return "ignore", "log_only"

        # Rule 4: Low confidence - needs human review
        if confidence_score < 0.4:
            reasoning.append("⚠ DECISION: Investigate - Low confidence score")
            reasoning.append("Action: Flag for human analyst review")
            return "investigate", "require_human_review"

        # Rule 5: Production + Critical/High severity + High confidence = REMEDIATE
        if context.is_production and severity in ["critical", "high"]:
            if confidence_score >= 0.7:
                reasoning.append("🚨 DECISION: Approve Remediation - Production threat with high confidence")

                # Determine action based on severity and threat type
                if severity == "critical":
                    if context.is_repeated_pattern:
                        reasoning.append("Action: BLOCK IP + Suspend User (repeated attacks)")
                        return "approve_remediation", "block_ip_and_suspend_user"
                    else:
                        reasoning.append("Action: BLOCK IP temporarily + Monitor")
                        return "approve_remediation", "block_ip_temp"
                else:  # high severity
                    reasoning.append("Action: Rate limit + Enhanced monitoring")
                    return "approve_remediation", "rate_limit"
            else:
                reasoning.append("⚠ DECISION: Investigate - Production + High severity but medium confidence")
                reasoning.append("Action: Enhanced monitoring + Analyst review")
                return "investigate", "monitor_closely"

        # Rule 6: Internal IP + Medium severity
        if context.is_internal_ip and severity == "medium":
            if confidence_score >= 0.6:
                reasoning.append("⚠ DECISION: Investigate - Internal IP with medium threat")
                reasoning.append("Action: Monitor closely, notify security team")
                return "investigate", "monitor_and_notify"
            else:
                reasoning.append("✓ DECISION: Ignore - Internal IP, likely benign activity")
                return "ignore", "log_only"

        # Rule 7: Repeated pattern from external source
        if context.is_repeated_pattern and not context.is_internal_ip:
            reasoning.append("🚨 DECISION: Approve Remediation - Repeated attack pattern from external source")
            reasoning.append("Action: BLOCK IP + Notify security team")
            return "approve_remediation", "block_ip"

        # Rule 8: Medium severity, medium confidence
        if severity == "medium" and confidence_score >= 0.5:
            reasoning.append("⚠ DECISION: Investigate - Medium severity, needs review")
            reasoning.append("Action: Monitor and log, flag for review")
            return "investigate", "monitor"

        # Rule 9: Low severity or very low confidence
        if severity == "low" or confidence_score < 0.3:
            reasoning.append("✓ DECISION: Ignore - Low risk")
            reasoning.append("Action: Log only")
            return "ignore", "log_only"

        # Default: Investigate (conservative approach)
        reasoning.append("⚠ DECISION: Investigate - Uncertain, requires analyst review")
        reasoning.append("Action: Monitor and flag for human review")
        return "investigate", "require_human_review"

    def provide_feedback(self, decision_id: str, was_correct: bool, actual_outcome: str):
        """
        Provide feedback on a decision for learning.

        Args:
            decision_id: The alert ID for the decision
            was_correct: Whether the decision was correct
            actual_outcome: What actually happened
        """
        self.decision_feedback[decision_id].append({
            "was_correct": was_correct,
            "actual_outcome": actual_outcome,
            "timestamp": time.time()
        })

        self.logger.info(f"Feedback recorded for decision {decision_id}: {'Correct' if was_correct else 'Incorrect'}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get analyst statistics and performance metrics"""
        total = self.stats["total_alerts_analyzed"]

        if total == 0:
            return self.stats

        return {
            **self.stats,
            "approval_rate": self.stats["approved_for_remediation"] / total,
            "rejection_rate": self.stats["rejected_as_test"] / total,
            "investigation_rate": self.stats["marked_for_investigation"] / total,
            "ignore_rate": self.stats["ignored_benign"] / total,
            "localhost_rate": self.stats["localhost_detections"] / total,
            "test_env_rate": self.stats["test_env_detections"] / total,
            "production_threat_rate": self.stats["production_threats"] / total,
            "recent_decisions": list(self.alert_history)[-10:] if self.alert_history else []
        }

    def get_decision_summary(self, decision: AnalystDecision) -> str:
        """Get a human-readable summary of the decision"""
        summary = f"Decision: {decision.decision.upper().replace('_', ' ')}\n"
        summary += f"Confidence: {decision.confidence:.1%}\n\n"
        summary += "Reasoning:\n"
        for i, reason in enumerate(decision.reasoning, 1):
            summary += f"{i}. {reason}\n"

        if decision.recommended_action:
            summary += f"\nRecommended Action: {decision.recommended_action}\n"

        if decision.context_flags:
            summary += "\nContext Flags:\n"
            for flag, value in decision.context_flags.items():
                if value:
                    summary += f"  - {flag}: {value}\n"

        return summary
