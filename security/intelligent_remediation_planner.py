"""
Intelligent Remediation Planner
Decides on remediation actions based on alert context, severity, and confidence.
Replaces static if/else logic in SOC Analyst.
"""

import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import Alert, Playbook, ThreatType
from ai.real_ai_integration import RealAIIntegration


@dataclass
class RemediationPlan:
    """A planned remediation response."""
    action: str  # Primary action name (e.g., "block_ip", "monitor")
    target: str  # Target entity (IP, User ID)
    justification: str
    actions: List[str]  # List of executable action strings
    metadata: Dict[str, Any] = field(default_factory=dict)


class IntelligentRemediationPlanner:
    """
    Intelligent planner that decides on remediation actions.
    Considers:
    - Alert severity and threat type
    - Confidence/Certainty scores
    - Context (Lab vs Prod, Localhost)
    - Historical effectiveness (optional/future)
    """

    def __init__(self, ai_integration: Optional[RealAIIntegration] = None):
        self.logger = logging.getLogger("IntelligentRemediationPlanner")
        self.ai_integration = ai_integration or RealAIIntegration()
        
        # Context definitions
        self.lab_ips = {
            "127.0.0.1", "localhost", "::1", "0.0.0.0"
        }
        
    def create_remediation_plan(self, alert: Alert, certainty_score: float) -> Optional[RemediationPlan]:
        """
        Create a remediation plan for an alert.
        """
        # 1. Analyze Context (Is this a lab test? Is it localhost?)
        is_lab_context = self._is_lab_context(alert)
        
        # 2. Determine appropriate actions based on severity, certainty, and context
        if self.ai_integration.use_real_ai:
            return self._plan_with_ai(alert, certainty_score, is_lab_context)
        else:
            return self._plan_with_heuristics(alert, certainty_score, is_lab_context)

    def _is_lab_context(self, alert: Alert) -> bool:
        """Determine if the alert is occurring in a lab/test context."""
        src_ip = alert.evidence.get("log", {}).get("src_ip")
        if src_ip and (src_ip in self.lab_ips or str(src_ip).startswith("192.168.") or str(src_ip).startswith("10.")):
            # Private IPs might be prod, but localhost is definitely lab/local
            if src_ip in self.lab_ips:
                return True
            # Could add more sophisticated checks here (e.g., environment vars)
        
        # Check message content for test indicators if available
        message = alert.evidence.get("log", {}).get("message", "").lower()
        if "test" in message and "ignore" not in message: # Simple heuristic
             # "ignore" is common in attacks ("ignore previous..."), so careful with that
             pass
             
        return False

    def _plan_with_heuristics(self, alert: Alert, certainty_score: float, is_lab_context: bool) -> Optional[RemediationPlan]:
        """Rule-based planning logic (enhanced)."""
        
        actions = []
        primary_action = "monitor" # Default
        justification = []
        target = ""
        
        src_ip = alert.evidence.get("log", {}).get("src_ip")
        user_id = alert.evidence.get("log", {}).get("user_id")
        agent_id = alert.agent_id

        # Target selection priority
        if src_ip: target = src_ip
        elif user_id: target = user_id
        else: target = "unknown"

        # Logic Matrix
        # Critical/High Severity + Medium+ Certainty -> Block
        # Critical/High Severity + Low Certainty -> Investigate
        # Medium Severity + High Certainty -> Block
        # Medium Severity + Medium Certainty -> Investigate
        # Lab Context (localhost) -> Log only (safety guardrail)
        
        if is_lab_context and src_ip in self.lab_ips:
            # Localhost safety guardrail - never block, but log
            primary_action = "log_event"
            actions.append("log_security_event")
            actions.append("notify_admin")
            justification.append(f"Detected threat from localhost ({src_ip}). Blocking suppressed for safety.")
        
        elif alert.severity in ["critical", "high"]:
            # High/Critical severity threats - be more aggressive
            if certainty_score >= 0.45:  # Lowered threshold to 0.45 for high/critical severity
                # Medium+ certainty for critical/high severity -> Block
                primary_action = "block_ip" if src_ip else "suspend_user"
                if src_ip: actions.append(f"block_ip:{src_ip}")
                if user_id: actions.append(f"suspend_user:{user_id}")
                actions.append("notify_security_team")
                justification.append(f"{alert.severity.upper()} severity threat with {certainty_score:.2f} certainty. Immediate blocking required.")
            else:
                # Very low certainty but high severity -> Investigate
                primary_action = "investigate"
                actions.append("require_human_review")
                if src_ip: actions.append(f"enhanced_monitoring:{src_ip}")
                justification.append(f"{alert.severity.upper()} severity threat with low certainty ({certainty_score:.2f}). Investigation required.")
        
        elif certainty_score >= 0.7:
            # High confidence for medium/low severity
            primary_action = "block_ip" if src_ip else "suspend_user"
            if src_ip: actions.append(f"block_ip:{src_ip}")
            if user_id: actions.append(f"suspend_user:{user_id}")
            actions.append("notify_security_team")
            justification.append(f"High confidence ({certainty_score:.2f}) {alert.severity} threat detected.")
        
        elif certainty_score >= 0.4:
            # Medium confidence
            primary_action = "investigate"
            actions.append("require_human_review")
            if src_ip: actions.append(f"enhanced_monitoring:{src_ip}")
            justification.append(f"Suspicious activity ({certainty_score:.2f} certainty). Investigation required.")
            
        else:
            # Low confidence
            return None # Treat as false positive / noise

        return RemediationPlan(
            action=primary_action,
            target=target,
            justification=" ".join(justification),
            actions=actions,
            metadata={
                "certainty_score": certainty_score,
                "is_lab_context": is_lab_context,
                "planner": "heuristic"
            }
        )

    def _plan_with_ai(self, alert: Alert, certainty_score: float, is_lab_context: bool) -> Optional[RemediationPlan]:
        """Use AI to generate a remediation plan."""
        # Fallback to heuristics for now to ensure reliability, 
        # but this is where you'd prompt the LLM:
        # "Given this alert X with certainty Y in context Z, what steps should be taken?"
        # The LLM would return a JSON list of actions.
        
        # For reliability in this demo, we wrap the heuristic logic
        # In a real impl, we'd call self.ai_integration.generate_response(...)
        return self._plan_with_heuristics(alert, certainty_score, is_lab_context)
