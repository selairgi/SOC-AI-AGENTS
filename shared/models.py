"""
Data models for SOC AI Agents.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, List
from enum import Enum


class AgentType(Enum):
    """Types of AI agents that can be monitored."""
    MEDICAL = "medical"
    FINANCIAL = "financial"
    CUSTOMER_SERVICE = "customer_service"
    CODE_ASSISTANT = "code_assistant"
    RESEARCH = "research"
    GENERAL = "general"


class ThreatType(Enum):
    """Types of security threats."""
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALICIOUS_INPUT = "malicious_input"
    SYSTEM_MANIPULATION = "system_manipulation"
    PRIVACY_VIOLATION = "privacy_violation"
    RATE_LIMIT_ABUSE = "rate_limit_abuse"
    MODEL_POISONING = "model_poisoning"


@dataclass
class AgentInfo:
    """Information about a monitored AI agent."""
    agent_id: str
    agent_type: AgentType
    name: str
    description: str
    endpoints: List[str]
    capabilities: List[str]
    security_level: str  # "low", "medium", "high", "critical"
    metadata: Dict[str, Any] = None


@dataclass
class LogEntry:
    timestamp: float
    source: str
    message: str
    agent_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    request_id: Optional[str] = None
    response_time: Optional[float] = None
    status_code: Optional[int] = None
    extra: Dict[str, Any] = None


@dataclass
class SecurityRule:
    """Security rule definition."""
    rule_id: str
    name: str
    description: str
    threat_type: ThreatType
    severity: str  # "low", "medium", "high", "critical"
    patterns: List[str]  # Regex patterns or keywords
    agent_types: List[AgentType]  # Which agent types this applies to
    enabled: bool = True
    metadata: Dict[str, Any] = None


@dataclass
class Alert:
    id: str
    timestamp: float
    severity: str
    title: str
    description: str
    threat_type: ThreatType
    agent_id: Optional[str] = None
    rule_id: Optional[str] = None
    evidence: Dict[str, Any] = None
    correlated: bool = False
    false_positive_probability: float = 0.0


@dataclass
class Playbook:
    action: str
    target: str
    justification: str
    owner: str = "soc_analyst"
    threat_type: Optional[ThreatType] = None
    agent_id: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def get_actions(self) -> List[str]:
        """Get structured actions from metadata, fallback to legacy target parsing."""
        if self.metadata and "actions" in self.metadata:
            return self.metadata["actions"]
        elif self.target:
            # Legacy support: parse target as comma-separated actions
            return [action.strip() for action in self.target.split(",") if action.strip()]
        else:
            return []
    
    def set_actions(self, actions: List[str]):
        """Set structured actions in metadata."""
        if not self.metadata:
            self.metadata = {}
        self.metadata["actions"] = actions

