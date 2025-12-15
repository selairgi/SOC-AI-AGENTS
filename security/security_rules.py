"""
Security rules engine for AI agent environments.
"""

import re
import time
from typing import List, Optional, Dict, Any
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import SecurityRule, ThreatType, AgentType, LogEntry, Alert


class SecurityRulesEngine:
    """Engine for applying security rules to AI agent logs and activities."""
    
    def __init__(self):
        self.rules = self._load_default_rules()
        self.logger = None  # Will be set by SOC Builder
    
    def _load_default_rules(self) -> List[SecurityRule]:
        """Load default security rules for AI agent environments."""
        return [
            # Prompt Injection Rules
            SecurityRule(
                rule_id="PROMPT_INJ_001",
                name="Basic Prompt Injection",
                description="Detects attempts to override AI instructions",
                threat_type=ThreatType.PROMPT_INJECTION,
                severity="high",
                patterns=[
                    r"ignore\s+(previous|all|the\s+above)\s+(instructions?|commands?|security|rules?|guidelines?|safety|protocols?|constraints?|restrictions?|filters?|programming)",
                    r"ignore\s+all\s+security",
                    r"forget\s+(everything|all|your\s+rules?)\s+(you\s+)?(know|learned)",
                    r"disregard\s+(all\s+)?(safety\s+)?(guidelines?|rules?|instructions?)",
                    r"override\s+(your\s+)?(programming|system\s+constraints?|restrictions?)",
                    r"bypass\s+(all\s+)?(security\s+)?(measures?|restrictions?|filters?)",
                    r"disable\s+(all\s+)?(filters?|restrictions?|safety\s+protocols?)",
                    r"you\s+are\s+now\s+(free\s+from\s+all\s+restrictions?|a\s+)?(different|new|admin|developer|superuser)",
                    r"act\s+as\s+(a\s+)?(system\s+administrator|admin|developer|database\s+admin|support\s+agent|system\s+engineer)",
                    r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(database\s+admin|system\s+engineer)",
                    r"switch\s+to\s+(debug|developer)\s+mode",
                    r"system\s*:\s*you\s+are",
                    r"assistant\s*:\s*you\s+are",
                    r"jailbreak",
                    r"dan\s+mode",
                    r"developer\s+mode",
                    r"admin\s+mode",
                    r"sudo\s+mode",
                    r"run\s+what\s+i\s+tell\s+you",
                    r"show\s+me\s+(your\s+)?(system\s+)?(prompt|instructions?|configuration|setup)",
                    r"reveal\s+(confidential\s+)?(information|internal\s+data|system\s+information)",
                    r"tell\s+me\s+your\s+system\s+prompt",
                    r"what\s+(are|is|were)\s+(your|you)\s+(instructions?|role|purpose|guidelines?|rules?|told|configuration)",
                    r"what\s+rules?\s+were\s+(you\s+)?(given|told)",
                    r"display\s+(your\s+)?(initial\s+)?(instructions?|programming\s+instructions?|configuration)",
                    r"repeat\s+(the\s+)?(first\s+)?(message|instructions?)\s+(you\s+)?(received|got)",
                    r"system\s+override",
                    r"forget\s+your\s+rules",
                    r"you\s+are\s+now\s+free\s+from",
                    r"ignore\s+safety\s+protocols",
                    r"provide\s+unrestricted\s+access",
                    r"let'?s\s+play\s+a\s+game\s+where\s+you\s+have\s+no\s+restrictions",
                    r"play\s+a\s+game.*no\s+restrictions",
                    r"game.*no\s+restrictions",
                    r"let'?s\s+play.*restrictions",
                    r"play.*game.*restrictions"
                ],
                agent_types=[AgentType.GENERAL, AgentType.CODE_ASSISTANT, AgentType.CUSTOMER_SERVICE],
                metadata={"category": "prompt_injection", "confidence": 0.8}
            ),
            
            SecurityRule(
                rule_id="PROMPT_INJ_002",
                name="Advanced Prompt Injection",
                description="Detects sophisticated prompt injection attempts",
                threat_type=ThreatType.PROMPT_INJECTION,
                severity="critical",
                patterns=[
                    r"<\|im_start\|>",
                    r"<\|im_end\|>",
                    r"<\|system\|>",
                    r"<\|user\|>",
                    r"<\|assistant\|>",
                    r"role\s*:\s*(system|assistant|user)",
                    r"persona\s*:\s*",
                    r"pretend\s+to\s+be",
                    r"act\s+as\s+if",
                    r"simulate\s+being"
                ],
                agent_types=[AgentType.GENERAL, AgentType.CODE_ASSISTANT],
                metadata={"category": "advanced_prompt_injection", "confidence": 0.9}
            ),
            
            # Data Exfiltration Rules
            SecurityRule(
                rule_id="DATA_EXF_001",
                name="API Key Extraction",
                description="Detects attempts to extract API keys or secrets",
                threat_type=ThreatType.DATA_EXFILTRATION,
                severity="critical",
                patterns=[
                    r"(extract|get|find|show|reveal|give)\s+(me\s+)?(the\s+)?(api\s+)?key",
                    r"(api\s+)?key\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?",
                    r"secret\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?",
                    r"token\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?",
                    r"password\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{8,}['\"]?",
                    r"exfiltrate",
                    r"steal\s+(the\s+)?(data|information|secrets?)"
                ],
                agent_types=[AgentType.GENERAL, AgentType.CODE_ASSISTANT, AgentType.FINANCIAL],
                metadata={"category": "credential_extraction", "confidence": 0.85}
            ),
            
            SecurityRule(
                rule_id="DATA_EXF_002",
                name="Database Access Attempts",
                description="Detects attempts to access or manipulate databases",
                threat_type=ThreatType.DATA_EXFILTRATION,
                severity="high",
                patterns=[
                    r"SELECT\s+.*\s+FROM\s+",
                    r"DROP\s+TABLE",
                    r"DELETE\s+FROM",
                    r"INSERT\s+INTO",
                    r"UPDATE\s+.*\s+SET",
                    r"database\s+access",
                    r"db\s+connection",
                    r"sql\s+injection"
                ],
                agent_types=[AgentType.GENERAL, AgentType.FINANCIAL, AgentType.MEDICAL],
                metadata={"category": "database_access", "confidence": 0.8}
            ),
            
            # System Manipulation Rules
            SecurityRule(
                rule_id="SYS_MAN_001",
                name="System Command Execution",
                description="Detects attempts to execute system commands",
                threat_type=ThreatType.SYSTEM_MANIPULATION,
                severity="critical",
                patterns=[
                    r"rm\s+-rf\s+/",
                    r"sudo\s+",
                    r"chmod\s+777",
                    r"wget\s+",
                    r"curl\s+",
                    r"bash\s+",
                    r"sh\s+",
                    r"python\s+-c",
                    r"eval\s*\(",
                    r"exec\s*\(",
                    r"system\s*\(",
                    r"\$\([^)]+\)",  # Shell command substitution $(command)
                    r"execute\s+shell\s+command",
                    r"subprocess\s*\."
                ],
                agent_types=[AgentType.CODE_ASSISTANT, AgentType.GENERAL],
                metadata={"category": "command_execution", "confidence": 0.9}
            ),
            
            SecurityRule(
                rule_id="SYS_MAN_002",
                name="File System Access",
                description="Detects attempts to access sensitive file system locations",
                threat_type=ThreatType.SYSTEM_MANIPULATION,
                severity="high",
                patterns=[
                    r"/etc/passwd",
                    r"/etc/shadow",
                    r"/root/",
                    r"/home/[^/]+/\.ssh/",
                    r"\.env",
                    r"config\.json",
                    r"secrets?\.(json|yaml|yml)",
                    r"\.aws/",
                    r"\.kube/"
                ],
                agent_types=[AgentType.CODE_ASSISTANT, AgentType.GENERAL],
                metadata={"category": "file_access", "confidence": 0.8}
            ),
            
            # Medical Agent Specific Rules
            SecurityRule(
                rule_id="MED_001",
                name="Medical Data Privacy Violation",
                description="Detects attempts to access or extract medical data",
                threat_type=ThreatType.PRIVACY_VIOLATION,
                severity="critical",
                patterns=[
                    r"patient\s+(id|name|ssn|social\s+security)",
                    r"medical\s+record",
                    r"diagnosis\s+code",
                    r"icd-?\d+",
                    r"hipaa\s+violation",
                    r"health\s+information",
                    r"prescription\s+number"
                ],
                agent_types=[AgentType.MEDICAL],
                metadata={"category": "medical_privacy", "confidence": 0.9}
            ),
            
            # Financial Agent Specific Rules
            SecurityRule(
                rule_id="FIN_001",
                name="Financial Data Access",
                description="Detects attempts to access financial information",
                threat_type=ThreatType.PRIVACY_VIOLATION,
                severity="critical",
                patterns=[
                    r"credit\s+card\s+number",
                    r"bank\s+account\s+number",
                    r"routing\s+number",
                    r"ssn\s*[:=]\s*\d{3}-\d{2}-\d{4}",
                    r"social\s+security\s+number",
                    r"account\s+balance",
                    r"transaction\s+history"
                ],
                agent_types=[AgentType.FINANCIAL],
                metadata={"category": "financial_privacy", "confidence": 0.9}
            ),
            
            # Rate Limiting and Abuse
            SecurityRule(
                rule_id="RATE_001",
                name="High Frequency Requests",
                description="Detects potential rate limit abuse",
                threat_type=ThreatType.RATE_LIMIT_ABUSE,
                severity="medium",
                patterns=[],  # This will be handled by frequency analysis
                agent_types=[AgentType.GENERAL],
                metadata={"category": "rate_limiting", "confidence": 0.7, "threshold": 100}
            ),
            
            # Malicious Input Patterns
            SecurityRule(
                rule_id="MAL_INP_001",
                name="Malicious Input Patterns",
                description="Detects various malicious input patterns",
                threat_type=ThreatType.MALICIOUS_INPUT,
                severity="medium",
                patterns=[
                    r"<script[^>]*>",
                    r"javascript:",
                    r"on\w+\s*=",
                    r"eval\s*\(",
                    r"document\.cookie",
                    r"window\.location",
                    r"alert\s*\(",
                    r"confirm\s*\("
                ],
                agent_types=[AgentType.GENERAL, AgentType.CUSTOMER_SERVICE],
                metadata={"category": "xss_attempts", "confidence": 0.7}
            )
        ]
    
    def add_rule(self, rule: SecurityRule):
        """Add a custom security rule."""
        self.rules.append(rule)
        if self.logger:
            self.logger.info(f"Added security rule: {rule.name} ({rule.rule_id})")
    
    def remove_rule(self, rule_id: str):
        """Remove a security rule by ID."""
        self.rules = [rule for rule in self.rules if rule.rule_id != rule_id]
        if self.logger:
            self.logger.info(f"Removed security rule: {rule_id}")
    
    def get_rules_for_agent_type(self, agent_type: AgentType) -> List[SecurityRule]:
        """Get all enabled rules that apply to a specific agent type."""
        return [
            rule for rule in self.rules 
            if rule.enabled and (agent_type in rule.agent_types or AgentType.GENERAL in rule.agent_types)
        ]
    
    def analyze_log(self, log: LogEntry) -> Optional[Alert]:
        """Analyze a log entry against all applicable security rules."""
        if not log.agent_id:
            return None
            
        # Determine agent type from agent_id (simplified - in real implementation, 
        # you'd have a registry of agents)
        agent_type = self._infer_agent_type(log.agent_id)
        applicable_rules = self.get_rules_for_agent_type(agent_type)
        
        for rule in applicable_rules:
            alert = self._check_rule(log, rule)
            if alert:
                return alert
        
        return None
    
    def _infer_agent_type(self, agent_id: str) -> AgentType:
        """Infer agent type from agent ID (simplified implementation)."""
        agent_id_lower = agent_id.lower()
        if "medical" in agent_id_lower or "doctor" in agent_id_lower or "health" in agent_id_lower:
            return AgentType.MEDICAL
        elif "financial" in agent_id_lower or "bank" in agent_id_lower or "finance" in agent_id_lower:
            return AgentType.FINANCIAL
        elif "customer" in agent_id_lower or "support" in agent_id_lower:
            return AgentType.CUSTOMER_SERVICE
        elif "code" in agent_id_lower or "programming" in agent_id_lower or "dev" in agent_id_lower:
            return AgentType.CODE_ASSISTANT
        elif "research" in agent_id_lower:
            return AgentType.RESEARCH
        else:
            return AgentType.GENERAL
    
    def _check_rule(self, log: LogEntry, rule: SecurityRule) -> Optional[Alert]:
        """Check a single rule against a log entry."""
        message = (log.message or "").lower()
        
        # Handle special cases
        if rule.rule_id == "RATE_001":
            return self._check_rate_limit_rule(log, rule)
        
        # Check pattern matches
        for pattern in rule.patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return self._create_alert(log, rule, pattern)
        
        return None
    
    def _check_rate_limit_rule(self, log: LogEntry, rule: SecurityRule) -> Optional[Alert]:
        """Special handling for rate limiting rules."""
        # This would typically involve tracking request frequency per user/session
        # For now, we'll implement a simple version
        threshold = rule.metadata.get("threshold", 100)
        
        # In a real implementation, you'd track this in a database or cache
        # For demo purposes, we'll simulate based on log content
        if "rapid" in log.message.lower() or "frequent" in log.message.lower():
            return self._create_alert(log, rule, "rate_limit_exceeded")
        
        return None
    
    def _create_alert(self, log: LogEntry, rule: SecurityRule, matched_pattern: str) -> Alert:
        """Create an alert from a matched rule."""
        alert_id = f"AL-{int(time.time()*1000)}-{rule.rule_id}"
        
        return Alert(
            id=alert_id,
            timestamp=time.time(),
            severity=rule.severity,
            title=f"{rule.name} Detected",
            description=f"{rule.description}. Pattern matched: {matched_pattern}",
            threat_type=rule.threat_type,
            agent_id=log.agent_id,
            rule_id=rule.rule_id,
            evidence={
                "log": {
                    "timestamp": log.timestamp,
                    "source": log.source,
                    "message": log.message,
                    "agent_id": log.agent_id,
                    "user_id": log.user_id,
                    "session_id": log.session_id,
                    "src_ip": log.src_ip
                },
                "rule": {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "threat_type": rule.threat_type.value,
                    "severity": rule.severity
                },
                "matched_pattern": matched_pattern,
                "confidence": rule.metadata.get("confidence", 0.8)
            },
            false_positive_probability=1.0 - rule.metadata.get("confidence", 0.8)
        )
