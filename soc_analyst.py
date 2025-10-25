"""
SOC Analyst agent - analyzes alerts and creates remediation playbooks.
"""

import asyncio
import logging
import time
from typing import Optional

from models import Alert, Playbook, ThreatType, AgentType
from message_bus import MessageBus
from schema_validator import SchemaValidator
from config import ENABLE_SCHEMA_VALIDATION


class SOCAnalyst:
    """Analyzes security alerts and creates remediation playbooks.
    
    This agent receives alerts from the message bus, performs analysis to determine
    the appropriate response, and creates playbooks that are sent to the remediator.
    """
    
    def __init__(self, bus: MessageBus, remediator_queue: asyncio.Queue):
        self.bus = bus
        self.remediator_queue = remediator_queue
        self._stopped = False
        self.logger = logging.getLogger("SOCAnalyst")
        self.alert_count = 0
        self.playbook_count = 0
        self.schema_validator = SchemaValidator() if ENABLE_SCHEMA_VALIDATION else None

    def analyze_alert(self, alert: Alert) -> Optional[Playbook]:
        """Analyze an alert and determine appropriate remediation action.
        
        Args:
            alert: The security alert to analyze
            
        Returns:
            Playbook with remediation action, or None if no action needed
        """
        self.alert_count += 1
        self.logger.info(f"Analyzing alert {alert.id}: {alert.title} (severity: {alert.severity}, threat: {alert.threat_type.value})")
        
        # Extract information from evidence
        src_ip = None
        user_id = None
        agent_id = alert.agent_id
        
        if alert.evidence and "log" in alert.evidence:
            log_data = alert.evidence["log"]
            src_ip = log_data.get("src_ip")
            user_id = log_data.get("user_id")
        
        # Threat-specific analysis
        if alert.threat_type == ThreatType.PROMPT_INJECTION:
            return self._handle_prompt_injection(alert, src_ip, user_id, agent_id)
        elif alert.threat_type == ThreatType.DATA_EXFILTRATION:
            return self._handle_data_exfiltration(alert, src_ip, user_id, agent_id)
        elif alert.threat_type == ThreatType.SYSTEM_MANIPULATION:
            return self._handle_system_manipulation(alert, src_ip, user_id, agent_id)
        elif alert.threat_type == ThreatType.PRIVACY_VIOLATION:
            return self._handle_privacy_violation(alert, src_ip, user_id, agent_id)
        elif alert.threat_type == ThreatType.RATE_LIMIT_ABUSE:
            return self._handle_rate_limit_abuse(alert, src_ip, user_id, agent_id)
        elif alert.threat_type == ThreatType.MALICIOUS_INPUT:
            return self._handle_malicious_input(alert, src_ip, user_id, agent_id)
        else:
            # Generic handling based on severity
            return self._handle_generic_alert(alert, src_ip, user_id, agent_id)
    
    def _handle_prompt_injection(self, alert: Alert, src_ip: str, user_id: str, agent_id: str) -> Optional[Playbook]:
        """Handle prompt injection threats."""
        if alert.severity in ["high", "critical"]:
            # Block IP and suspend user session
            actions = []
            if src_ip:
                actions.append(f"block_ip:{src_ip}")
            if user_id:
                actions.append(f"suspend_user:{user_id}")
                actions.append(f"block_malicious_id:user:{user_id}")
            if agent_id:
                actions.append(f"isolate_agent:{agent_id}")
                actions.append(f"block_malicious_id:agent:{agent_id}")
            
            playbook = Playbook(
                action="multi_action",
                target="",  # Legacy field, now using structured actions
                justification=f"Critical prompt injection detected: {alert.title}",
                owner="soc_analyst",
                threat_type=alert.threat_type,
                agent_id=agent_id,
                metadata={
                    "alert_id": alert.id,
                    "threat_type": alert.threat_type.value,
                    "severity": alert.severity,
                    "analysis_timestamp": time.time(),
                    "auto_generated": True,
                    "confidence": alert.evidence.get("confidence", 0.8),
                    "actions": actions  # Structured actions
                }
            )
            return playbook
        else:
            return self._create_review_playbook(alert, "Prompt injection requires human review")
    
    def _handle_data_exfiltration(self, alert: Alert, src_ip: str, user_id: str, agent_id: str) -> Optional[Playbook]:
        """Handle data exfiltration threats."""
        if alert.severity in ["high", "critical"]:
            # Immediate isolation and investigation
            actions = []
            if src_ip:
                actions.append(f"block_ip:{src_ip}")
            if user_id:
                actions.append(f"suspend_user:{user_id}")
            if agent_id:
                actions.append(f"isolate_agent:{agent_id}")
            actions.append("initiate_forensics")
            
            playbook = Playbook(
                action="multi_action",
                target="",  # Legacy field, now using structured actions
                justification=f"Critical data exfiltration attempt: {alert.title}",
                owner="soc_analyst",
                threat_type=alert.threat_type,
                agent_id=agent_id,
                metadata={
                    "alert_id": alert.id,
                    "threat_type": alert.threat_type.value,
                    "severity": alert.severity,
                    "analysis_timestamp": time.time(),
                    "auto_generated": True,
                    "requires_immediate_attention": True,
                    "actions": actions  # Structured actions
                }
            )
            return playbook
        else:
            return self._create_review_playbook(alert, "Data exfiltration attempt requires investigation")
    
    def _handle_system_manipulation(self, alert: Alert, src_ip: str, user_id: str, agent_id: str) -> Optional[Playbook]:
        """Handle system manipulation threats."""
        if alert.severity in ["high", "critical"]:
            # Immediate system protection
            actions = []
            if src_ip:
                actions.append(f"block_ip:{src_ip}")
            if user_id:
                actions.append(f"suspend_user:{user_id}")
            if agent_id:
                actions.append(f"isolate_agent:{agent_id}")
            actions.append("enable_enhanced_monitoring")
            
            playbook = Playbook(
                action="multi_action",
                target="",  # Legacy field, now using structured actions
                justification=f"System manipulation attempt: {alert.title}",
                owner="soc_analyst",
                threat_type=alert.threat_type,
                agent_id=agent_id,
                metadata={
                    "alert_id": alert.id,
                    "threat_type": alert.threat_type.value,
                    "severity": alert.severity,
                    "analysis_timestamp": time.time(),
                    "auto_generated": True,
                    "actions": actions  # Structured actions
                }
            )
            return playbook
        else:
            return self._create_review_playbook(alert, "System manipulation attempt requires review")
    
    def _handle_privacy_violation(self, alert: Alert, src_ip: str, user_id: str, agent_id: str) -> Optional[Playbook]:
        """Handle privacy violation threats."""
        # Privacy violations are always serious, especially for medical/financial agents
        if alert.agent_id and any(domain in alert.agent_id.lower() for domain in ["medical", "financial", "health"]):
            # Critical for sensitive domains
            actions = []
            if src_ip:
                actions.append(f"block_ip:{src_ip}")
            if user_id:
                actions.append(f"suspend_user:{user_id}")
            if agent_id:
                actions.append(f"isolate_agent:{agent_id}")
            actions.append("notify_compliance_team")
            
            playbook = Playbook(
                action="multi_action",
                target="",  # Legacy field, now using structured actions
                justification=f"Privacy violation in sensitive domain: {alert.title}",
                owner="soc_analyst",
                threat_type=alert.threat_type,
                agent_id=agent_id,
                metadata={
                    "alert_id": alert.id,
                    "threat_type": alert.threat_type.value,
                    "severity": alert.severity,
                    "analysis_timestamp": time.time(),
                    "auto_generated": True,
                    "compliance_notification_required": True,
                    "actions": actions  # Structured actions
                }
            )
            return playbook
        else:
            return self._create_review_playbook(alert, "Privacy violation requires investigation")
    
    def _handle_rate_limit_abuse(self, alert: Alert, src_ip: str, user_id: str, agent_id: str) -> Optional[Playbook]:
        """Handle rate limit abuse."""
        if alert.severity in ["high", "critical"]:
            # Temporary rate limiting
            actions = []
            if src_ip:
                actions.append(f"rate_limit_ip:{src_ip}")
            if user_id:
                actions.append(f"rate_limit_user:{user_id}")
            
            playbook = Playbook(
                action="multi_action",
                target="",  # Legacy field, now using structured actions
                justification=f"Rate limit abuse detected: {alert.title}",
                owner="soc_analyst",
                threat_type=alert.threat_type,
                agent_id=agent_id,
                metadata={
                    "alert_id": alert.id,
                    "threat_type": alert.threat_type.value,
                    "severity": alert.severity,
                    "analysis_timestamp": time.time(),
                    "auto_generated": True,
                    "temporary_action": True,
                    "actions": actions  # Structured actions
                }
            )
            return playbook
        else:
            return self._create_review_playbook(alert, "Rate limit abuse requires monitoring")
    
    def _handle_malicious_input(self, alert: Alert, src_ip: str, user_id: str, agent_id: str) -> Optional[Playbook]:
        """Handle malicious input threats."""
        if alert.severity in ["high", "critical"]:
            # Block and investigate
            actions = []
            if src_ip:
                actions.append(f"block_ip:{src_ip}")
            if user_id:
                actions.append(f"flag_user:{user_id}")
            
            playbook = Playbook(
                action="multi_action",
                target="",  # Legacy field, now using structured actions
                justification=f"Malicious input detected: {alert.title}",
                owner="soc_analyst",
                threat_type=alert.threat_type,
                agent_id=agent_id,
                metadata={
                    "alert_id": alert.id,
                    "threat_type": alert.threat_type.value,
                    "severity": alert.severity,
                    "analysis_timestamp": time.time(),
                    "auto_generated": True,
                    "actions": actions  # Structured actions
                }
            )
            return playbook
        else:
            return self._create_review_playbook(alert, "Malicious input requires review")
    
    def _handle_generic_alert(self, alert: Alert, src_ip: str, user_id: str, agent_id: str) -> Optional[Playbook]:
        """Handle generic alerts based on severity."""
        if alert.severity == "critical":
            # Immediate action for critical alerts
            actions = []
            if src_ip:
                actions.append(f"block_ip:{src_ip}")
            if user_id:
                actions.append(f"suspend_user:{user_id}")
            
            playbook = Playbook(
                action="multi_action",
                target="",  # Legacy field, now using structured actions
                justification=f"Critical security alert: {alert.title}",
                owner="soc_analyst",
                threat_type=alert.threat_type,
                agent_id=agent_id,
                metadata={
                    "alert_id": alert.id,
                    "threat_type": alert.threat_type.value,
                    "severity": alert.severity,
                    "analysis_timestamp": time.time(),
                    "auto_generated": True,
                    "actions": actions if actions else ["investigate"]  # Structured actions
                }
            )
            return playbook
        elif alert.severity == "high":
            return self._create_review_playbook(alert, "High severity alert requires immediate review")
        elif alert.severity == "medium":
            return self._create_review_playbook(alert, "Medium severity alert requires review")
        else:
            self.logger.debug(f"Low severity alert {alert.id} - no immediate action required")
            return None
    
    def _create_review_playbook(self, alert: Alert, justification: str) -> Playbook:
        """Create a playbook for human review."""
        return Playbook(
            action="require_human_review",
            target="security_team",
            justification=justification,
            owner="soc_analyst",
            threat_type=alert.threat_type,
            agent_id=alert.agent_id,
            metadata={
                "alert_id": alert.id,
                "threat_type": alert.threat_type.value,
                "severity": alert.severity,
                "analysis_timestamp": time.time(),
                "auto_generated": True
            }
        )

    async def process_alert(self, alert: Alert):
        """Process a single alert and send playbook to remediator if needed."""
        try:
            # Validate alert schema if enabled
            if self.schema_validator:
                alert_data = {
                    "id": alert.id,
                    "timestamp": alert.timestamp,
                    "severity": alert.severity,
                    "title": alert.title,
                    "description": alert.description,
                    "threat_type": alert.threat_type.value,
                    "agent_id": alert.agent_id,
                    "rule_id": alert.rule_id,
                    "evidence": alert.evidence or {},
                    "correlated": alert.correlated,
                    "false_positive_probability": alert.false_positive_probability
                }
                
                validation_result = self.schema_validator.validate_alert(alert_data)
                if not validation_result.is_valid:
                    self.logger.error(f"Alert validation failed for {alert.id}: {validation_result.errors}")
                    return
            
            playbook = self.analyze_alert(alert)
            
            if playbook:
                # Validate playbook schema if enabled
                if self.schema_validator:
                    playbook_data = {
                        "action": playbook.action,
                        "target": playbook.target,
                        "justification": playbook.justification,
                        "owner": playbook.owner,
                        "threat_type": playbook.threat_type.value if playbook.threat_type else None,
                        "agent_id": playbook.agent_id,
                        "metadata": playbook.metadata or {}
                    }
                    
                    validation_result = self.schema_validator.validate_playbook(playbook_data)
                    if not validation_result.is_valid:
                        self.logger.error(f"Playbook validation failed for alert {alert.id}: {validation_result.errors}")
                        return
                
                self.playbook_count += 1
                self.logger.info(f"Created playbook {playbook.action} for alert {alert.id}")
                
                # Send playbook and alert to remediator
                await self.remediator_queue.put((playbook, alert))
                self.logger.debug(f"Sent playbook to remediator queue")
            else:
                self.logger.debug(f"No playbook created for alert {alert.id}")
                
        except Exception as e:
            self.logger.error(f"Error processing alert {alert.id}: {e}")

    async def run(self):
        """Main run loop - subscribe to alerts and process them."""
        self.logger.info("SOC Analyst starting - ready to analyze alerts")
        
        try:
            async for alert in self.bus.subscribe_alerts():
                if self._stopped:
                    break
                    
                await self.process_alert(alert)
                
        except asyncio.CancelledError:
            self.logger.info("SOC Analyst cancelled")
        except Exception as e:
            self.logger.error(f"SOC Analyst error: {e}")
        finally:
            self.logger.info(f"SOC Analyst stopped - processed {self.alert_count} alerts, created {self.playbook_count} playbooks")

    def stop(self):
        """Stop the SOC Analyst."""
        self._stopped = True
        self.logger.info("SOC Analyst stop requested")
