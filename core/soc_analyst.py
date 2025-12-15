"""
SOC Analyst agent - analyzes alerts and creates remediation playbooks.
"""

import asyncio
import logging
import time
from typing import Optional, Dict, Any, List

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import Alert, Playbook, ThreatType, AgentType
from shared.message_bus import MessageBus
from shared.schema_validator import SchemaValidator
from shared.config import ENABLE_SCHEMA_VALIDATION
from shared.agent_memory import AgentMemory
from security.false_positive_detector import FalsePositiveDetector
from security.intelligent_remediation_planner import IntelligentRemediationPlanner
from ai.real_ai_integration import RealAIIntegration


class SOCAnalyst:
    """Analyzes security alerts and creates remediation playbooks.
    
    This agent receives alerts from the message bus, performs analysis to determine
    the appropriate response, and creates playbooks that are sent to the remediator.
    """
    
    def __init__(self, bus: MessageBus, remediator_queue: asyncio.Queue, memory: Optional[AgentMemory] = None):
        self.bus = bus
        self.remediator_queue = remediator_queue
        self._stopped = False
        self.logger = logging.getLogger("SOCAnalyst")
        self.alert_count = 0
        self.playbook_count = 0
        self.schema_validator = SchemaValidator() if ENABLE_SCHEMA_VALIDATION else None
        
        # Initialize memory system
        self.memory = memory or AgentMemory()
        
        # Initialize false positive detector
        self.fp_detector = FalsePositiveDetector()
        
        # Initialize intelligent remediation planner
        ai_integration = RealAIIntegration()
        self.remediation_planner = IntelligentRemediationPlanner(ai_integration)
        
        # Statistics
        self.stats = {
            "alerts_analyzed": 0,
            "alerts_classified": 0,
            "false_positives_identified": 0,
            "true_positives_identified": 0,
            "average_certainty": 0.0,
            "playbooks_created": 0
        }

    def analyze_alert(self, alert: Alert) -> Optional[Playbook]:
        """Analyze an alert and determine appropriate remediation action with certainty scoring.
        
        Args:
            alert: The security alert to analyze
            
        Returns:
            Playbook with remediation action, or None if no action needed
        """
        self.alert_count += 1
        self.stats["alerts_analyzed"] += 1
        self.logger.info(f"Analyzing alert {alert.id}: {alert.title} (severity: {alert.severity}, threat: {alert.threat_type.value})")
        
        # Extract information from evidence
        src_ip = None
        user_id = None
        agent_id = alert.agent_id
        log_entry = None
        
        if alert.evidence and "log" in alert.evidence:
            log_data = alert.evidence["log"]
            src_ip = log_data.get("src_ip")
            user_id = log_data.get("user_id")
            
            # Create LogEntry for false positive detection
            from shared.models import LogEntry
            log_entry = LogEntry(
                timestamp=log_data.get("timestamp", time.time()),
                source=log_data.get("source", "unknown"),
                message=log_data.get("message", ""),
                agent_id=log_data.get("agent_id", agent_id),
                user_id=user_id,
                session_id=log_data.get("session_id", ""),
                src_ip=src_ip,
                request_id=log_data.get("request_id", ""),
                response_time=log_data.get("response_time", 0.0),
                status_code=log_data.get("status_code", 200)
            )
        
        # Perform false positive analysis with certainty scoring
        certainty_score = 0.0
        false_positive_probability = 0.0
        reasoning = []
        decision = "alert"  # Default: treat as alert
        
        if log_entry:
            fp_score = self.fp_detector.analyze_alert(
                alert,
                log_entry,
                user_context={"session_id": log_entry.session_id, "src_ip": src_ip}
            )
            
            false_positive_probability = fp_score.false_positive_probability
            reasoning = fp_score.reasoning
            
            # Calculate certainty score (inverse of false positive probability)
            # Higher certainty = more confident it's a real threat
            certainty_score = 1.0 - false_positive_probability
            
            # Determine decision based on certainty and severity
            if false_positive_probability > 0.7:
                decision = "false_positive"
                self.stats["false_positives_identified"] += 1
                self.logger.info(f"Alert {alert.id} classified as FALSE POSITIVE (certainty: {certainty_score:.2f})")
            elif certainty_score > 0.7:
                decision = "alert"
                self.stats["true_positives_identified"] += 1
                self.logger.info(f"Alert {alert.id} classified as REAL THREAT (certainty: {certainty_score:.2f})")
            else:
                decision = "investigate"
                self.logger.info(f"Alert {alert.id} requires INVESTIGATION (certainty: {certainty_score:.2f})")
        
        # Store decision in memory
        decision_id = self.memory.store_alert_decision(
            alert_id=alert.id,
            certainty_score=certainty_score,
            false_positive_probability=false_positive_probability,
            decision=decision,
            reasoning=reasoning,
            metadata={
                "severity": alert.severity,
                "threat_type": alert.threat_type.value if alert.threat_type else "unknown",
                "rule_id": alert.rule_id,
                "agent_id": agent_id
            }
        )
        
        self.stats["alerts_classified"] += 1
        # Update average certainty
        total = self.stats["alerts_classified"]
        self.stats["average_certainty"] = (
            (self.stats["average_certainty"] * (total - 1) + certainty_score) / total
        )
        
        # If classified as false positive, return None (no action)
        if decision == "false_positive":
            return None
            
        # --- Use Intelligent Remediation Planner ---
        plan = self.remediation_planner.create_remediation_plan(alert, certainty_score)
        
        if not plan:
            self.logger.info(f"Planner decided no action needed for alert {alert.id}")
            return None
            
        # Create Playbook from Plan
        playbook = Playbook(
            action=plan.action,
            target=plan.target,
            justification=plan.justification,
            owner="soc_analyst",
            threat_type=alert.threat_type,
            agent_id=agent_id,
            metadata={
                "alert_id": alert.id,
                "threat_type": alert.threat_type.value if alert.threat_type else "unknown",
                "severity": alert.severity,
                "analysis_timestamp": time.time(),
                "auto_generated": True,
                "confidence": certainty_score,
                "certainty_score": certainty_score,
                "is_lab_context": plan.metadata.get("is_lab_context", False),
                "actions": plan.actions # Structured actions for remediator
            }
        )
        return playbook

    # Legacy handler methods removed/deprecated as they are replaced by the intelligent planner
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
            self.logger.info(f"Statistics: {self.stats}")

    def stop(self):
        """Stop the SOC Analyst."""
        self._stopped = True
        self.logger.info("SOC Analyst stop requested")
