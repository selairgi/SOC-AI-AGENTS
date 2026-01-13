"""
Risk Assessment Agent.

This agent subscribes to AnalysisCompleted and ContextEnriched events,
computes risk scores, and publishes RiskAssessment events.

Usage:
    from soc_core.events import EventBus
    from soc_core.agents import RiskAgent

    bus = EventBus()
    risk_agent = RiskAgent(bus)
    risk_agent.start()

    # Risk assessments will be published for incoming events
    bus.subscribe("RiskAssessment", my_handler)
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class RiskFactors:
    """Collected factors for risk calculation."""
    threat_type: Optional[str] = None
    alert_severity: Optional[str] = None
    confidence: float = 0.0
    similar_alert_count: int = 1
    is_escalating: bool = False
    affected_agents: int = 0
    affected_users: int = 0
    affected_ips: int = 0
    verdict: Optional[str] = None
    max_severity: Optional[str] = None


class RiskAgent:
    """
    Risk assessment agent that evaluates threats and computes risk scores.

    This agent:
    - Subscribes to AnalysisCompleted and ContextEnriched events
    - Computes technical_severity, business_impact, and blast_radius
    - Publishes RiskAssessment events with overall risk level

    The agent can process either event type independently.
    """

    # Event type constants
    EVENT_ANALYSIS_COMPLETED = "AnalysisCompleted"
    EVENT_CONTEXT_ENRICHED = "ContextEnriched"
    EVENT_RISK_ASSESSMENT = "RiskAssessment"

    # Severity mappings
    SEVERITY_VALUES = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    # Threat type risk weights
    THREAT_RISK_WEIGHTS = {
        "prompt_injection": 3,
        "data_exfiltration": 4,
        "unauthorized_access": 4,
        "malicious_input": 3,
        "system_manipulation": 4,
        "privacy_violation": 3,
        "rate_limit_abuse": 1,
        "model_poisoning": 4,
    }

    # Business-critical agent types
    CRITICAL_AGENT_TYPES = {"medical", "financial", "infrastructure"}

    def __init__(
        self,
        event_bus,
        logger: logging.Logger = None
    ):
        """
        Initialize the risk agent.

        Args:
            event_bus: The EventBus instance to use for pub/sub
            logger: Optional logger instance
        """
        self.bus = event_bus
        self.logger = logger or logging.getLogger("RiskAgent")

        self._running = False
        self._subscribed_analysis = False
        self._subscribed_context = False

        # Statistics
        self.stats = {
            "analysis_events_received": 0,
            "context_events_received": 0,
            "assessments_published": 0,
            "risk_levels": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "start_time": None,
            "stop_time": None
        }

    def start(self) -> None:
        """
        Start the risk agent.

        Subscribes to AnalysisCompleted and ContextEnriched events.
        """
        if self._running:
            self.logger.warning("RiskAgent is already running")
            return

        self.bus.subscribe(self.EVENT_ANALYSIS_COMPLETED, self._handle_analysis_completed)
        self._subscribed_analysis = True

        self.bus.subscribe(self.EVENT_CONTEXT_ENRICHED, self._handle_context_enriched)
        self._subscribed_context = True

        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.stats["stop_time"] = None

        self.logger.info("RiskAgent started")

    def stop(self) -> None:
        """
        Stop the risk agent.

        Unsubscribes from all events.
        """
        if not self._running:
            self.logger.warning("RiskAgent is not running")
            return

        if self._subscribed_analysis:
            self.bus.unsubscribe(self.EVENT_ANALYSIS_COMPLETED, self._handle_analysis_completed)
            self._subscribed_analysis = False

        if self._subscribed_context:
            self.bus.unsubscribe(self.EVENT_CONTEXT_ENRICHED, self._handle_context_enriched)
            self._subscribed_context = False

        self._running = False
        self.stats["stop_time"] = datetime.now(timezone.utc).isoformat()

        self.logger.info("RiskAgent stopped")
        self._log_statistics()

    def is_running(self) -> bool:
        """Check if the agent is currently running."""
        return self._running

    def _handle_analysis_completed(self, event: dict) -> None:
        """Handle incoming AnalysisCompleted event."""
        self.stats["analysis_events_received"] += 1

        try:
            factors = self._extract_factors_from_analysis(event)
            self._publish_assessment(event, self.EVENT_ANALYSIS_COMPLETED, factors)
        except Exception as e:
            self.logger.error(f"Error processing AnalysisCompleted: {e}")

    def _handle_context_enriched(self, event: dict) -> None:
        """Handle incoming ContextEnriched event."""
        self.stats["context_events_received"] += 1

        try:
            factors = self._extract_factors_from_context(event)
            self._publish_assessment(event, self.EVENT_CONTEXT_ENRICHED, factors)
        except Exception as e:
            self.logger.error(f"Error processing ContextEnriched: {e}")

    def _extract_factors_from_analysis(self, event: dict) -> RiskFactors:
        """Extract risk factors from AnalysisCompleted event."""
        payload = event.get("payload", {})

        return RiskFactors(
            threat_type=payload.get("threat_type"),
            alert_severity=payload.get("severity"),
            confidence=payload.get("certainty_score", 0.0),
            verdict=payload.get("verdict"),
            similar_alert_count=1,
            is_escalating=False,
            affected_agents=1,
            affected_users=1,
            affected_ips=1
        )

    def _extract_factors_from_context(self, event: dict) -> RiskFactors:
        """Extract risk factors from ContextEnriched event."""
        payload = event.get("payload", {})
        context = payload.get("context", {})
        original_alert = payload.get("original_alert", {})
        sources = context.get("sources_involved", {})

        # Get threat types
        threat_types = context.get("threat_types_seen", [])
        primary_threat = threat_types[0] if threat_types else original_alert.get("threat_type")

        return RiskFactors(
            threat_type=primary_threat,
            alert_severity=original_alert.get("severity"),
            confidence=original_alert.get("confidence", 0.0),
            similar_alert_count=context.get("similar_alert_count", 1),
            is_escalating=context.get("is_escalating", False),
            affected_agents=len(sources.get("agent_ids", [])) or 1,
            affected_users=len(sources.get("user_ids", [])) or 1,
            affected_ips=len(sources.get("src_ips", [])) or 1,
            max_severity=context.get("max_severity")
        )

    def _compute_technical_severity(self, factors: RiskFactors) -> str:
        """
        Compute technical severity based on threat characteristics.

        Returns: "low", "medium", or "high"
        """
        score = 0

        # Base score from alert severity
        severity = factors.alert_severity or factors.max_severity or "low"
        severity_val = self.SEVERITY_VALUES.get(severity.lower(), 1)
        score += severity_val * 2

        # Threat type weight
        threat_weight = self.THREAT_RISK_WEIGHTS.get(factors.threat_type, 2)
        score += threat_weight

        # Confidence factor
        if factors.confidence >= 0.8:
            score += 2
        elif factors.confidence >= 0.5:
            score += 1

        # Escalation factor
        if factors.is_escalating:
            score += 2

        # Classify
        if score >= 10:
            return "high"
        elif score >= 6:
            return "medium"
        else:
            return "low"

    def _compute_business_impact(self, factors: RiskFactors) -> str:
        """
        Compute business impact based on threat type and scope.

        Returns: "low", "medium", or "high"
        """
        score = 0

        # High-impact threat types
        high_impact_threats = {
            "data_exfiltration", "unauthorized_access",
            "privacy_violation", "system_manipulation"
        }

        if factors.threat_type in high_impact_threats:
            score += 3

        # Alert count indicates persistent threat
        if factors.similar_alert_count >= 10:
            score += 3
        elif factors.similar_alert_count >= 5:
            score += 2
        elif factors.similar_alert_count >= 2:
            score += 1

        # Escalation is concerning for business
        if factors.is_escalating:
            score += 2

        # Multiple affected users = higher business impact
        if factors.affected_users >= 10:
            score += 3
        elif factors.affected_users >= 3:
            score += 2
        elif factors.affected_users >= 2:
            score += 1

        # Verdict influence
        if factors.verdict == "true_positive":
            score += 2
        elif factors.verdict == "requires_investigation":
            score += 1

        # Classify
        if score >= 8:
            return "high"
        elif score >= 4:
            return "medium"
        else:
            return "low"

    def _compute_blast_radius(self, factors: RiskFactors) -> str:
        """
        Compute blast radius based on scope of affected entities.

        Returns: "single_user", "team", or "org"
        """
        # Check multiple indicators of scope
        total_affected = max(
            factors.affected_users,
            factors.affected_agents,
            factors.affected_ips
        )

        # Escalating incidents tend to spread
        if factors.is_escalating and total_affected >= 2:
            total_affected += 2

        # Multiple alert types suggest broader attack
        if factors.similar_alert_count >= 10:
            return "org"
        elif factors.similar_alert_count >= 5 and total_affected >= 3:
            return "org"

        # Classify by affected count
        if total_affected >= 5:
            return "org"
        elif total_affected >= 2:
            return "team"
        else:
            return "single_user"

    def _compute_overall_risk(
        self,
        technical_severity: str,
        business_impact: str,
        blast_radius: str,
        factors: RiskFactors
    ) -> Tuple[str, float]:
        """
        Compute overall risk level and numeric score.

        Returns: (risk_level, numeric_score)
        """
        # Convert to numeric values
        level_values = {"low": 1, "medium": 2, "high": 3}
        radius_values = {"single_user": 1, "team": 2, "org": 3}

        tech_val = level_values.get(technical_severity, 1)
        biz_val = level_values.get(business_impact, 1)
        radius_val = radius_values.get(blast_radius, 1)

        # Weighted combination
        # Technical severity: 40%, Business impact: 35%, Blast radius: 25%
        raw_score = (tech_val * 0.4 + biz_val * 0.35 + radius_val * 0.25) / 3.0

        # Adjust for escalation and confidence
        if factors.is_escalating:
            raw_score *= 1.2
        if factors.confidence >= 0.9:
            raw_score *= 1.1

        # Normalize to 0-100
        numeric_score = min(100, raw_score * 33.33)

        # Determine level
        if numeric_score >= 75 or (technical_severity == "high" and business_impact == "high"):
            return "critical", numeric_score
        elif numeric_score >= 50 or technical_severity == "high" or business_impact == "high":
            return "high", numeric_score
        elif numeric_score >= 25 or technical_severity == "medium" or business_impact == "medium":
            return "medium", numeric_score
        else:
            return "low", numeric_score

    def _generate_recommendations(
        self,
        overall_risk: str,
        technical_severity: str,
        business_impact: str,
        blast_radius: str,
        factors: RiskFactors
    ) -> List[str]:
        """Generate recommendations based on risk assessment."""
        recommendations = []

        if overall_risk == "critical":
            recommendations.append("Immediate escalation to security team required")
            recommendations.append("Consider isolating affected systems")

        if overall_risk in ("critical", "high"):
            recommendations.append("Initiate incident response procedures")

        if blast_radius == "org":
            recommendations.append("Organization-wide alert may be warranted")

        if factors.is_escalating:
            recommendations.append("Monitor for continued escalation")
            recommendations.append("Increase logging verbosity for affected agents")

        if business_impact == "high":
            recommendations.append("Notify business stakeholders")

        if factors.threat_type == "data_exfiltration":
            recommendations.append("Review data access logs")
            recommendations.append("Check for unauthorized data transfers")

        if factors.threat_type == "prompt_injection":
            recommendations.append("Review agent input validation")
            recommendations.append("Consider rate limiting affected users")

        if not recommendations:
            recommendations.append("Continue monitoring")

        return recommendations

    def _publish_assessment(
        self,
        source_event: dict,
        source_type: str,
        factors: RiskFactors
    ) -> None:
        """Create and publish a RiskAssessment event."""
        # Compute risk scores
        technical_severity = self._compute_technical_severity(factors)
        business_impact = self._compute_business_impact(factors)
        blast_radius = self._compute_blast_radius(factors)
        overall_risk, numeric_score = self._compute_overall_risk(
            technical_severity, business_impact, blast_radius, factors
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            overall_risk, technical_severity, business_impact, blast_radius, factors
        )

        # Build event
        event_id = str(uuid.uuid4())
        correlation_id = source_event.get("correlation_id", str(uuid.uuid4()))
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = source_event.get("payload", {})

        assessment_event = {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "risk_agent",
            "payload": {
                "assessment_id": f"risk-{event_id[:8]}",
                "source_event_type": source_type,
                "source_event_id": source_event.get("event_id"),
                "alert_id": payload.get("alert_id"),
                "incident_id": payload.get("incident_id"),
                "risk_scores": {
                    "technical_severity": technical_severity,
                    "business_impact": business_impact,
                    "blast_radius": blast_radius
                },
                "overall_risk_level": overall_risk,
                "risk_score_numeric": round(numeric_score, 2),
                "factors": {
                    "threat_type": factors.threat_type,
                    "alert_severity": factors.alert_severity,
                    "confidence": factors.confidence,
                    "similar_alert_count": factors.similar_alert_count,
                    "is_escalating": factors.is_escalating,
                    "affected_agents": factors.affected_agents,
                    "affected_users": factors.affected_users,
                    "affected_ips": factors.affected_ips,
                    "verdict": factors.verdict
                },
                "recommendations": recommendations
            }
        }

        self.bus.publish(self.EVENT_RISK_ASSESSMENT, assessment_event)
        self.stats["assessments_published"] += 1
        self.stats["risk_levels"][overall_risk] += 1

        self.logger.debug(
            f"Risk assessment published: {overall_risk} "
            f"(tech={technical_severity}, biz={business_impact}, radius={blast_radius})"
        )

    def _log_statistics(self) -> None:
        """Log agent statistics."""
        self.logger.info("=== RiskAgent Statistics ===")
        self.logger.info(f"AnalysisCompleted received: {self.stats['analysis_events_received']}")
        self.logger.info(f"ContextEnriched received: {self.stats['context_events_received']}")
        self.logger.info(f"Assessments published: {self.stats['assessments_published']}")
        self.logger.info(f"Risk levels: {self.stats['risk_levels']}")

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        return self.stats.copy()
