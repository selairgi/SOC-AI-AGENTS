"""
SOC Analyst Agent.

Main analysis agent that:
- Subscribes to AlertDetected events
- Generates hypotheses about threats
- Calculates risk and likelihood scores
- Publishes AnalysisCompleted events

Flow:
    AlertDetected -> SOCAnalyst -> AnalysisCompleted
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

# Import utilities
try:
    from ..utils import FalsePositiveDetector, IntentAnalyzer, IntentResult, Intent
    HAS_INTENT_ANALYZER = True
except ImportError:
    FalsePositiveDetector = None
    IntentAnalyzer = None
    IntentResult = None
    Intent = None
    HAS_INTENT_ANALYZER = False


@dataclass
class Hypothesis:
    """A hypothesis about the threat."""
    description: str
    likelihood: float  # 0.0 - 1.0
    evidence: List[str] = field(default_factory=list)
    counter_evidence: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Result of threat analysis."""
    verdict: str  # true_positive, false_positive, needs_investigation
    certainty_score: float  # 0.0 - 1.0
    risk_level: str  # low, medium, high, critical
    risk_score: float  # 0 - 100
    hypotheses: List[Hypothesis] = field(default_factory=list)
    recommended_action: str = ""
    reasoning: str = ""
    context: Dict[str, Any] = field(default_factory=dict)


class SOCAnalyst:
    """
    Main SOC Analysis Agent.

    Responsibilities:
    - Subscribe to AlertDetected
    - Generate hypotheses about threats
    - Calculate risk scores
    - Recommend actions
    - Publish AnalysisCompleted events
    """

    EVENT_ALERT_DETECTED = "AlertDetected"
    EVENT_ANALYSIS_COMPLETED = "AnalysisCompleted"

    # Risk weights for different factors
    RISK_WEIGHTS = {
        "severity": 0.30,
        "confidence": 0.25,
        "asset_criticality": 0.20,
        "threat_history": 0.15,
        "exposure": 0.10
    }

    # Threat analysis rules
    THREAT_ANALYSIS = {
        "prompt_injection": {
            "hypotheses": [
                "Attempt to manipulate LLM behavior",
                "Social engineering through prompt manipulation",
                "Trying to bypass safety guidelines"
            ],
            "indicators_of_true_positive": [
                "Direct instruction override commands",
                "Multiple manipulation attempts",
                "Combination with other attack patterns"
            ],
            "indicators_of_false_positive": [
                "Educational question about prompt injection",
                "Security research discussion",
                "Quoted example in learning context"
            ],
            "recommended_action": "monitor"
        },
        "brute_force": {
            "hypotheses": [
                "Credential stuffing attack using leaked passwords",
                "Targeted brute force against specific user",
                "Automated bot attempting common passwords"
            ],
            "indicators_of_true_positive": [
                "Multiple failed attempts from same IP",
                "Attempts against multiple users",
                "Non-standard user agent"
            ],
            "indicators_of_false_positive": [
                "User forgot password",
                "Password change in progress",
                "Single IP, single user, few attempts"
            ],
            "recommended_action": "block_ip"
        },
        "sql_injection": {
            "hypotheses": [
                "Automated SQL injection scan",
                "Targeted attack on database",
                "Web application vulnerability probe"
            ],
            "indicators_of_true_positive": [
                "Multiple injection patterns",
                "Targeting multiple endpoints",
                "Following common SQLi payloads"
            ],
            "indicators_of_false_positive": [
                "Legitimate query with SQL keywords",
                "Developer testing",
                "Single isolated request"
            ],
            "recommended_action": "block_ip"
        },
        "xss": {
            "hypotheses": [
                "XSS vulnerability scanning",
                "Targeted session hijacking attempt",
                "Malicious script injection"
            ],
            "indicators_of_true_positive": [
                "Multiple XSS patterns",
                "Encoded payloads",
                "Targeting input fields"
            ],
            "indicators_of_false_positive": [
                "Developer testing",
                "Legitimate JavaScript in form"
            ],
            "recommended_action": "block_ip"
        },
        "command_injection": {
            "hypotheses": [
                "Remote code execution attempt",
                "System compromise attempt",
                "Reverse shell injection"
            ],
            "indicators_of_true_positive": [
                "Shell metacharacters present",
                "Known command injection patterns",
                "Targeting vulnerable endpoints"
            ],
            "indicators_of_false_positive": [
                "Legitimate system command",
                "Admin operation"
            ],
            "recommended_action": "isolate_system"
        },
        "data_exfiltration": {
            "hypotheses": [
                "Insider threat exfiltrating data",
                "Compromised account data theft",
                "Automated data harvesting"
            ],
            "indicators_of_true_positive": [
                "Unusual data volume",
                "Off-hours activity",
                "Accessing sensitive files"
            ],
            "indicators_of_false_positive": [
                "Legitimate bulk operation",
                "Scheduled backup",
                "Authorized export"
            ],
            "recommended_action": "disable_account"
        },
        "malware": {
            "hypotheses": [
                "Malware infection detected",
                "Ransomware deployment",
                "Botnet communication"
            ],
            "indicators_of_true_positive": [
                "Known malware signature",
                "C2 communication patterns",
                "File encryption activity"
            ],
            "indicators_of_false_positive": [
                "Security tool false positive",
                "Legitimate software flagged"
            ],
            "recommended_action": "isolate_system"
        },
        "port_scan": {
            "hypotheses": [
                "Reconnaissance before attack",
                "Network mapping activity",
                "Vulnerability scanning"
            ],
            "indicators_of_true_positive": [
                "Sequential port access",
                "Known scanner patterns",
                "Multiple targets"
            ],
            "indicators_of_false_positive": [
                "Legitimate network monitoring",
                "Admin connectivity test"
            ],
            "recommended_action": "block_ip"
        },
        "suspicious_access": {
            "hypotheses": [
                "Privilege escalation attempt",
                "Unauthorized resource access",
                "Misconfigured permissions probe"
            ],
            "indicators_of_true_positive": [
                "Multiple 403/401 errors",
                "Accessing restricted paths",
                "Following privilege escalation patterns"
            ],
            "indicators_of_false_positive": [
                "Misconfigured client",
                "Expired credentials",
                "Normal crawling"
            ],
            "recommended_action": "monitor"
        }
    }

    def __init__(
        self,
        event_bus,
        incremental_storage=None,
        context_service=None,
        use_fp_detector: bool = True,
        use_intent_analyzer: bool = True,
        llm_provider: str = "ollama",
        llm_model: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the SOC Analyst.

        Args:
            event_bus: EventBus for pub/sub
            incremental_storage: Optional storage for learning
            context_service: Optional service for context enrichment
            use_fp_detector: Enable false positive detection
            use_intent_analyzer: Enable LLM-based intent analysis
            llm_provider: LLM provider ("ollama", "openai", "anthropic")
            llm_model: LLM model name
            llm_api_key: API key for cloud LLM providers
            logger: Optional logger instance
        """
        self.bus = event_bus
        self.storage = incremental_storage
        self.context_service = context_service
        self.logger = logger or logging.getLogger("SOCAnalyst")

        # Initialize FalsePositiveDetector if available
        self.fp_detector = None
        if use_fp_detector and FalsePositiveDetector:
            self.fp_detector = FalsePositiveDetector(logger=self.logger)
            self.logger.info("FalsePositiveDetector enabled")

        # Initialize IntentAnalyzer (LLM-based) if available
        self.intent_analyzer = None
        if use_intent_analyzer and HAS_INTENT_ANALYZER and IntentAnalyzer:
            try:
                self.intent_analyzer = IntentAnalyzer(
                    provider=llm_provider,
                    model=llm_model,
                    api_key=llm_api_key,
                    logger=self.logger
                )
                self.logger.info(f"IntentAnalyzer enabled ({llm_provider})")
            except Exception as e:
                self.logger.warning(f"IntentAnalyzer init failed: {e}")

        self._running = False

        # Statistics
        self.stats = {
            "alerts_analyzed": 0,
            "verdicts": {"true_positive": 0, "false_positive": 0, "needs_investigation": 0},
            "risk_levels": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "fp_detector_used": 0,
            "intent_analyzer_used": 0,
            "llm_false_positives": 0,
            "start_time": None
        }

    def start(self) -> None:
        """Start the analyst agent."""
        if self._running:
            self.logger.warning("SOCAnalyst already running")
            return

        self.bus.subscribe(self.EVENT_ALERT_DETECTED, self._handle_alert)
        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()

        self.logger.info("SOCAnalyst started")

    def stop(self) -> None:
        """Stop the analyst agent."""
        if not self._running:
            return

        self.bus.unsubscribe(self.EVENT_ALERT_DETECTED, self._handle_alert)
        self._running = False

        self.logger.info("SOCAnalyst stopped")
        self._log_stats()

    def _handle_alert(self, event: dict) -> None:
        """Handle incoming alert event."""
        self.stats["alerts_analyzed"] += 1

        try:
            correlation_id = event.get("correlation_id")
            payload = event.get("payload", {})

            # Extract alert details
            threat_type = payload.get("threat_type", "unknown")
            severity = payload.get("severity", "medium")
            confidence = payload.get("confidence", 0.5)
            features = payload.get("features", {})
            indicators = payload.get("indicators", [])

            # Get additional context if available
            context = self._get_context(payload)

            # Run FalsePositiveDetector if available
            fp_result = None
            if self.fp_detector:
                message = payload.get("explanation", "")
                user_id = features.get("user") or payload.get("source_event", {}).get("user")
                fp_result = self.fp_detector.analyze(
                    message=message,
                    threat_type=threat_type,
                    severity=severity,
                    user_id=user_id,
                    context={"source_ip": features.get("source_ip")}
                )
                self.stats["fp_detector_used"] += 1

                # Adjust confidence based on FP detector
                if fp_result.is_false_positive:
                    confidence = min(confidence, 1.0 - fp_result.fp_probability)
                    self.logger.debug(f"FP detector: likely false positive (fp_prob={fp_result.fp_probability:.2f})")

            # Run IntentAnalyzer (LLM-based) if available
            intent_result = None
            if self.intent_analyzer:
                # Get original message that triggered the alert
                original_message = payload.get("source_event", {}).get("message", "")
                if not original_message:
                    original_message = payload.get("explanation", "")

                if original_message:
                    try:
                        intent_result = self.intent_analyzer.analyze(
                            message=original_message,
                            detected_threat=threat_type,
                            severity=severity,
                            additional_context={
                                "source_ip": features.get("source_ip"),
                                "indicators": indicators
                            }
                        )
                        self.stats["intent_analyzer_used"] += 1

                        # If LLM determines educational/benign intent, adjust confidence
                        if intent_result.is_false_positive:
                            old_confidence = confidence
                            confidence = min(confidence, 1.0 - intent_result.confidence)
                            self.stats["llm_false_positives"] += 1
                            self.logger.info(
                                f"IntentAnalyzer: {intent_result.intent.value} intent detected "
                                f"(confidence={intent_result.confidence:.2f}), "
                                f"adjusted confidence {old_confidence:.2f} -> {confidence:.2f}"
                            )
                    except Exception as e:
                        self.logger.warning(f"IntentAnalyzer failed: {e}")

            # Perform analysis
            result = self._analyze(
                threat_type=threat_type,
                severity=severity,
                confidence=confidence,
                features=features,
                indicators=indicators,
                context=context,
                fp_result=fp_result,
                intent_result=intent_result
            )

            # Store for incremental learning
            if self.storage:
                self._store_for_learning(event, result)

            # Publish analysis result
            self._publish_analysis(event, result, correlation_id)

        except Exception as e:
            self.logger.error(f"Error analyzing alert: {e}")

    def _get_context(self, payload: dict) -> Dict[str, Any]:
        """Get additional context for analysis."""
        context = {
            "asset_criticality": "medium",  # Default
            "threat_history": False,
            "exposure": "internal"
        }

        # Use context service if available
        if self.context_service:
            try:
                source_ip = payload.get("source_event", {}).get("source_ip")
                user = payload.get("source_event", {}).get("user")

                if source_ip:
                    ip_context = self.context_service.get_ip_context(source_ip)
                    context.update(ip_context)

                if user:
                    user_context = self.context_service.get_user_context(user)
                    context.update(user_context)
            except Exception as e:
                self.logger.debug(f"Context enrichment failed: {e}")

        return context

    def _analyze(
        self,
        threat_type: str,
        severity: str,
        confidence: float,
        features: Dict[str, Any],
        indicators: List[str],
        context: Dict[str, Any],
        fp_result=None,
        intent_result=None
    ) -> AnalysisResult:
        """
        Analyze alert and generate hypotheses.

        Args:
            threat_type: Type of threat detected
            severity: Alert severity
            confidence: Detection confidence
            features: Extracted features
            indicators: Threat indicators
            context: Additional context
            fp_result: Optional FalsePositiveDetector result
            intent_result: Optional IntentAnalyzer result (LLM-based)

        Returns:
            AnalysisResult with verdict and recommendations
        """
        # Get threat-specific analysis rules
        analysis_rules = self.THREAT_ANALYSIS.get(threat_type, {})

        # Override verdict if FP detector is confident
        fp_override = None
        if fp_result and fp_result.is_false_positive and fp_result.fp_probability > 0.8:
            fp_override = "false_positive"

        # Override verdict if IntentAnalyzer (LLM) is confident about educational/benign intent
        intent_override = None
        if intent_result and intent_result.is_false_positive and intent_result.confidence > 0.7:
            intent_override = "false_positive"

        # Generate hypotheses
        hypotheses = self._generate_hypotheses(
            threat_type, analysis_rules, features, indicators
        )

        # Calculate risk score
        risk_score = self._calculate_risk_score(
            severity, confidence, context
        )
        risk_level = self._risk_level_from_score(risk_score)

        # Determine verdict
        verdict, certainty = self._determine_verdict(
            hypotheses, confidence, risk_score, analysis_rules
        )

        # Apply FP override if confident (rule-based)
        if fp_override:
            verdict = fp_override
            certainty = fp_result.fp_probability if fp_result else certainty

        # Apply Intent override if confident (LLM-based) - takes priority
        if intent_override:
            verdict = intent_override
            certainty = intent_result.confidence if intent_result else certainty

        # Get recommended action
        recommended_action = analysis_rules.get("recommended_action", "monitor")
        if verdict == "false_positive":
            recommended_action = "dismiss"
        elif verdict == "needs_investigation":
            recommended_action = "escalate"

        # Add FP reasoning if available
        fp_reasoning = ""
        if fp_result:
            fp_reasoning = f"\n\nFP Analysis: {fp_result.recommended_action} (confidence={fp_result.confidence:.2f})"
            if fp_result.reasoning:
                fp_reasoning += f"\n- " + "\n- ".join(fp_result.reasoning[:3])

        # Add Intent Analysis reasoning if available (LLM-based)
        intent_reasoning = ""
        if intent_result:
            intent_reasoning = f"\n\nIntent Analysis (LLM): {intent_result.intent.value} (confidence={intent_result.confidence:.2f})"
            if intent_result.reasoning:
                intent_reasoning += f"\n- {intent_result.reasoning}"
            if intent_result.is_false_positive:
                intent_reasoning += f"\n- Conclusion: FALSE POSITIVE (educational/benign intent detected)"

        # Generate reasoning
        reasoning = self._generate_reasoning(
            threat_type, verdict, hypotheses, risk_level
        ) + fp_reasoning + intent_reasoning

        return AnalysisResult(
            verdict=verdict,
            certainty_score=certainty,
            risk_level=risk_level,
            risk_score=risk_score,
            hypotheses=hypotheses,
            recommended_action=recommended_action,
            reasoning=reasoning,
            context=context
        )

    def _generate_hypotheses(
        self,
        threat_type: str,
        analysis_rules: Dict[str, Any],
        features: Dict[str, Any],
        indicators: List[str]
    ) -> List[Hypothesis]:
        """Generate hypotheses about the threat."""
        hypotheses = []

        hypothesis_texts = analysis_rules.get("hypotheses", [
            f"Potential {threat_type} attack detected"
        ])
        tp_indicators = analysis_rules.get("indicators_of_true_positive", [])
        fp_indicators = analysis_rules.get("indicators_of_false_positive", [])

        for i, text in enumerate(hypothesis_texts[:3]):  # Max 3 hypotheses
            # Calculate likelihood based on indicators
            evidence = []
            counter_evidence = []

            for indicator in tp_indicators:
                if any(ind.lower() in indicator.lower() for ind in indicators):
                    evidence.append(indicator)

            for indicator in fp_indicators:
                if any(ind.lower() in indicator.lower() for ind in indicators):
                    counter_evidence.append(indicator)

            # Calculate likelihood
            evidence_weight = len(evidence) * 0.2
            counter_weight = len(counter_evidence) * 0.15
            base_likelihood = 0.5 + evidence_weight - counter_weight

            hypotheses.append(Hypothesis(
                description=text,
                likelihood=max(0.1, min(0.95, base_likelihood)),
                evidence=evidence,
                counter_evidence=counter_evidence
            ))

        return hypotheses

    def _calculate_risk_score(
        self,
        severity: str,
        confidence: float,
        context: Dict[str, Any]
    ) -> float:
        """Calculate overall risk score (0-100)."""
        # Severity score
        severity_scores = {"low": 25, "medium": 50, "high": 75, "critical": 100}
        severity_score = severity_scores.get(severity, 50)

        # Asset criticality score
        criticality_scores = {"low": 25, "medium": 50, "high": 75, "critical": 100}
        asset_criticality = context.get("asset_criticality", "medium")
        criticality_score = criticality_scores.get(asset_criticality, 50)

        # Threat history factor
        history_factor = 1.2 if context.get("threat_history") else 1.0

        # Exposure factor
        exposure_scores = {"internal": 0.8, "external": 1.0, "public": 1.2}
        exposure = context.get("exposure", "internal")
        exposure_factor = exposure_scores.get(exposure, 1.0)

        # Calculate weighted risk score
        risk_score = (
            (severity_score * self.RISK_WEIGHTS["severity"]) +
            (confidence * 100 * self.RISK_WEIGHTS["confidence"]) +
            (criticality_score * self.RISK_WEIGHTS["asset_criticality"]) +
            (50 * history_factor * self.RISK_WEIGHTS["threat_history"]) +
            (50 * exposure_factor * self.RISK_WEIGHTS["exposure"])
        )

        return min(100, max(0, risk_score))

    def _risk_level_from_score(self, score: float) -> str:
        """Convert risk score to risk level."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"

    def _determine_verdict(
        self,
        hypotheses: List[Hypothesis],
        confidence: float,
        risk_score: float,
        analysis_rules: Dict[str, Any]
    ) -> tuple:
        """Determine verdict and certainty."""
        if not hypotheses:
            return "needs_investigation", 0.5

        # Average hypothesis likelihood
        avg_likelihood = sum(h.likelihood for h in hypotheses) / len(hypotheses)

        # Combine with confidence and risk
        combined_score = (
            (confidence * 0.4) +
            (avg_likelihood * 0.4) +
            (risk_score / 100 * 0.2)
        )

        # Determine verdict
        if combined_score >= 0.7:
            verdict = "true_positive"
            certainty = combined_score
        elif combined_score <= 0.3:
            verdict = "false_positive"
            certainty = 1 - combined_score
        else:
            verdict = "needs_investigation"
            certainty = 0.5 + abs(combined_score - 0.5)

        return verdict, certainty

    def _generate_reasoning(
        self,
        threat_type: str,
        verdict: str,
        hypotheses: List[Hypothesis],
        risk_level: str
    ) -> str:
        """Generate human-readable reasoning."""
        lines = [
            f"Threat Type: {threat_type}",
            f"Verdict: {verdict}",
            f"Risk Level: {risk_level}",
            "",
            "Hypotheses:"
        ]

        for h in hypotheses:
            lines.append(f"- {h.description} (likelihood: {h.likelihood:.0%})")
            if h.evidence:
                lines.append(f"  Evidence: {', '.join(h.evidence)}")
            if h.counter_evidence:
                lines.append(f"  Counter-evidence: {', '.join(h.counter_evidence)}")

        return "\n".join(lines)

    def _store_for_learning(self, event: dict, result: AnalysisResult) -> None:
        """Store analysis example for incremental learning."""
        try:
            example = {
                "alert_event": event,
                "analysis": {
                    "verdict": result.verdict,
                    "certainty_score": result.certainty_score,
                    "risk_level": result.risk_level,
                    "risk_score": result.risk_score,
                    "recommended_action": result.recommended_action
                },
                "hypotheses": [
                    {
                        "description": h.description,
                        "likelihood": h.likelihood
                    }
                    for h in result.hypotheses
                ],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.storage.store("analyst", example)
        except Exception as e:
            self.logger.debug(f"Failed to store for learning: {e}")

    def _publish_analysis(
        self,
        source_event: dict,
        result: AnalysisResult,
        correlation_id: str
    ) -> None:
        """Publish AnalysisCompleted event."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        analysis_event = {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "soc_analyst",
            "payload": {
                "analysis_id": f"analysis-{event_id[:8]}",
                "alert_id": source_event.get("payload", {}).get("alert_id"),
                "verdict": result.verdict,
                "certainty_score": result.certainty_score,
                "risk_level": result.risk_level,
                "risk_score": result.risk_score,
                "recommended_action": result.recommended_action,
                "hypotheses": [
                    {
                        "description": h.description,
                        "likelihood": h.likelihood,
                        "evidence": h.evidence,
                        "counter_evidence": h.counter_evidence
                    }
                    for h in result.hypotheses
                ],
                "reasoning": result.reasoning,
                "context": result.context
            }
        }

        self.bus.publish(self.EVENT_ANALYSIS_COMPLETED, analysis_event)

        # Update statistics
        self.stats["verdicts"][result.verdict] += 1
        self.stats["risk_levels"][result.risk_level] += 1

        self.logger.info(
            f"Analysis completed: verdict={result.verdict}, "
            f"risk={result.risk_level}, action={result.recommended_action}"
        )

    def _log_stats(self) -> None:
        """Log statistics."""
        self.logger.info("=== SOCAnalyst Statistics ===")
        self.logger.info(f"Alerts analyzed: {self.stats['alerts_analyzed']}")
        self.logger.info(f"Verdicts: {self.stats['verdicts']}")
        self.logger.info(f"Risk levels: {self.stats['risk_levels']}")
        self.logger.info(f"FP detector used: {self.stats['fp_detector_used']}")
        self.logger.info(f"Intent analyzer used: {self.stats['intent_analyzer_used']}")
        self.logger.info(f"LLM false positives detected: {self.stats['llm_false_positives']}")

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        return self.stats.copy()

    def is_running(self) -> bool:
        """Check if analyst is running."""
        return self._running
