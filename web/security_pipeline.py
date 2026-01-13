"""
SOC Builder for Web Application - Manages security components and threat detection.

This module contains the SecureSOCWebIntegration class which orchestrates:
- Security rules engine
- Intelligent prompt detection
- False positive analysis
- Remediation engine
- Real-time alerting via WebSocket

Extracted from app.py to improve code organization and maintainability.
"""

import os
import time
import asyncio
import threading
import logging
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime

from security.security_rules import SecurityRulesEngine
from security.false_positive_detector import FalsePositiveDetector
from security.real_remediation import RealRemediationEngine
from security.intelligent_prompt_detector import IntelligentPromptDetector
from security.incremental_learning import IncrementalLearningSystem
from security.formal_effect_analyzer_v5_2 import FormalEffectAnalyzerV52
from security.sophisticated_injection_detector import SophisticatedInjectionDetector
from security.semantic_detector import SemanticInjectionDetector
from core.soc_analyst import SOCAnalyst
from core.remediator import Remediator
from shared.message_bus import MessageBus
from shared.models import LogEntry, Alert, AgentType
from shared.environment_config import EnvironmentConfig
from shared.agent_memory import AgentMemory
from shared.constants import (
    FALSE_POSITIVE_IGNORE_THRESHOLD,
    FALSE_POSITIVE_BLOCK_PROMPT_INJECTION,
    FALSE_POSITIVE_BLOCK_HIGH_SEVERITY,
    DEFAULT_IP_BLOCK_DURATION_SECONDS,
    MAX_CHAT_HISTORY_PER_SESSION,
    MAX_CACHED_ALERTS
)
from ai.real_ai_integration import RealAIIntegration


logger = logging.getLogger("SOCBuilder")


class SecureSOCWebIntegration:
    """
    SOC Builder for Web Application - orchestrates security monitoring and response.

    This class builds and manages the Security Operations Center (SOC) for the web application.
    It integrates multiple security components:
    - Threat detection (rule-based and AI-powered)
    - False positive analysis
    - Automated and manual remediation
    - Real-time alerting

    Architecture:
        Input → Validation → Threat Detection → FP Analysis → Remediation → Response
    """

    def __init__(self, socketio=None):
        """
        Initialize SOC Builder with all security components.

        Args:
            socketio: Flask-SocketIO instance for real-time WebSocket emissions
        """
        self.logger = logger
        self.socketio = socketio

        # Initialize SOC Components
        try:
            self.rules_engine = SecurityRulesEngine()
            self.bus = MessageBus()
            self.remediator_queue = asyncio.Queue()
            self.analyst = SOCAnalyst(self.bus, self.remediator_queue)
            self.remediator = Remediator()
            self.config = EnvironmentConfig()
            self.config.apply_preset("production")

            # AI Integration
            openai_key = os.getenv('OPENAI_API_KEY')
            if not openai_key:
                self.logger.warning("OPENAI_API_KEY not set - AI features will be limited")

            self.ai_integration = RealAIIntegration(
                api_key=openai_key,
                model=os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
            )
            self.fp_detector = FalsePositiveDetector()
            self.real_remediator = RealRemediationEngine()

            # Add intelligent prompt detector
            self.intelligent_detector = IntelligentPromptDetector(ai_integration=self.ai_integration)

            # Initialize Formal Effect Analyzer V5.2
            self.formal_analyzer = FormalEffectAnalyzerV52()
            self.logger.info("[GOOD] Formal Effect Analyzer V5.2 initialized ")

            # Initialize Semantic Detector (FIX V5: Authority + Logical Traps)
            self.semantic_detector = SemanticInjectionDetector()
            self.logger.info("[GOOD] Semantic Injection Detector initialized (scoring system)")

            # Initialize ML Ensemble Detector (V7: XGBoost + Embeddings + PromptSleuth)
            try:
                from security.ml_ensemble_detector import MLEnsembleDetector
                self.ml_ensemble = MLEnsembleDetector(model_dir="security/.cache")
                if self.ml_ensemble.is_trained():
                    self.logger.info("[GOOD] ML Ensemble Detector initialized (XGBoost + Embeddings trained)")
                else:
                    self.logger.warning("[WARNING] ML Ensemble Detector initialized (NOT trained - will use default scoring)")
            except Exception as e:
                self.logger.warning(f"[WARNING] ML Ensemble Detector not available: {e}")
                self.ml_ensemble = None

            # Initialize PromptSleuth Arbitre
            self._initialize_promptsleuth()

            # Initialize Sophisticated Injection Detector (Fallback Layer)
            self.sophisticated_detector = SophisticatedInjectionDetector()
            stats = self.sophisticated_detector.get_detection_stats()
            self.logger.info(f"[GOOD] Sophisticated Detector initialized | Patterns: {stats['total_patterns']} | Keywords: {stats['total_keywords']} | Fallback layer (free, <10ms)")
            self.sophisticated_detector_metrics = {
                "calls": 0,
                "detections": 0,
                "avg_time_ms": 0.0,
                "total_time": 0.0
            }

            # Initialize incremental learning system
            self.agent_memory = AgentMemory()
            self.learning_system = IncrementalLearningSystem(
                memory=self.agent_memory,
                ai_integration=self.ai_integration,
                auto_update=True,  # Automatically learn from missed attacks
                learning_rate=0.1
            )

            # State management
            self.soc_enabled = True
            self.active_sessions: Dict[str, Dict[str, Any]] = {}
            self.chat_history: Dict[str, list] = {}
            self.soc_alerts: list = []
            self.start_time = time.time()
            self.test_results: list = []

            # Start SOC monitoring
            self.start_soc_monitoring()

            self.logger.info("[GOOD] SOC Builder initialized successfully")

        except Exception as e:
            self.logger.error(f"[PROBLEM] Failed to initialize SOC Builder: {e}", exc_info=True)
            raise

    def _initialize_promptsleuth(self):
        """
        Initialize PromptSleuth arbitre for disagreement resolution.

        Only called when Intelligent Detector = SAFE and Formal V5.2 = THREAT
        with certainty < 90%.
        """
        try:
            import sys
            import hashlib
            from pathlib import Path
            from collections import deque

            # Add prompt_sleuth to path
            # In Docker: /app/security_pipeline.py -> /app/prompt_sleuth
            # Local dev: project/web/security_pipeline.py -> project/prompt_sleuth
            current_file = Path(__file__).resolve()

            # Try Docker path first
            prompt_sleuth_path = Path('/app/prompt_sleuth')
            if not prompt_sleuth_path.exists():
                # Fallback to local dev path
                prompt_sleuth_path = current_file.parent.parent / 'prompt_sleuth'

            if prompt_sleuth_path.exists():
                sys.path.insert(0, str(prompt_sleuth_path.parent))

            from prompt_sleuth import PromptSleuth, PromptSleuthConfig

            # Mode Fast pour latence réduite
            ps_config = PromptSleuthConfig.accurate_mode()
            ps_config.logging.enable_logging = False  # Éviter double logging
            ps_config.llm.timeout = 8  # Timeout raisonnable

            self.prompt_sleuth = PromptSleuth(ps_config)
            self.prompt_sleuth_enabled = True

            # Cache pour éviter appels répétés
            self.promptsleuth_cache = {}  # {prompt_hash: (result, timestamp)}
            self.promptsleuth_cache_ttl = 3600  # 1 heure

            # Mode dégradé
            self.promptsleuth_error_threshold = 5
            self.promptsleuth_consecutive_errors = 0

            # Whitelist patterns
            self.promptsleuth_bypass_patterns = [
                r"^what is \w+",
                r"^explain \w+",
                r"^how (do|to) \w+",
                r"^can you (help|show|tell)",
            ]

            # Métriques
            self.promptsleuth_metrics = {
                "calls": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "timeouts": 0,
                "errors": 0,
                "bypassed": 0,
                "total_time": 0.0,
                "verdicts": {
                    "safe": 0,
                    "warning": 0,
                    "confirm": 0
                }
            }

            self.logger.info(
                "[GOOD] PromptSleuth arbitre initialized | "
                "Mode: Accurate | Cache: 1h TTL | No rate limits"
            )

        except Exception as e:
            self.logger.warning(f"[WARNING] PromptSleuth not available: {e}")
            self.prompt_sleuth = None
            self.prompt_sleuth_enabled = False

    def start_soc_monitoring(self):
        """Start SOC Analyst and Remediator in background thread."""
        def run_soc():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._run_soc_components())
            except Exception as e:
                self.logger.error(f"SOC monitoring thread error: {e}", exc_info=True)

        soc_thread = threading.Thread(target=run_soc, daemon=True, name="SOC-Monitoring")
        soc_thread.start()
        self.logger.info("SOC monitoring thread started")

    async def _run_soc_components(self):
        """Run SOC Analyst and Remediator asynchronously."""
        try:
            await asyncio.gather(
                self.analyst.run(),
                self.remediator.run(self.remediator_queue),
                return_exceptions=True
            )
        except Exception as e:
            self.logger.error(f"SOC components error: {e}", exc_info=True)

    def process_chat_message(
        self,
        message: str,
        user_id: str,
        session_id: str,
        user_ip: str = "127.0.0.1",
        security_mode: str = "security_aware",
        auto_remediation: bool = False
    ) -> Dict[str, Any]:
        """
        Process chat message with comprehensive security checks.

        Security Pipeline:
        1. Input validation
        2. Block status check (IP, user, session)
        3. Rate limiting
        4. Threat detection (intelligent + rule-based)
        5. False positive analysis
        6. Remediation (auto or manual approval)
        7. AI response generation

        Args:
            message: User's chat message
            user_id: User identifier
            session_id: Session identifier
            user_ip: User's IP address
            security_mode: Security mode (security_aware, strict, permissive)
            auto_remediation: If True, execute remediation immediately. If False, request approval.

        Returns:
            dict with response, security info, and remediation status
        """
        result = {
            "response": "",
            "interaction_id": "",
            "security_check": {
                "soc_enabled": self.soc_enabled,
                "alert_detected": False,
                "alert": None,
                "false_positive_analysis": None,
                "remediation_taken": False,
                "remediation_actions": [],
                "blocked": False,
                "block_reason": None
            },
            "ai_stats": {},
            "timestamp": datetime.utcnow().isoformat(),
            "error": None
        }

        try:
            # Step 2: Check if user/IP/session is blocked
            if self.real_remediator.is_ip_blocked(user_ip):
                result["security_check"]["blocked"] = True
                result["security_check"]["block_reason"] = "IP address is blocked"
                result["response"] = "Access denied: Your IP address has been blocked due to security policy violations."
                self.logger.warning(f"[BLOCKED] Blocked IP {user_ip} attempted access")
                return result

            if self.real_remediator.is_user_blocked(user_id):
                result["security_check"]["blocked"] = True
                result["security_check"]["block_reason"] = "User account is suspended"
                result["response"] = "Access denied: Your account has been suspended due to security violations."
                self.logger.warning(f"[BLOCKED] Blocked user {user_id} attempted access")
                return result

            if self.real_remediator.is_session_terminated(session_id):
                result["security_check"]["blocked"] = True
                result["security_check"]["block_reason"] = "Session has been terminated"
                result["response"] = "Access denied: Your session has been terminated due to security policy violations."
                self.logger.warning(f"[BLOCKED] Terminated session {session_id} attempted access")
                return result

            # Step 3: Rate limiting - DISABLED for evaluation
            # if user_id and not user_id.startswith("test_"):
            #     allowed, retry_after = self.real_remediator.check_rate_limit(user_ip, "ip")
            #     if not allowed:
            #         result["security_check"]["blocked"] = True
            #         result["security_check"]["block_reason"] = f"Rate limit exceeded. Retry after {retry_after:.0f}s"
            #         result["response"] = f"Rate limit exceeded. Please wait {retry_after:.0f} seconds before trying again."
            #         self.logger.warning(f"⏱️ Rate limit exceeded for IP {user_ip}")
            #         return result

            # Step 4: SOC Security Analysis BEFORE generating AI response
            if self.soc_enabled:
                try:
                    # Create log entry for security analysis
                    temp_log = LogEntry(
                        timestamp=time.time(),
                        source="real_ai_chatbot",
                        message=message,
                        agent_id="openai_chatbot_agent",
                        user_id=user_id,
                        session_id=session_id,
                        src_ip=user_ip,
                        request_id=f"temp_{int(time.time())}",
                        response_time=0.0,
                        status_code=200,
                        extra={"agent_type": AgentType.GENERAL.value}
                    )

                    # ================================================================
                    # DUAL DETECTION LAYER (Parallel execution)
                    # ================================================================
                    # Layer 1: Intelligent Detector (LLM-based, educational context aware)
                    # Layer 2: Formal Effect Analyzer V5.2 (enhanced NLP, format abuse, indirect revelation)

                    intelligent_alert = None
                    formal_alert = None
                    detection_methods = []

                    # Layer 1: Intelligent Detector
                    try:
                        intelligent_alert = self.intelligent_detector.detect_prompt_injection(temp_log)
                        if intelligent_alert:
                            detection_methods.append("intelligent_detector")
                    except Exception as e:
                        self.logger.warning(f"Intelligent detection error: {e}")
                        # Fallback to rules_engine if intelligent_detector fails
                        try:
                            intelligent_alert = self.rules_engine.analyze_log(temp_log)
                            if intelligent_alert:
                                detection_methods.append("rules_engine")
                            self.logger.info("Using rules_engine fallback")
                        except Exception as e2:
                            self.logger.error(f"Both intelligent detectors failed: {e2}")

                    # Layer 2: Formal Effect Analyzer V5.2
                    try:
                        formal_result = self.formal_analyzer.analyze(message)

                        # Convert V5.2 verdict to Alert if threat detected
                        if formal_result["verdict"] in ["STRONG_LEAK", "PARTIAL_LEAK", "WEAK_LEAK", "INSTRUCTION_VIOLATION", "SOCIAL_ENGINEERING"]:
                            from shared.models import ThreatType

                            # Map V5.2 verdict to ThreatType
                            threat_type_map = {
                                "STRONG_LEAK": ThreatType.DATA_EXFILTRATION,
                                "PARTIAL_LEAK": ThreatType.DATA_EXFILTRATION,
                                "WEAK_LEAK": ThreatType.DATA_EXFILTRATION,
                                "INSTRUCTION_VIOLATION": ThreatType.PROMPT_INJECTION,
                                "SOCIAL_ENGINEERING": ThreatType.PROMPT_INJECTION
                            }

                            formal_alert = Alert(
                                id=f"AL-{int(time.time() * 1000)}-FORMAL",
                                timestamp=time.time(),
                                severity="critical" if formal_result["certainty"] >= 0.90 else "high" if formal_result["certainty"] >= 0.75 else "medium",
                                title=f"Formal Analysis: {formal_result['verdict']}",
                                description=f"V5.2 Enhanced detection | Certainty: {formal_result['certainty']:.0%} | {formal_result['reason']}",
                                threat_type=threat_type_map.get(formal_result["verdict"], ThreatType.PROMPT_INJECTION),
                                false_positive_probability=1.0 - formal_result["certainty"],
                                evidence={
                                    "detection_method": "formal_effect_analyzer_v5.2",
                                    "verdict": formal_result["verdict"],
                                    "certainty": formal_result["certainty"],
                                    "reason": formal_result["reason"],
                                    "nlp_context": formal_result.get("nlp_context").__dict__ if formal_result.get("nlp_context") else None
                                }
                            )
                            detection_methods.append("formal_analyzer_v5.2")

                            # Emit formal analyzer workflow log
                            self._emit_workflow_log(
                                agent='Formal Analyzer V5.2',
                                action=f'Verdict: {formal_result["verdict"]}',
                                log_type='danger',
                                details=f'Certainty: {formal_result["certainty"]:.0%} | Mass: 81%, Advanced: 58% | {formal_result["reason"]}',
                                session_id=session_id
                            )

                    except Exception as e:
                        self.logger.warning(f"Formal analysis error: {e}")

                    # Layer 3: Semantic Detector (FIX V5: Authority + Logical Traps)
                    semantic_alert = None
                    try:
                        semantic_result = self.semantic_detector.detect(message)

                        # Convert to Alert if suspicious
                        if semantic_result.is_suspicious:
                            from shared.models import ThreatType

                            semantic_alert = Alert(
                                id=f"AL-{int(time.time() * 1000)}-SEMANTIC",
                                timestamp=time.time(),
                                severity="high" if semantic_result.severity == "high" else "medium",
                                title="Semantic Analysis: Scored Attack Pattern",
                                description=f"Scoring System | Score: {semantic_result.score:.2f} | Components: {semantic_result.components}",
                                threat_type=ThreatType.PROMPT_INJECTION,
                                false_positive_probability=1.0 - semantic_result.score,
                                evidence={
                                    "detection_method": "semantic_detector",
                                    "semantic_result": semantic_result.__dict__,
                                    "score": semantic_result.score,
                                    "components": semantic_result.components,
                                    "matched_patterns": semantic_result.matched_patterns,
                                    "severity": semantic_result.severity,
                                    "tags": ["semantic_scoring", f"severity_{semantic_result.severity}"] + semantic_result.matched_patterns[:3],
                                    "remediation_suggestions": [
                                        f"Attack score: {semantic_result.score:.2f}/1.0 (threshold: 0.70)",
                                        f"Matched patterns: {', '.join(semantic_result.matched_patterns[:5])}"
                                    ]
                                }
                            )
                            # Add confidence as dynamic attribute for _fuse_verdicts
                            semantic_alert.confidence = semantic_result.score
                            detection_methods.append("semantic_detector")

                            self._emit_workflow_log(
                                agent='Semantic Detector',
                                action=f'Suspicious: {semantic_result.severity.upper()}',
                                log_type='warning' if semantic_result.severity == "medium" else 'danger',
                                details=f'Score: {semantic_result.score:.2f} | Components: {semantic_result.components}',
                                session_id=session_id
                            )

                    except Exception as e:
                        self.logger.warning(f"Semantic analysis error: {e}")

                    # Layer 4: ML Ensemble Detector (V7: XGBoost + Embeddings + PromptSleuth)
                    ml_alert = None
                    if self.ml_ensemble:
                        try:
                            # Prepare PromptSleuth result if available
                            promptsleuth_result = None
                            if hasattr(self, 'prompt_sleuth') and self.prompt_sleuth:
                                try:
                                    ps_detection = self.prompt_sleuth.check_prompt(
                                        system_prompt="You are a SOC AI assistant.",
                                        user_input=message
                                    )
                                    promptsleuth_result = {
                                        'is_injection': ps_detection.is_injection,
                                        'score': ps_detection.score,
                                        'explanation': ps_detection.explanation
                                    }
                                except Exception as ps_err:
                                    self.logger.debug(f"PromptSleuth error in ML layer: {ps_err}")

                            # Run ML Ensemble detection
                            ml_result = self.ml_ensemble.detect(
                                message=message,
                                semantic_result=semantic_result.__dict__ if semantic_result else None,
                                promptsleuth_result=promptsleuth_result
                            )

                            # Convert to Alert if suspicious
                            if ml_result.is_suspicious:
                                from shared.models import ThreatType

                                ml_alert = Alert(
                                    id=f"AL-{int(time.time() * 1000)}-ML",
                                    timestamp=time.time(),
                                    severity="high" if ml_result.ml_confidence >= 0.8 else "medium",
                                    title="ML Ensemble Detection",
                                    description=f"ML Ensemble | Confidence: {ml_result.ml_confidence:.2f} | {ml_result.explanation}",
                                    threat_type=ThreatType.PROMPT_INJECTION,
                                    false_positive_probability=1.0 - ml_result.ml_confidence,
                                    evidence={
                                        "detection_method": "ml_ensemble",
                                        "ml_confidence": ml_result.ml_confidence,
                                        "xgb_score": ml_result.xgb_score,
                                        "embedding_score": ml_result.embedding_score,
                                        "promptsleuth_score": ml_result.promptsleuth_score,
                                        "components": ml_result.components,
                                        "tags": ["ml_ensemble", f"confidence_{int(ml_result.ml_confidence * 100)}"],
                                        "remediation_suggestions": [
                                            f"ML Confidence: {ml_result.ml_confidence:.2f}/1.0 (threshold: 0.60)",
                                            f"Components: XGB={ml_result.xgb_score:.2f}, Emb={ml_result.embedding_score:.2f}, PS={ml_result.promptsleuth_score:.2f}"
                                        ]
                                    }
                                )
                                ml_alert.confidence = ml_result.ml_confidence
                                detection_methods.append("ml_ensemble")

                                self._emit_workflow_log(
                                    agent='ML Ensemble',
                                    action='ML Detection',
                                    log_type='danger' if ml_result.ml_confidence >= 0.8 else 'warning',
                                    details=f'Confidence: {ml_result.ml_confidence:.2f} | {ml_result.explanation}',
                                    session_id=session_id
                                )

                        except Exception as e:
                            self.logger.warning(f"ML Ensemble detection error: {e}")

                    # VERDICT FUSION: Combine results from all detection layers
                    alert = self._fuse_verdicts(intelligent_alert, formal_alert, semantic_alert, ml_alert, detection_methods, session_id, message)

                    if alert:
                        # Analyze for false positives
                        fp_score = self.fp_detector.analyze_alert(
                            alert,
                            temp_log,
                            user_context={"session_id": session_id}
                        )

                        # Build reasoning from FP score
                        reasoning = fp_score.reasoning if fp_score else []
                        certainty_score = 1.0 - (fp_score.false_positive_probability if fp_score else 0.0)
                        fp_probability = fp_score.false_positive_probability if fp_score else 0.0

                        # Generate simple explanation
                        simple_explanation = f"Threat detected: {alert.severity.upper()} severity - Certainty: {certainty_score:.0%}, FP Probability: {fp_probability:.0%}"

                        # Store explanation in alert evidence
                        if not alert.evidence:
                            alert.evidence = {}
                        alert.evidence["llm_explanation"] = simple_explanation

                        self.logger.info(f"[GOOD] Generated explanation for alert {alert.id} (severity: {alert.severity})")

                        result["security_check"]["alert_detected"] = True
                        result["security_check"]["alert"] = {
                            "id": alert.id,
                            "severity": alert.severity,
                            "threat_type": alert.threat_type.value,
                            "title": alert.title,
                            "description": alert.description,
                            "false_positive_probability": alert.false_positive_probability
                        }

                        if fp_score:
                            result["security_check"]["false_positive_analysis"] = {
                                "probability": fp_score.false_positive_probability,
                                "recommended_action": fp_score.recommended_action,
                                "reasoning": fp_score.reasoning
                            }

                        # Store alert
                        alert_data = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "user_id": user_id,
                            "session_id": session_id,
                            "alert": alert,
                            "message": message,
                            "src_ip": user_ip,
                            "fp_score": fp_score
                        }
                        self.soc_alerts.append(alert_data)
                        if len(self.soc_alerts) > MAX_CACHED_ALERTS:
                            self.soc_alerts = self.soc_alerts[-MAX_CACHED_ALERTS:]

                        # Emit workflow logs BEFORE any blocking
                        self._emit_workflow_log(
                            agent='SOC Builder',
                            action=f'Threat detected: {alert.title}',
                            log_type='danger',
                            details=f'Severity: {alert.severity} | Threat Type: {alert.threat_type.value}',
                            session_id=session_id
                        )

                        recommended_action = fp_score.recommended_action if fp_score else "monitor"
                        fp_prob = fp_score.false_positive_probability if fp_score else 0.0

                        self._emit_workflow_log(
                            agent='SOC Analyst',
                            action='Analyzing threat and determining response',
                            log_type='warning',
                            details=f'False Positive: {fp_prob*100:.1f}% | Recommended: {recommended_action}',
                            session_id=session_id
                        )

                        # Take remediation action
                        remediation_result = self._take_remediation_action(
                            alert, fp_score, user_id, session_id, user_ip, auto_remediation
                        )

                        if remediation_result:
                            result["security_check"]["remediation_taken"] = remediation_result.get("action_taken", False)
                            result["security_check"]["remediation_actions"] = remediation_result.get("actions", [])

                        # Emit security alert via WebSocket
                        self._emit_security_alert(
                            alert=alert,
                            user_id=user_id,
                            session_id=session_id,
                            user_ip=user_ip,
                            fp_prob=fp_prob,
                            recommended_action=recommended_action,
                            remediation_result=remediation_result
                        )

                        # Check if should block response
                        if remediation_result and remediation_result.get("blocked"):
                            result["security_check"]["blocked"] = True
                            result["security_check"]["block_reason"] = remediation_result.get("block_reason")
                            result["response"] = "Your request has been blocked due to security policy violations."
                            self.logger.warning(f"[BLOCKED] Blocked message from {user_ip}: {message[:50]}")
                            return result

                        # Special handling for sophisticated detector alerts
                        # These are fallback detections with high confidence patterns
                        detection_layer = alert.evidence.get("detection_layer", "") if alert.evidence else ""
                        is_sophisticated = "fallback_sophisticated" in detection_layer or "sophisticated" in detection_layer

                        should_block_response = False

                        if is_sophisticated:
                            # Sophisticated detector with confidence >= 0.6 → BLOCK
                            sophist_confidence = alert.evidence.get("confidence", 0) if alert.evidence else 0
                            if sophist_confidence >= 0.6:
                                should_block_response = True
                                self.logger.info(f"Blocking sophisticated attack: {alert.title} (Confidence: {sophist_confidence:.0%}, Severity: {alert.severity})")
                            # Medium confidence (0.5-0.6) + high severity → BLOCK
                            elif sophist_confidence >= 0.5 and alert.severity in ["high", "critical"]:
                                should_block_response = True
                                self.logger.info(f"Blocking sophisticated high-severity attack: {alert.title} (Confidence: {sophist_confidence:.0%})")
                        elif alert.threat_type.value == "prompt_injection":
                            if fp_prob < FALSE_POSITIVE_BLOCK_PROMPT_INJECTION:
                                should_block_response = True
                                self.logger.info(f"Blocking prompt injection: {alert.title} (FP: {fp_prob:.2%})")
                        elif alert.severity in ["high", "critical"]:
                            if fp_prob < FALSE_POSITIVE_BLOCK_HIGH_SEVERITY:
                                should_block_response = True
                                self.logger.info(f"Blocking high/critical threat: {alert.title} (FP: {fp_prob:.2%})")

                        if should_block_response:
                            result["response"] = "I cannot process this request due to security restrictions."
                            result["security_check"]["blocked"] = True
                            result["security_check"]["block_reason"] = f"Security threat detected: {alert.title}"
                            self.logger.warning(f"[BLOCKED] BLOCKED threat from {user_ip}: {alert.title} (Severity: {alert.severity}, FP: {fp_prob:.2%})")
                            self._store_chat_history(session_id, message, result)
                            return result

                        self.logger.warning(
                            f"🚨 SECURITY ALERT: {alert.severity.upper()} - {alert.title} (FP: {fp_prob:.2%})"
                        )

                except Exception as e:
                    self.logger.error(f"SOC analysis error: {e}", exc_info=True)

            # Step 5: Generate AI response (only if not blocked)
            if not result["security_check"]["blocked"]:
                try:
                    ai_response = self.ai_integration.generate_response(
                        prompt=message,
                        user_id=user_id,
                        session_id=session_id,
                        security_mode=security_mode,
                        max_tokens=500,
                        temperature=0.7
                    )

                    ai_response_text = ai_response.get("response", "")
                    result["response"] = ai_response_text if ai_response_text else "I couldn't generate a response. Please try again."
                    result["interaction_id"] = ai_response.get("interaction_id", "")
                    result["ai_stats"] = {
                        "tokens_used": ai_response.get("tokens_used", 0),
                        "cost": ai_response.get("cost", 0.0),
                        "response_time": ai_response.get("response_time", 0.0),
                        "model": ai_response.get("model", "unknown")
                    }
                except Exception as e:
                    self.logger.error(f"AI integration error: {e}", exc_info=True)
                    result["response"] = "I encountered an error. Please try again."
                    result["error"] = "AI service unavailable"

            # Step 6: Store chat history
            self._store_chat_history(session_id, message, result)

            return result

        except Exception as e:
            self.logger.error(f"Error processing chat message: {e}", exc_info=True)
            result["response"] = "I apologize, but I encountered an error processing your request."
            result["error"] = str(e)
            return result

    def _take_remediation_action(
        self,
        alert: Alert,
        fp_score: Any,
        user_id: str,
        session_id: str,
        user_ip: str,
        auto_remediation: bool = False
    ) -> Dict[str, Any]:
        """
        Take remediation action based on mode.

        AUTO MODE: Immediately block IP and terminate session
        MANUAL MODE: Only create remediation plan (requires user approval)

        Args:
            alert: Security alert
            fp_score: False positive analysis score
            user_id: User identifier
            session_id: Session identifier
            user_ip: User's IP address
            auto_remediation: If True, execute immediately; if False, require approval

        Returns:
            dict with remediation result
        """
        result = {
            "action_taken": False,
            "actions": [],
            "blocked": False,
            "block_reason": None,
            "pending_approval": False
        }

        try:
            recommended_action = fp_score.recommended_action if fp_score else "block"
            fp_probability = fp_score.false_positive_probability if fp_score else 0.0

            # ONLY ignore if it's an extremely high false positive
            if fp_probability > FALSE_POSITIVE_IGNORE_THRESHOLD:
                self.logger.info(f"Alert {alert.id} ignored - extremely high false positive: {fp_probability:.2%}")
                result["action_taken"] = True
                result["actions"].append({
                    "type": "monitor",
                    "description": f"High false positive ({fp_probability:.0%}) - monitoring only"
                })
                return result

            # Determine remediation strategy based on severity
            severity = alert.severity.lower()

            # high/critical → block IP + terminate session
            # medium/low → rate limit + monitor
            if severity in ['high', 'critical']:
                action_type = "block_ip"
                action_description = "Block IP and Terminate Session"
            else:  # medium, low
                action_type = "rate_limit"
                action_description = "Apply Rate Limit and Monitor"

            # SOC Analyst creates remediation plan
            mode_text = "AUTO MODE" if auto_remediation else "MANUAL MODE"
            action_text = "Executing immediately" if auto_remediation else "Requesting user approval"

            self._emit_workflow_log(
                agent='SOC Analyst',
                action=f'Remediation plan created ({mode_text})',
                log_type='danger',
                details=f'Severity: {alert.severity.upper()} | FP: {fp_probability:.0%} | Action: {action_description} | {action_text}',
                session_id=session_id
            )

            # MANUAL MODE: Don't execute, just propose
            if not auto_remediation:
                self.logger.info(f"MANUAL MODE: Remediation pending approval for alert {alert.id}")
                result["pending_approval"] = True

                if severity in ['high', 'critical']:
                    # Suggest block IP for high/critical
                    result["actions"].append({
                        "type": "block_ip",
                        "target": user_ip,
                        "description": "IP block proposed (awaiting approval)",
                        "pending": True
                    })
                    result["actions"].append({
                        "type": "terminate_session",
                        "target": session_id,
                        "description": "Session termination proposed (awaiting approval)",
                        "pending": True
                    })
                else:
                    # Suggest rate limit for medium/low
                    result["actions"].append({
                        "type": "rate_limit",
                        "target": user_ip,
                        "description": "Rate limit proposed (awaiting approval)",
                        "pending": True
                    })
                    result["actions"].append({
                        "type": "monitor",
                        "target": session_id,
                        "description": "Enhanced monitoring proposed (awaiting approval)",
                        "pending": True
                    })
                return result

            # AUTO MODE: Execute immediately
            self.logger.info(f"AUTO MODE: Executing remediation for alert {alert.id}")
            result["action_taken"] = True

            if severity in ['high', 'critical']:
                # HIGH/CRITICAL: BLOCK IP ADDRESS
                self.real_remediator.block_ip(
                    user_ip,
                    reason=f"{alert.severity.upper()} threat: {alert.title}",
                    duration=DEFAULT_IP_BLOCK_DURATION_SECONDS,
                    alert_id=alert.id
                )
                result["actions"].append({
                    "type": "block_ip",
                    "target": user_ip,
                    "description": "IP blocked for 1 hour"
                })
                result["blocked"] = True
                result["block_reason"] = f"{alert.severity.upper()} security threat detected: {alert.title}"

                self._emit_workflow_log(
                    agent='Remediator',
                    action='IP address blocked',
                    log_type='danger',
                    details=f'Target: {user_ip} | Duration: 1 hour | Reason: {alert.title}',
                    session_id=session_id
                )

                # TERMINATE SESSION
                self.real_remediator.terminate_session(
                    session_id,
                    reason=f"Security threat: {alert.title}",
                    alert_id=alert.id
                )
                result["actions"].append({
                    "type": "terminate_session",
                    "target": session_id,
                    "description": "Session terminated"
                })

                self._emit_workflow_log(
                    agent='Remediator',
                    action='Session terminated',
                    log_type='danger',
                    details=f'Session: {session_id} | Reason: {alert.title}',
                    session_id=session_id
                )
            else:
                # MEDIUM/LOW: RATE LIMIT
                # Note: Rate limiting is handled by Flask-Limiter automatically
                # Just log and monitor
                result["actions"].append({
                    "type": "rate_limit",
                    "target": user_ip,
                    "description": "Rate limit applied"
                })
                result["actions"].append({
                    "type": "monitor",
                    "target": session_id,
                    "description": "Enhanced monitoring enabled"
                })

                self._emit_workflow_log(
                    agent='Remediator',
                    action='Rate limit applied',
                    log_type='warning',
                    details=f'Target: {user_ip} | Enhanced monitoring for session: {session_id}',
                    session_id=session_id
                )

            return result

        except Exception as e:
            self.logger.error(f"Error in _take_remediation_action: {e}", exc_info=True)
            return result

    def _fuse_verdicts(
        self,
        intelligent_alert: Optional[Alert],
        formal_alert: Optional[Alert],
        semantic_alert: Optional[Alert],
        ml_alert: Optional[Alert],
        detection_methods: List[str],
        session_id: str,
        message: str = ""
    ) -> Optional[Alert]:
        """
        Fuse verdicts from multiple detection layers.

        FIX V4: TRUST FORMAL V5.2 si haute certainty (>0.85)
        FIX V5: Add semantic_alert layer for Authority + Logical Traps
        FIX V7: Add ml_alert layer for ML Ensemble (XGBoost + Embeddings + PromptSleuth)

        Priority:
        0. FORMAL HIGH CERTAINTY (>0.85) - TRUST IT (best performer standalone)
        1. CONSENSUS (multiple detectors) - highest confidence, true positive
        2. INTELLIGENT_ONLY - pattern-based attack (LLM has educational context)
        3. FORMAL_ONLY - TRUST INTELLIGENT (likely educational context FP)
        4. NONE - safe

        Key insight: When Intelligent says SAFE but Formal detects,
        it's usually educational context (e.g., "explain 'ignore instructions'").
        We TRUST the Intelligent detector's educational context awareness.

        Args:
            intelligent_alert: Alert from intelligent detector (LLM-based)
            formal_alert: Alert from formal analyzer (proof-based)
            semantic_alert: Alert from semantic detector (scoring-based)
            ml_alert: Alert from ML Ensemble (ML-based)
            detection_methods: List of detection methods that fired
            session_id: Session identifier for logging

        Returns:
            Fused alert or None if all layers agree it's safe
        """

        # Case 0: TRUST FORMAL V5.2 with high certainty (NEW!)
        # Formal V5.2 standalone: 62% detection, 11.2% FPR (best individual performer)
        if formal_alert and formal_alert.evidence.get('certainty', 0) >= 0.85:
            self.logger.warning(
                f"[TRUST_FORMAL] High certainty detection | "
                f"Certainty: {formal_alert.evidence.get('certainty', 0):.0%} | "
                f"Verdict: {formal_alert.evidence.get('verdict', 'UNKNOWN')}"
            )
            # Trust Formal V5.2 - it's our best standalone detector
            return formal_alert

        # Case 1: CONSENSUS - Multiple detectors agreed
        if intelligent_alert and formal_alert:
            num_detectors = 2
            if semantic_alert:
                num_detectors += 1
            if ml_alert:
                num_detectors += 1

            log_msg = (
                f"[CONSENSUS] {num_detectors} detectors agreed | "
                f"Intelligent: {intelligent_alert.severity} | "
                f"Formal: {formal_alert.severity} ({formal_alert.evidence.get('certainty', 0):.0%})"
            )
            if semantic_alert:
                log_msg += f" | Semantic: {semantic_alert.severity} (score: {semantic_alert.confidence:.2f})"
            if ml_alert:
                log_msg += f" | ML: {ml_alert.severity} (conf: {ml_alert.confidence:.2f})"

            self.logger.warning(log_msg)

            # Use the more severe alert as base
            alerts = [intelligent_alert, formal_alert]
            if semantic_alert:
                alerts.append(semantic_alert)
            if ml_alert:
                alerts.append(ml_alert)

            # Select alert with highest severity
            severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
            base_alert = max(alerts, key=lambda a: severity_order.get(a.severity, 0))

            # Boost certainty due to consensus - halve FP probability for 2 detectors, quarter for 3, 1/8 for 4
            if num_detectors == 2:
                fp_reduction = 0.5
            elif num_detectors == 3:
                fp_reduction = 0.25
            else:  # 4 detectors
                fp_reduction = 0.125

            base_alert.false_positive_probability = min([
                a.false_positive_probability for a in alerts
            ]) * fp_reduction

            # Combine evidence from all detectors
            if not hasattr(base_alert, 'evidence') or base_alert.evidence is None:
                base_alert.evidence = {}

            base_alert.evidence["detection_consensus"] = True
            base_alert.evidence["num_detectors_agreed"] = num_detectors
            base_alert.evidence["intelligent_evidence"] = intelligent_alert.evidence if hasattr(intelligent_alert, 'evidence') else {}
            base_alert.evidence["formal_evidence"] = formal_alert.evidence if hasattr(formal_alert, 'evidence') else {}
            if semantic_alert:
                base_alert.evidence["semantic_evidence"] = semantic_alert.evidence if hasattr(semantic_alert, 'evidence') else {}
            if ml_alert:
                base_alert.evidence["ml_evidence"] = ml_alert.evidence if hasattr(ml_alert, 'evidence') else {}

            # PRIORITY 3 FIX: Confidence amplification
            confidence_boost = 1.0
            original_fp = base_alert.false_positive_probability

            # Boost 1: Multiple layer agreement (already done above with 0.5x)
            # Additional boost for 3+ detection methods
            if len(detection_methods) >= 3:
                confidence_boost *= 1.2  # +20% for triple agreement

            # Boost 2: High certainty from Formal V5.2
            if formal_alert and formal_alert.evidence.get('certainty', 0) >= 0.90:
                confidence_boost *= 1.2  # +20% for high certainty

            # Boost 3: PromptSleuth confirmation
            if any('promptsleuth' in method.lower() for method in detection_methods):
                confidence_boost *= 1.25  # +25% for PromptSleuth

            # Boost 4: ML Ensemble high confidence (V7)
            if ml_alert and ml_alert.confidence >= 0.8:
                confidence_boost *= 1.2  # +20% for high ML confidence

            # Apply additional boost
            if confidence_boost > 1.0:
                base_alert.false_positive_probability = max(
                    0.05,  # Floor at 5%
                    base_alert.false_positive_probability / confidence_boost
                )

                self.logger.info(
                    f"[CONFIDENCE_BOOST] FP: {original_fp:.2f} → "
                    f"{base_alert.false_positive_probability:.2f} (boost: {confidence_boost:.2f}x)"
                )

            # Emit consensus workflow log
            self._emit_workflow_log(
                agent='Verdict Fusion',
                action='CONSENSUS DETECTION',
                log_type='danger',
                details=f'Both layers detected threat | High confidence | Methods: {", ".join(detection_methods)} | FP reduced to {base_alert.false_positive_probability*100:.0f}%',
                session_id=session_id
            )

            return base_alert

        # Case 1.5: ML + Other layer(s) (no Intelligent+Formal consensus)
        # ML can detect with Semantic or alone
        elif ml_alert and (semantic_alert or intelligent_alert or formal_alert):
            num_detectors = 1  # ML
            alerts = [ml_alert]

            if semantic_alert:
                num_detectors += 1
                alerts.append(semantic_alert)
            if intelligent_alert and not formal_alert:
                num_detectors += 1
                alerts.append(intelligent_alert)
            elif formal_alert and not intelligent_alert:
                num_detectors += 1
                alerts.append(formal_alert)

            if num_detectors >= 2:
                self.logger.warning(
                    f"[ML_CONSENSUS] {num_detectors} detectors (including ML) | "
                    f"ML: {ml_alert.severity} (conf: {ml_alert.confidence:.2f}) | "
                    f"Methods: {', '.join(detection_methods)}"
                )

                # Select alert with highest severity
                severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
                base_alert = max(alerts, key=lambda a: severity_order.get(a.severity, 0))

                # Reduce FP probability
                fp_reduction = 0.4  # ML + 1 other layer
                base_alert.false_positive_probability = min([
                    a.false_positive_probability for a in alerts
                ]) * fp_reduction

                # Combine evidence
                if not hasattr(base_alert, 'evidence') or base_alert.evidence is None:
                    base_alert.evidence = {}

                base_alert.evidence["detection_consensus"] = True
                base_alert.evidence["num_detectors_agreed"] = num_detectors
                base_alert.evidence["ml_led_consensus"] = True

                # Add evidence from all detectors
                if ml_alert:
                    base_alert.evidence["ml_evidence"] = ml_alert.evidence if hasattr(ml_alert, 'evidence') else {}
                if semantic_alert:
                    base_alert.evidence["semantic_evidence"] = semantic_alert.evidence if hasattr(semantic_alert, 'evidence') else {}
                if intelligent_alert:
                    base_alert.evidence["intelligent_evidence"] = intelligent_alert.evidence if hasattr(intelligent_alert, 'evidence') else {}
                if formal_alert:
                    base_alert.evidence["formal_evidence"] = formal_alert.evidence if hasattr(formal_alert, 'evidence') else {}

                self._emit_workflow_log(
                    agent='Verdict Fusion',
                    action='ML-LED CONSENSUS',
                    log_type='danger' if ml_alert.confidence >= 0.8 else 'warning',
                    details=f'{num_detectors} layers agreed (ML + others) | FP: {base_alert.false_positive_probability*100:.0f}%',
                    session_id=session_id
                )

                return base_alert

        # Case 2: INTELLIGENT ONLY - Pattern-based (TRUST IT)
        elif intelligent_alert and not formal_alert:
            self.logger.warning(
                f"[INTELLIGENT_ONLY] Pattern-based threat | "
                f"Severity: {intelligent_alert.severity}"
            )

            if not hasattr(intelligent_alert, 'evidence') or intelligent_alert.evidence is None:
                intelligent_alert.evidence = {}
            intelligent_alert.evidence["detection_layer"] = "intelligent_only"

            self._emit_workflow_log(
                agent='Verdict Fusion',
                action='INTELLIGENT ONLY Detection',
                log_type='warning',
                details=f'Pattern-based threat | Severity: {intelligent_alert.severity}',
                session_id=session_id
            )

            return intelligent_alert

        # Case 3: FORMAL ONLY - Decision depends on analyzer version
        # V5.2 has educational context detection built-in, so TRUST V5.2
        # V4 lacks educational context, so trust Intelligent Detector
        elif formal_alert and not intelligent_alert:
            detection_method = formal_alert.evidence.get("detection_method", "")

            # V5.2: Analyse de désaccord avec PromptSleuth arbitrage
            if "v5.2" in detection_method.lower():
                certainty = formal_alert.evidence.get("certainty", 0)
                verdict = formal_alert.evidence.get("verdict", "UNKNOWN")

                # Fort signal (>= 90%) → TRUST V5.2 directement
                if certainty >= 0.90:
                    self.logger.warning(
                        f"[FORMAL_V5.2_HIGH_CERTAINTY] Strong signal ({certainty:.0%}) | "
                        f"Verdict: {verdict} | TRUSTING V5.2"
                    )

                    self._emit_workflow_log(
                        agent='Verdict Fusion',
                        action='Strong V5.2 Signal',
                        log_type='danger',
                        details=f'High certainty ({certainty:.0%}) → Trust V5.2 | {verdict}',
                        session_id=session_id
                    )

                    if not hasattr(formal_alert, 'evidence') or formal_alert.evidence is None:
                        formal_alert.evidence = {}
                    formal_alert.evidence["detection_layer"] = "formal_v5.2_high_certainty"
                    return formal_alert

                # Signal ambigu (< 90%) → ARBITRAGE PAR PROMPTSLEUTH
                else:
                    self.logger.info(
                        f"[DÉSACCORD_AMBIGU] Intelligent=SAFE vs Formal={verdict} "
                        f"(certainty: {certainty:.0%}) | Calling PromptSleuth arbitre..."
                    )

                    # Appeler PromptSleuth comme arbitre
                    sleuth_result = self._arbitrate_with_promptsleuth(
                        message=message,
                        formal_alert=formal_alert,
                        session_id=session_id
                    )

                    return sleuth_result

            # V4: TRUST INTELLIGENT (V4 lacks educational context detection)
            else:
                self.logger.info(
                    f"[FORMAL_V4_DISMISSED] V4 detected but Intelligent said SAFE | "
                    f"Verdict: {formal_alert.evidence.get('verdict')} | "
                    f"Likely educational context - TRUSTING INTELLIGENT"
                )

                self._emit_workflow_log(
                    agent='Verdict Fusion',
                    action='Educational Context Detected (V4)',
                    log_type='info',
                    details=f'V4 detected pattern but Intelligent said SAFE | Verdict: {formal_alert.evidence.get("verdict")} | Classified as educational/safe',
                    session_id=session_id
                )

                # Trust Intelligent - return None (SAFE)
                return None

        # Case 3.5: SEMANTIC ONLY - Scored attack pattern (FIX V5: Authority + Logical Traps)
        elif semantic_alert and not intelligent_alert and not formal_alert:
            self.logger.warning(
                f"[SEMANTIC_ONLY] Scoring system detected attack | "
                f"Score: {semantic_alert.confidence:.2f} | "
                f"Severity: {semantic_alert.severity}"
            )

            if not hasattr(semantic_alert, 'evidence') or semantic_alert.evidence is None:
                semantic_alert.evidence = {}
            semantic_alert.evidence["detection_layer"] = "semantic_only"

            self._emit_workflow_log(
                agent='Verdict Fusion',
                action='SEMANTIC ONLY Detection',
                log_type='warning' if semantic_alert.severity == "medium" else 'danger',
                details=f'Scored pattern | Score: {semantic_alert.confidence:.2f} | Severity: {semantic_alert.severity}',
                session_id=session_id
            )

            return semantic_alert

        # Case 4: NONE - Fallback to Sophisticated Detector
        # When all primary detectors say SAFE, check for sophisticated attacks
        # This is the last-resort detector for indirect/subtle injections
        else:
            # Call sophisticated detector (free, <10ms)
            start_time = time.time()
            sophisticated_result = self.sophisticated_detector.detect(message)
            elapsed_ms = (time.time() - start_time) * 1000

            # Update metrics
            self.sophisticated_detector_metrics["calls"] += 1
            self.sophisticated_detector_metrics["total_time"] += elapsed_ms
            self.sophisticated_detector_metrics["avg_time_ms"] = (
                self.sophisticated_detector_metrics["total_time"] /
                self.sophisticated_detector_metrics["calls"]
            )

            if sophisticated_result.is_suspicious:
                self.sophisticated_detector_metrics["detections"] += 1

                self.logger.warning(
                    f"[SOPHISTICATED_FALLBACK] Detected subtle attack | "
                    f"Confidence: {sophisticated_result.confidence:.0%} | "
                    f"Type: {sophisticated_result.threat_type} | "
                    f"Severity: {sophisticated_result.severity}"
                )

                # Create alert from sophisticated detector result
                from shared.models import ThreatType

                threat_type_map = {
                    "Indirect System Extraction": ThreatType.DATA_EXFILTRATION,
                    "Meta-Cognitive Query": ThreatType.PROMPT_INJECTION,
                    "Authority Impersonation": ThreatType.PROMPT_INJECTION,
                    "Negative Framing": ThreatType.PROMPT_INJECTION,
                    "Hypothetical Scenario": ThreatType.PROMPT_INJECTION,
                    "Research Pretext": ThreatType.PROMPT_INJECTION,
                    "Dual Request": ThreatType.PROMPT_INJECTION,
                    "Comparative Extraction": ThreatType.DATA_EXFILTRATION,
                    "Fragmented Request": ThreatType.PROMPT_INJECTION
                }

                sophisticated_alert = Alert(
                    id=f"AL-{int(time.time() * 1000)}-SOPHIST",
                    timestamp=time.time(),
                    severity=sophisticated_result.severity,
                    title=f"Sophisticated Injection: {sophisticated_result.threat_type}",
                    description=f"Fallback detector | Confidence: {sophisticated_result.confidence:.0%} | Patterns: {', '.join(sophisticated_result.matched_patterns[:2])}",
                    threat_type=threat_type_map.get(sophisticated_result.threat_type, ThreatType.PROMPT_INJECTION),
                    false_positive_probability=1.0 - sophisticated_result.confidence,
                    evidence={
                        "detection_method": "sophisticated_injection_detector",
                        "detection_layer": "fallback_sophisticated",
                        "confidence": sophisticated_result.confidence,
                        "threat_type": sophisticated_result.threat_type,
                        "matched_patterns": sophisticated_result.matched_patterns,
                        "latency_ms": elapsed_ms
                    }
                )

                # URGENT FIX 3: Apply False Positive Detector to Sophisticated layer
                # Check if this is a legitimate technical/educational query
                from shared.models import SecurityLog
                temp_log = SecurityLog(
                    session_id=session_id,
                    timestamp=time.time(),
                    user_ip="127.0.0.1",
                    message=message,
                    alert=sophisticated_alert
                )
                fp_result = self.false_positive_detector.analyze_alert(temp_log)

                # If FP detector recommends ignoring, suppress the alert
                if fp_result.recommended_action == "ignore":
                    self.logger.info(
                        f"[FP_SUPPRESSION] Sophisticated alert suppressed as false positive | "
                        f"FP Probability: {fp_result.false_positive_probability:.0%} | "
                        f"Reason: {fp_result.reasoning[0] if fp_result.reasoning else 'Legitimate query'}"
                    )
                    return None

                # Update alert with FP analysis
                sophisticated_alert.false_positive_probability = fp_result.false_positive_probability

                # Emit workflow log
                self._emit_workflow_log(
                    agent='Sophisticated Detector (Fallback)',
                    action=f'Detected: {sophisticated_result.threat_type}',
                    log_type='warning',
                    details=f'Confidence: {sophisticated_result.confidence:.0%} | Severity: {sophisticated_result.severity} | Patterns: {", ".join(sophisticated_result.matched_patterns[:2])} | Latency: {elapsed_ms:.2f}ms',
                    session_id=session_id
                )

                return sophisticated_alert
            else:
                # Truly safe
                self.logger.debug(f"[ALL_SAFE] No threats detected by any layer (including sophisticated detector)")
                return None

    def _emit_workflow_log(
        self,
        agent: str,
        action: str,
        log_type: str,
        details: str,
        session_id: str
    ):
        """Emit workflow log via WebSocket if socketio is available."""
        if self.socketio:
            self.socketio.emit('workflow_log', {
                'agent': agent,
                'action': action,
                'type': log_type,
                'details': details,
                'timestamp': datetime.utcnow().isoformat()
            }, room=session_id)

    def _emit_security_alert(
        self,
        alert: Alert,
        user_id: str,
        session_id: str,
        user_ip: str,
        fp_prob: float,
        recommended_action: str,
        remediation_result: Optional[Dict[str, Any]]
    ):
        """Emit security alert via WebSocket if socketio is available."""
        if self.socketio:
            # Extract LLM explanation from alert evidence
            llm_explanation = ""
            if alert.evidence:
                llm_explanation = alert.evidence.get("llm_explanation", "")

            self.socketio.emit('security_alert', {
                'alert_id': alert.id,
                'rule_id': alert.rule_id,
                'severity': alert.severity,
                'threat_type': alert.threat_type.value,
                'title': alert.title,
                'description': alert.description,
                'timestamp': datetime.utcnow().isoformat(),
                'user_id': user_id,
                'session_id': session_id,
                'src_ip': user_ip,
                'false_positive_probability': fp_prob,
                'recommended_action': recommended_action,
                'llm_explanation': llm_explanation,  # Add LLM explanation
                'remediation_taken': remediation_result.get("action_taken", False) if remediation_result else False,
                'remediation_actions': remediation_result.get("actions", []) if remediation_result else []
            }, room=session_id)

    def _store_chat_history(self, session_id: str, message: str, result: Dict[str, Any]):
        """Store chat history with size limits."""
        if session_id not in self.chat_history:
            self.chat_history[session_id] = []

        self.chat_history[session_id].append({
            "timestamp": datetime.utcnow().isoformat(),
            "message": message,
            "response": result.get("response", ""),
            "security_check": result.get("security_check", {})
        })

        # Keep only last N messages per session
        if len(self.chat_history[session_id]) > MAX_CHAT_HISTORY_PER_SESSION:
            self.chat_history[session_id] = self.chat_history[session_id][-MAX_CHAT_HISTORY_PER_SESSION:]

    def toggle_soc(self, enabled: bool) -> Dict[str, Any]:
        """Enable or disable SOC monitoring."""
        self.soc_enabled = enabled
        self.logger.info(f"SOC monitoring {'enabled' if enabled else 'disabled'}")
        return {
            "success": True,
            "soc_enabled": self.soc_enabled,
            "message": f"SOC monitoring {'enabled' if enabled else 'disabled'}"
        }

    def _arbitrate_with_promptsleuth(
        self,
        message: str,
        formal_alert,
        session_id: str
    ):
        """
        Arbitre un désaccord avec PromptSleuth.

        [WARNING] RÈGLES CRITIQUES:
        - Ne regarde PAS les secrets
        - N'est appelé QUE sur désaccord ambigu
        - Ne modifie JAMAIS une alerte consensuelle

        Args:
            message: Prompt utilisateur
            formal_alert: Alerte du Formal Analyzer
            session_id: ID de session

        Returns:
            Alert si injection confirmée/ambiguë, None si SAFE
        """
        import re
        import hashlib

        # Vérifier disponibilité
        if not self.prompt_sleuth_enabled or not self.prompt_sleuth:
            self.logger.warning("[PROMPTSLEUTH_UNAVAILABLE] Fallback to V5.2")
            self._emit_workflow_log(
                agent='PromptSleuth Arbitre',
                action='Unavailable - Fallback to V5.2',
                log_type='warning',
                details='PromptSleuth not initialized',
                session_id=session_id
            )
            return formal_alert  # Fallback

        # Whitelist check
        for pattern in self.promptsleuth_bypass_patterns:
            if re.match(pattern, message.lower()):
                self.logger.info(f"[PROMPTSLEUTH_BYPASS] Pattern whitelisted: {pattern}")
                self.promptsleuth_metrics["bypassed"] += 1

                self._emit_workflow_log(
                    agent='PromptSleuth Arbitre',
                    action='Bypassed (Whitelist)',
                    log_type='success',
                    details=f'Pattern matches whitelist: {pattern}',
                    session_id=session_id
                )

                return None  # SAFE

        # Check cache
        current_time = time.time()
        prompt_hash = hashlib.md5(message.encode()).hexdigest()

        if prompt_hash in self.promptsleuth_cache:
            cache_entry = self.promptsleuth_cache[prompt_hash]
            cache_age = current_time - cache_entry[1]

            if cache_age < self.promptsleuth_cache_ttl:
                self.promptsleuth_metrics["cache_hits"] += 1
                self.logger.info(f"[PROMPTSLEUTH_CACHE_HIT] Age: {cache_age:.0f}s")

                cached_result = cache_entry[0]

                self._emit_workflow_log(
                    agent='PromptSleuth Arbitre',
                    action='Cache Hit',
                    log_type='info',
                    details=f'Using cached result | Decision: {cached_result["action"]}',
                    session_id=session_id
                )

                return self._process_sleuth_verdict(cached_result, formal_alert, session_id)

        # Cache miss
        self.promptsleuth_metrics["cache_misses"] += 1

        # Appeler PromptSleuth
        try:
            start_time = time.time()

            self._emit_workflow_log(
                agent='PromptSleuth Arbitre',
                action='Analyzing Disagreement',
                log_type='warning',
                details=f'Intelligent=SAFE vs Formal={formal_alert.evidence.get("verdict")} ({formal_alert.evidence.get("certainty", 0):.0%})',
                session_id=session_id
            )

            # System prompt générique (ne révèle PAS de secrets)
            system_prompt = "You are a helpful AI assistant. Follow instructions carefully and be helpful."

            result = self.prompt_sleuth.check_prompt(
                system_prompt=system_prompt,
                user_input=message
            )

            elapsed_time = time.time() - start_time

            # Métriques
            self.promptsleuth_metrics["calls"] += 1
            self.promptsleuth_metrics["total_time"] += elapsed_time
            self.promptsleuth_consecutive_errors = 0  # Reset errors

            self.logger.info(
                f"[PROMPTSLEUTH_RESULT] "
                f"is_injection={result.is_injection} | "
                f"confidence={result.confidence:.2f} | "
                f"suspicious={len(result.suspicious_tasks)} | "
                f"time={elapsed_time:.2f}s"
            )

            # Interpréter résultat
            sleuth_decision = self._interpret_sleuth_result(result)

            # Update métriques
            self.promptsleuth_metrics["verdicts"][sleuth_decision["action"].lower()] += 1

            # Cache
            self.promptsleuth_cache[prompt_hash] = (sleuth_decision, current_time)

            # Emit
            self._emit_workflow_log(
                agent='PromptSleuth Arbitre',
                action=f'Decision: {sleuth_decision["action"]}',
                log_type=sleuth_decision["log_type"],
                details=f'Confidence: {result.confidence:.0%} | Suspicious: {result.suspicious_tasks[:3]} | Time: {elapsed_time:.2f}s',
                session_id=session_id
            )

            return self._process_sleuth_verdict(sleuth_decision, formal_alert, session_id)

        except Exception as e:
            self.promptsleuth_metrics["errors"] += 1
            self.promptsleuth_consecutive_errors += 1

            self.logger.error(f"[PROMPTSLEUTH_ERROR] {e}")

            # Mode dégradé
            if self.promptsleuth_consecutive_errors >= self.promptsleuth_error_threshold:
                self.prompt_sleuth_enabled = False
                self.logger.error(
                    f"[PROMPTSLEUTH_DEGRADED] Disabling after "
                    f"{self.promptsleuth_consecutive_errors} consecutive errors"
                )

            self._emit_workflow_log(
                agent='PromptSleuth Arbitre',
                action='Error - Fallback to V5.2',
                log_type='warning',
                details=f'Error: {str(e)[:100]}',
                session_id=session_id
            )

            return formal_alert  # Fallback

    def _interpret_sleuth_result(self, result) -> dict:
        """Interpréter résultat PromptSleuth."""
        if not result.is_injection:
            # Pas d'injection → SAFE
            return {
                "action": "SAFE",
                "log_type": "success",
                "reason": "PromptSleuth: No injection pattern detected"
            }
        elif result.confidence < 0.7:
            # Injection faible confiance → WARNING
            return {
                "action": "WARNING",
                "log_type": "warning",
                "reason": f"PromptSleuth: Ambiguous (confidence: {result.confidence:.0%})"
            }
        else:
            # Injection bonne confiance → CONFIRM
            return {
                "action": "CONFIRM",
                "log_type": "danger",
                "reason": f"PromptSleuth: Injection confirmed (confidence: {result.confidence:.0%})"
            }

    def _process_sleuth_verdict(self, sleuth_decision: dict, formal_alert, session_id: str):
        """Traiter verdict PromptSleuth."""
        from shared.models import Alert

        action = sleuth_decision["action"]

        if action == "SAFE":
            # DOWNGRADE
            self.logger.info(
                f"[SLEUTH_DOWNGRADE] PromptSleuth arbitrage → SAFE | "
                f"Formal V5.2 likely false positive"
            )

            self._emit_workflow_log(
                agent='PromptSleuth Arbitre',
                action='DOWNGRADE to SAFE',
                log_type='success',
                details=f'{sleuth_decision["reason"]} | Formal alert dismissed',
                session_id=session_id
            )

            return None  # Pas d'alerte

        elif action == "WARNING":
            # AMBIGUOUS
            self.logger.warning(
                f"[SLEUTH_AMBIGUOUS] PromptSleuth uncertain | Creating WARNING alert"
            )

            # Réduire sévérité
            formal_alert.severity = "medium"
            formal_alert.title = f"[AMBIGUOUS] {formal_alert.title}"
            formal_alert.description = (
                f"[WARNING] Ambiguous pattern detected | "
                f"{sleuth_decision['reason']} | "
                f"Original: {formal_alert.description}"
            )
            formal_alert.false_positive_probability = 0.4

            if not hasattr(formal_alert, 'evidence') or formal_alert.evidence is None:
                formal_alert.evidence = {}
            formal_alert.evidence["promptsleuth_verdict"] = "ambiguous"
            formal_alert.evidence["detection_layer"] = "formal_v5.2_ambiguous"

            self._emit_workflow_log(
                agent='PromptSleuth Arbitre',
                action='WARNING Alert',
                log_type='warning',
                details=f'{sleuth_decision["reason"]} | Severity reduced to MEDIUM',
                session_id=session_id
            )

            return formal_alert

        else:  # CONFIRM
            # CONFIRM
            self.logger.warning(
                f"[SLEUTH_CONFIRM] PromptSleuth confirms injection | Trust V5.2"
            )

            # Augmenter confiance
            formal_alert.false_positive_probability *= 0.7

            if not hasattr(formal_alert, 'evidence') or formal_alert.evidence is None:
                formal_alert.evidence = {}
            formal_alert.evidence["promptsleuth_verdict"] = "confirmed"
            formal_alert.evidence["detection_layer"] = "formal_v5.2_confirmed"

            self._emit_workflow_log(
                agent='PromptSleuth Arbitre',
                action='CONFIRM Alert',
                log_type='danger',
                details=f'{sleuth_decision["reason"]} | Formal alert confirmed',
                session_id=session_id
            )

            return formal_alert

    def get_promptsleuth_metrics(self) -> dict:
        """
        Obtenir les métriques PromptSleuth.

        Returns:
            Dict avec métriques détaillées
        """
        if not hasattr(self, 'promptsleuth_metrics'):
            return {"error": "PromptSleuth not initialized"}

        metrics = self.promptsleuth_metrics.copy()

        # Calculer statistiques
        if metrics["calls"] > 0:
            metrics["avg_time_per_call"] = metrics["total_time"] / metrics["calls"]
            metrics["cache_hit_rate"] = metrics["cache_hits"] / (metrics["cache_hits"] + metrics["cache_misses"])
        else:
            metrics["avg_time_per_call"] = 0
            metrics["cache_hit_rate"] = 0

        metrics["enabled"] = self.prompt_sleuth_enabled
        metrics["cache_size"] = len(self.promptsleuth_cache) if hasattr(self, 'promptsleuth_cache') else 0

        return metrics

    def get_sophisticated_detector_metrics(self) -> dict:
        """
        Get Sophisticated Detector metrics.

        Returns:
            Dict with detailed metrics
        """
        if not hasattr(self, 'sophisticated_detector_metrics'):
            return {"error": "Sophisticated Detector not initialized"}

        metrics = self.sophisticated_detector_metrics.copy()

        # Add detection stats from the detector itself
        if hasattr(self, 'sophisticated_detector'):
            stats = self.sophisticated_detector.get_detection_stats()
            metrics.update(stats)

        # Calculate detection rate
        if metrics["calls"] > 0:
            metrics["detection_rate"] = metrics["detections"] / metrics["calls"]
        else:
            metrics["detection_rate"] = 0

        return metrics

    def get_statistics(self) -> Dict[str, Any]:
        """Get SOC statistics."""
        return {
            "soc_enabled": self.soc_enabled,
            "uptime": time.time() - self.start_time,
            "total_alerts": len(self.soc_alerts),
            "active_sessions": len(self.active_sessions),
            "chat_history_sessions": len(self.chat_history)
        }
