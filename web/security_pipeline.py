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
                model=os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')
            )
            self.fp_detector = FalsePositiveDetector()
            self.real_remediator = RealRemediationEngine()

            # Add intelligent prompt detector
            self.intelligent_detector = IntelligentPromptDetector(ai_integration=self.ai_integration)

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

            self.logger.info("✅ SOC Builder initialized successfully")

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize SOC Builder: {e}", exc_info=True)
            raise

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
                self.logger.warning(f"🚫 Blocked IP {user_ip} attempted access")
                return result

            if self.real_remediator.is_user_blocked(user_id):
                result["security_check"]["blocked"] = True
                result["security_check"]["block_reason"] = "User account is suspended"
                result["response"] = "Access denied: Your account has been suspended due to security violations."
                self.logger.warning(f"🚫 Blocked user {user_id} attempted access")
                return result

            if self.real_remediator.is_session_terminated(session_id):
                result["security_check"]["blocked"] = True
                result["security_check"]["block_reason"] = "Session has been terminated"
                result["response"] = "Access denied: Your session has been terminated due to security policy violations."
                self.logger.warning(f"🚫 Terminated session {session_id} attempted access")
                return result

            # Step 3: Check rate limiting (skip for test users)
            if user_id and not user_id.startswith("test_"):
                allowed, retry_after = self.real_remediator.check_rate_limit(user_ip, "ip")
                if not allowed:
                    result["security_check"]["blocked"] = True
                    result["security_check"]["block_reason"] = f"Rate limit exceeded. Retry after {retry_after:.0f}s"
                    result["response"] = f"Rate limit exceeded. Please wait {retry_after:.0f} seconds before trying again."
                    self.logger.warning(f"⏱️ Rate limit exceeded for IP {user_ip}")
                    return result

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

                    # Detect threats (intelligent detector first, then rule-based)
                    alert = None
                    try:
                        alert = self.intelligent_detector.detect_prompt_injection(temp_log)
                    except Exception as e:
                        self.logger.warning(f"Intelligent detection error: {e}")

                    if not alert:
                        alert = self.rules_engine.analyze_log(temp_log)

                    if alert:
                        # Analyze for false positives
                        fp_score = self.fp_detector.analyze_alert(
                            alert,
                            temp_log,
                            user_context={"session_id": session_id}
                        )

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
                            self.logger.warning(f"🚫 Blocked message from {user_ip}: {message[:50]}")
                            return result

                        # Aggressive blocking for prompt injections and high/critical threats
                        should_block_response = False
                        if alert.threat_type.value == "prompt_injection":
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
                            self.logger.warning(f"🚫 BLOCKED threat from {user_ip}: {alert.title} (Severity: {alert.severity}, FP: {fp_prob:.2%})")
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

            # SOC Analyst creates remediation plan
            mode_text = "AUTO MODE" if auto_remediation else "MANUAL MODE"
            action_text = "Executing immediately" if auto_remediation else "Requesting user approval"

            self._emit_workflow_log(
                agent='SOC Analyst',
                action=f'Remediation plan created ({mode_text})',
                log_type='danger',
                details=f'Severity: {alert.severity.upper()} | FP: {fp_probability:.0%} | Action: Block IP and Terminate Session | {action_text}',
                session_id=session_id
            )

            # MANUAL MODE: Don't execute, just propose
            if not auto_remediation:
                self.logger.info(f"MANUAL MODE: Remediation pending approval for alert {alert.id}")
                result["pending_approval"] = True
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
                return result

            # AUTO MODE: Execute immediately
            self.logger.info(f"AUTO MODE: Executing remediation for alert {alert.id}")
            result["action_taken"] = True

            # 1. BLOCK IP ADDRESS
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

            # 2. TERMINATE SESSION
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

            return result

        except Exception as e:
            self.logger.error(f"Error in _take_remediation_action: {e}", exc_info=True)
            return result

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

    def get_statistics(self) -> Dict[str, Any]:
        """Get SOC statistics."""
        return {
            "soc_enabled": self.soc_enabled,
            "uptime": time.time() - self.start_time,
            "total_alerts": len(self.soc_alerts),
            "active_sessions": len(self.active_sessions),
            "chat_history_sessions": len(self.chat_history)
        }
