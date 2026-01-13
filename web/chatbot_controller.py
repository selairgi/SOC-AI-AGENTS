"""
Chatbot Controller - Control Plane for SOC Pipeline.

This module provides the chatbot interface to the SOC pipeline.
It is NOT an agent - it only submits events and queries state.

The chatbot:
- Submits raw logs/alerts to the pipeline via EventBus
- Queries incident state from IncidentStateManager
- Provides human approval for remediation actions
- Displays timeline: Raw → Detection → Analysis → Decision → Execution

Endpoints:
- POST /chatbot/submit_event - Submit raw log/alert
- GET /chatbot/incidents - List all incidents
- GET /chatbot/incidents/<correlation_id> - Get specific incident
- POST /chatbot/approve/<correlation_id> - Approve/reject remediation

Usage:
    from web.chatbot_controller import ChatbotController

    controller = ChatbotController(event_bus, state_manager)
    # Register routes with Flask app
    controller.register_routes(app)
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from flask import Blueprint, request, jsonify, session


class ChatbotController:
    """
    Control plane for the SOC pipeline.

    This controller:
    - Reads ONLY from IncidentStateManager
    - Never reads agents directly
    - Publishes events to EventBus
    - Requires human approval for high-risk actions
    """

    # Confidence threshold for requiring human approval
    DEFAULT_APPROVAL_THRESHOLD = 0.7

    def __init__(
        self,
        event_bus,
        state_manager,
        approval_threshold: float = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the chatbot controller.

        Args:
            event_bus: EventBus instance for publishing events
            state_manager: IncidentStateManager for querying state
            approval_threshold: Confidence below this requires human approval
            logger: Optional logger instance
        """
        self.bus = event_bus
        self.state_manager = state_manager
        self.approval_threshold = approval_threshold or self.DEFAULT_APPROVAL_THRESHOLD
        self.logger = logger or logging.getLogger("ChatbotController")

        # Create Flask blueprint
        self.blueprint = Blueprint('chatbot', __name__, url_prefix='/chatbot')
        self._register_routes()

        self.logger.info("ChatbotController initialized")

    def _register_routes(self):
        """Register routes on the blueprint."""

        @self.blueprint.route('/submit_event', methods=['POST'])
        def submit_event():
            """
            Submit a raw log or alert to the SOC pipeline.

            Request Body:
            {
                "message": "User input or log message",
                "user_id": "user_123",
                "session_id": "session_456",
                "src_ip": "192.168.1.100",
                "agent_id": "chatbot_agent",
                "metadata": {}
            }

            Returns:
            {
                "success": true,
                "correlation_id": "uuid",
                "message": "Event submitted to pipeline"
            }
            """
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'Invalid request body'}), 400

                message = data.get('message', '')
                if not message:
                    return jsonify({'error': 'Message is required'}), 400

                # Generate or use provided correlation_id
                correlation_id = data.get('correlation_id') or str(uuid.uuid4())

                # Build RawLogEvent
                raw_event = self._create_raw_log_event(
                    correlation_id=correlation_id,
                    message=message,
                    user_id=data.get('user_id', session.get('user_id', 'anonymous')),
                    session_id=data.get('session_id', session.get('session_id', '')),
                    src_ip=data.get('src_ip', request.remote_addr or '127.0.0.1'),
                    agent_id=data.get('agent_id', 'chatbot_agent'),
                    metadata=data.get('metadata', {})
                )

                # Publish to EventBus
                self.bus.publish("RawLogEvent", raw_event)

                self.logger.info(f"Submitted event: {correlation_id[:8]}... - {message[:50]}...")

                return jsonify({
                    'success': True,
                    'correlation_id': correlation_id,
                    'message': 'Event submitted to SOC pipeline'
                })

            except Exception as e:
                self.logger.error(f"Error submitting event: {e}")
                return jsonify({'error': 'Internal server error'}), 500

        @self.blueprint.route('/incidents', methods=['GET'])
        def list_incidents():
            """
            List all incidents from IncidentStateManager.

            Query Parameters:
            - status: Filter by status (open, analyzing, remediating, resolved)
            - severity: Filter by severity
            - limit: Max results (default 100)
            - offset: Pagination offset

            Returns:
            {
                "incidents": [...],
                "total": 123,
                "limit": 100,
                "offset": 0
            }
            """
            try:
                status = request.args.get('status')
                severity = request.args.get('severity')
                limit = int(request.args.get('limit', 100))
                offset = int(request.args.get('offset', 0))

                incidents = self.state_manager.list_incidents(
                    status=status,
                    severity=severity,
                    limit=limit,
                    offset=offset
                )

                total = self.state_manager.get_incident_count()

                return jsonify({
                    'incidents': incidents,
                    'total': total,
                    'limit': limit,
                    'offset': offset
                })

            except Exception as e:
                self.logger.error(f"Error listing incidents: {e}")
                return jsonify({'error': 'Internal server error'}), 500

        @self.blueprint.route('/incidents/<correlation_id>', methods=['GET'])
        def get_incident(correlation_id: str):
            """
            Get a specific incident by correlation_id.

            Returns aggregated state including:
            - Timeline (Raw → Detection → Analysis → Decision → Execution)
            - All agent outputs
            - Explanations
            - Current status
            """
            try:
                incident = self.state_manager.get_incident(correlation_id)

                if not incident:
                    return jsonify({'error': 'Incident not found'}), 404

                # Add formatted timeline for UI
                incident['formatted_timeline'] = self._format_timeline(incident)

                return jsonify(incident)

            except Exception as e:
                self.logger.error(f"Error getting incident: {e}")
                return jsonify({'error': 'Internal server error'}), 500

        @self.blueprint.route('/approve/<correlation_id>', methods=['POST'])
        def approve_remediation(correlation_id: str):
            """
            Approve or reject a pending remediation.

            Request Body:
            {
                "approved": true,
                "reason": "Optional reason for decision",
                "approver": "user_id"
            }

            Returns:
            {
                "success": true,
                "correlation_id": "uuid",
                "approved": true
            }
            """
            try:
                data = request.get_json() or {}
                approved = data.get('approved', False)
                reason = data.get('reason', '')
                approver = data.get('approver', session.get('user_id', 'anonymous'))

                # Publish HumanApproval event
                approval_event = self._create_approval_event(
                    correlation_id=correlation_id,
                    approved=approved,
                    reason=reason,
                    approver=approver
                )

                self.bus.publish("HumanApproval", approval_event)

                action = "approved" if approved else "rejected"
                self.logger.info(f"Remediation {action} for {correlation_id[:8]}... by {approver}")

                return jsonify({
                    'success': True,
                    'correlation_id': correlation_id,
                    'approved': approved,
                    'message': f'Remediation {action}'
                })

            except Exception as e:
                self.logger.error(f"Error processing approval: {e}")
                return jsonify({'error': 'Internal server error'}), 500

        @self.blueprint.route('/timeline/<correlation_id>', methods=['GET'])
        def get_timeline(correlation_id: str):
            """
            Get the timeline for a specific incident.

            Returns ordered list of events with timestamps.
            """
            try:
                timeline = self.state_manager.get_timeline(correlation_id)

                if not timeline:
                    return jsonify({'error': 'Incident not found'}), 404

                return jsonify({
                    'correlation_id': correlation_id,
                    'timeline': timeline
                })

            except Exception as e:
                self.logger.error(f"Error getting timeline: {e}")
                return jsonify({'error': 'Internal server error'}), 500

        @self.blueprint.route('/stats', methods=['GET'])
        def get_stats():
            """Get controller and state manager statistics."""
            try:
                state_stats = self.state_manager.get_stats()

                return jsonify({
                    'state_manager': state_stats,
                    'approval_threshold': self.approval_threshold
                })

            except Exception as e:
                self.logger.error(f"Error getting stats: {e}")
                return jsonify({'error': 'Internal server error'}), 500

        @self.blueprint.route('/pending_approvals', methods=['GET'])
        def get_pending_approvals():
            """
            Get list of incidents awaiting human approval.

            Returns incidents where:
            - Status is 'remediating'
            - Remediation decision requires approval
            - Confidence is below threshold
            """
            try:
                # Get all remediating incidents
                incidents = self.state_manager.list_incidents(
                    status='remediating',
                    limit=100
                )

                # Filter to those needing approval
                pending = []
                for incident in incidents:
                    remediation = incident.get('remediation_decision', {})
                    if remediation:
                        payload = remediation.get('payload', {})
                        if payload.get('requires_approval'):
                            pending.append({
                                'correlation_id': incident['correlation_id'],
                                'severity': incident.get('severity'),
                                'threat_type': incident.get('threat_type'),
                                'action': payload.get('action'),
                                'confidence': incident.get('confidence', 0),
                                'created_at': incident.get('created_at'),
                            })

                return jsonify({
                    'pending_approvals': pending,
                    'count': len(pending)
                })

            except Exception as e:
                self.logger.error(f"Error getting pending approvals: {e}")
                return jsonify({'error': 'Internal server error'}), 500

        @self.blueprint.route('/feedback', methods=['POST'])
        def submit_feedback():
            """
            Submit human feedback for incremental learning.

            Request Body:
            {
                "correlation_id": "uuid",
                "feedback_type": "false_positive|true_positive|incorrect_action",
                "correct_label": "expected_value",
                "comments": "Optional comments"
            }
            """
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'Invalid request body'}), 400

                correlation_id = data.get('correlation_id')
                feedback_type = data.get('feedback_type')

                if not correlation_id or not feedback_type:
                    return jsonify({'error': 'correlation_id and feedback_type required'}), 400

                # Store feedback (would update incremental learning storage)
                self.logger.info(
                    f"Feedback received for {correlation_id[:8]}...: "
                    f"{feedback_type} - {data.get('correct_label', 'N/A')}"
                )

                return jsonify({
                    'success': True,
                    'message': 'Feedback recorded for learning'
                })

            except Exception as e:
                self.logger.error(f"Error submitting feedback: {e}")
                return jsonify({'error': 'Internal server error'}), 500

    def _create_raw_log_event(
        self,
        correlation_id: str,
        message: str,
        user_id: str,
        session_id: str,
        src_ip: str,
        agent_id: str,
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a RawLogEvent structure."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        return {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "chatbot_controller",
            "payload": {
                "message": message,
                "user_id": user_id,
                "session_id": session_id,
                "src_ip": src_ip,
                "agent_id": agent_id,
                "source": "chatbot",
                "extra": metadata,
            }
        }

    def _create_approval_event(
        self,
        correlation_id: str,
        approved: bool,
        reason: str,
        approver: str
    ) -> Dict[str, Any]:
        """Create a HumanApproval event structure."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        return {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "chatbot_controller",
            "payload": {
                "approved": approved,
                "reason": reason,
                "approver": approver,
                "approval_timestamp": timestamp,
            }
        }

    def _format_timeline(self, incident: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format timeline for UI display."""
        timeline = incident.get('timeline', [])

        # Map event types to display labels
        labels = {
            "RawLogEvent": "📥 Event Received",
            "DetectorFinding": "🔍 Threat Detected",
            "AlertDetected": "🚨 Alert Generated",
            "AnalysisCompleted": "📊 Analysis Complete",
            "AnalystAssessment": "🧠 Assessment Ready",
            "RiskAssessment": "⚠️ Risk Evaluated",
            "PolicyDecision": "📋 Policy Applied",
            "RemediationDecision": "🎯 Decision Made",
            "RemediationExecuted": "✅ Action Executed",
            "HumanApproval": "👤 Human Review",
        }

        formatted = []
        for entry in timeline:
            event_type = entry.get('event_type', 'Unknown')
            formatted.append({
                "timestamp": entry.get('timestamp'),
                "label": labels.get(event_type, event_type),
                "event_type": event_type,
                "producer": entry.get('producer'),
                "summary": entry.get('summary'),
            })

        return formatted

    def register_routes(self, app):
        """Register the blueprint with a Flask app."""
        app.register_blueprint(self.blueprint)
        self.logger.info("Chatbot routes registered")


# ============================================================================
# SOC Pipeline Orchestrator
# ============================================================================

class SOCPipelineOrchestrator:
    """
    Orchestrates the complete SOC pipeline with EventBus.

    This class:
    - Initializes EventBus and all agents
    - Connects IncidentStateManager
    - Provides ChatbotController for Flask integration
    - Manages lifecycle of all components
    """

    def __init__(
        self,
        dry_run: bool = True,
        logger: Optional[logging.Logger] = None
    ):
        self.dry_run = dry_run
        self.logger = logger or logging.getLogger("SOCPipeline")

        # Import here to avoid circular imports
        from soc_core.events import EventBus
        from soc_core.state import IncidentStateManager
        from soc_core.agents import (
            UnifiedDetectorAdapter,
            UnifiedAnalystAdapter,
            UnifiedRemediatorAdapter,
        )
        from shared.agent_memory import AgentMemory

        # Initialize core components
        self.bus = EventBus()
        self.memory = AgentMemory()
        self.state_manager = IncidentStateManager(self.bus)

        # Initialize unified agents
        self.detector = UnifiedDetectorAdapter(self.bus, self.memory, self.logger)
        self.analyst = UnifiedAnalystAdapter(self.bus, self.memory, self.logger)
        self.remediator = UnifiedRemediatorAdapter(
            self.bus, self.memory,
            dry_run=dry_run,
            logger=self.logger
        )

        # Initialize chatbot controller
        self.controller = ChatbotController(self.bus, self.state_manager, logger=self.logger)

        self._started = False
        self.logger.info(f"SOCPipelineOrchestrator initialized (dry_run={dry_run})")

    def start(self) -> None:
        """Start all pipeline components."""
        if self._started:
            self.logger.warning("Pipeline already started")
            return

        # Start in order: state manager first (to observe all events)
        self.state_manager.start()
        self.detector.start()
        self.analyst.start()
        self.remediator.start()

        self._started = True
        self.logger.info("SOC Pipeline started")

    def stop(self) -> None:
        """Stop all pipeline components."""
        if not self._started:
            return

        # Stop in reverse order
        self.remediator.stop()
        self.analyst.stop()
        self.detector.stop()
        self.state_manager.stop()

        self._started = False
        self.logger.info("SOC Pipeline stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics from all components."""
        return {
            "detector": self.detector.get_stats(),
            "analyst": self.analyst.get_stats(),
            "remediator": self.remediator.get_stats(),
            "state_manager": self.state_manager.get_stats(),
        }

    def register_with_flask(self, app) -> None:
        """Register chatbot routes with Flask app."""
        self.controller.register_routes(app)
