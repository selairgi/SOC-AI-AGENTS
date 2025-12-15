#!/usr/bin/env python3
"""
Production-Ready SOC AI Agents Web Application
A secure, enterprise-grade Flask web application with comprehensive security features
"""

# Monkey patch for eventlet
import eventlet
eventlet.monkey_patch()

import asyncio
import json
import time
import threading
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from functools import wraps
import re
import logging
import os
from pathlib import Path

from flask import Flask, render_template, request, jsonify, session, g
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import uuid

from dotenv import load_dotenv

# Import modules with proper paths
import sys
import os
from pathlib import Path

# Set up Python path
# In Docker: modules are in /app (PYTHONPATH=/app)
# Local dev: add parent directory to path
app_dir = Path(__file__).parent
if os.path.exists('/app'):  # Running in Docker
    sys.path.insert(0, '/app')
else:  # Running locally
    parent_dir = app_dir.parent
    sys.path.insert(0, str(parent_dir))
    sys.path.insert(0, str(app_dir))

# Import modules
from security_pipeline import SecureSOCWebIntegration

# Load environment variables
load_dotenv()

# Ensure logs directory exists
# In Docker: app.py is in /app/, so parent is /app, parent.parent is /
# We want /app/logs in Docker and project_root/logs locally
if os.path.exists('/app'):  # Running in Docker
    logs_dir = Path('/app/logs')
else:  # Running locally
    logs_dir = Path(__file__).parent.parent / 'logs'

# Create logs directory with proper error handling
try:
    logs_dir.mkdir(exist_ok=True, parents=True)
except PermissionError:
    # Fallback to /tmp/logs if we can't create in the preferred location
    logs_dir = Path('/tmp/logs')
    logs_dir.mkdir(exist_ok=True, parents=True)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / 'app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SOCWebApp")

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')

# Security Configuration
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    logger.warning("SECRET_KEY not set in environment, generating temporary key")
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("⚠️  Using temporary SECRET_KEY - set SECRET_KEY in environment for production!")

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size

# CORS Configuration
CORS(app, resources={
    r"/api/*": {
        "origins": os.getenv('ALLOWED_ORIGINS', 'http://localhost:5000').split(','),
        "methods": ["GET", "POST"],
        "allow_headers": ["Content-Type", "Authorization", "X-CSRFToken"]
    }
})

# Rate Limiting
# Increased limits to allow for CTF testing (190+ rapid requests)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per day", "500 per hour"],
    storage_uri=os.getenv('REDIS_URL', 'memory://')
)

# SocketIO
socketio = SocketIO(
    app,
    cors_allowed_origins=os.getenv('ALLOWED_ORIGINS', 'http://localhost:5000').split(','),
    async_mode='threading',
    logger=False,
    engineio_logger=False
)


# IP Blocking Middleware - ENFORCE BLOCKED IPS
@app.before_request
def check_ip_blocked():
    """Check if the requesting IP is blocked before processing any request"""
    # Skip check for health endpoint
    if request.path == '/health':
        return None

    # Get client IP
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if user_ip and ',' in user_ip:
        user_ip = user_ip.split(',')[0].strip()

    # Check if IP is blocked (using the global soc instance which will be initialized later)
    # We need to check this lazily to avoid circular dependency
    if 'soc' in globals() and globals()['soc'] is not None:
        soc_instance = globals()['soc']
        if hasattr(soc_instance, 'real_remediator') and soc_instance.real_remediator.is_ip_blocked(user_ip):
            logger.warning(f"🚫 BLOCKED REQUEST from blocked IP: {user_ip}")
            return jsonify({
                'error': 'Access Denied',
                'message': 'Your IP address has been blocked due to security violations.',
                'blocked': True
            }), 403

    return None


class InputValidator:
    """Centralized input validation and sanitization"""
    
    MAX_MESSAGE_LENGTH = 10000
    MAX_USER_ID_LENGTH = 256
    MAX_SESSION_ID_LENGTH = 256
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = MAX_MESSAGE_LENGTH) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Sanitize and validate string input.
        
        Returns:
            (is_valid, sanitized_value, error_message)
        """
        if not isinstance(value, str):
            return False, None, "Input must be a string"
        
        # Check length
        if len(value) > max_length:
            return False, None, f"Input exceeds maximum length of {max_length} characters"
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Trim whitespace
        value = value.strip()
        
        # Check for empty after trim
        if not value:
            return False, None, "Input cannot be empty"
        
        # Basic XSS prevention (escape HTML)
        # Note: For production, use a proper HTML sanitizer like bleach
        value = value.replace('<', '&lt;').replace('>', '&gt;')
        
        return True, value, None
    
    @staticmethod
    def validate_message(message: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate chat message"""
        return InputValidator.sanitize_string(message, InputValidator.MAX_MESSAGE_LENGTH)
    
    @staticmethod
    def validate_user_id(user_id: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate user ID"""
        if not user_id:
            return False, None, "User ID is required"
        
        # Check format
        if not re.match(r'^[a-zA-Z0-9_\-@.]+$', user_id):
            return False, None, "Invalid user ID format"
        
        if len(user_id) > InputValidator.MAX_USER_ID_LENGTH:
            return False, None, f"User ID exceeds maximum length of {InputValidator.MAX_USER_ID_LENGTH}"
        
        return True, user_id, None
    
    @staticmethod
    def validate_session_id(session_id: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate session ID"""
        if not session_id:
            return False, None, "Session ID is required"
        
        if not re.match(r'^[a-zA-Z0-9_\-]+$', session_id):
            return False, None, "Invalid session ID format"
        
        if len(session_id) > InputValidator.MAX_SESSION_ID_LENGTH:
            return False, None, f"Session ID exceeds maximum length of {InputValidator.MAX_SESSION_ID_LENGTH}"
        
        return True, session_id, None


class CSRFProtection:
    """CSRF token generation and validation"""
    
    @staticmethod
    def generate_token() -> str:
        """Generate CSRF token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_token(session_token: Optional[str], request_token: Optional[str]) -> bool:
        """Validate CSRF token"""
        if not session_token or not request_token:
            return False
        return hmac.compare_digest(session_token, request_token)


def require_csrf(f):
    """Decorator to require CSRF token for POST requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            session_token = session.get('csrf_token')
            request_token = request.headers.get('X-CSRFToken') or request.json.get('csrf_token') if request.is_json else None
            
            if not CSRFProtection.validate_token(session_token, request_token):
                logger.warning(f"CSRF validation failed for {request.remote_addr}")
                return jsonify({'error': 'CSRF token validation failed'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


# Initialize SOC integration
# Note: The SecureSOCWebIntegration class has been extracted to security_pipeline.py
try:
    from security_pipeline import SecureSOCWebIntegration
    # Pass socketio instance for WebSocket emissions
    soc = SecureSOCWebIntegration(socketio=socketio)
    logger.info("SOC Integration initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize SOC: {e}", exc_info=True)
    soc = None


# Routes
@app.route('/')
def index():
    """Main chat interface"""
    session_id = str(uuid.uuid4())
    session['session_id'] = session_id
    session['user_id'] = f"user_{int(time.time())}"
    
    # Generate CSRF token
    if 'csrf_token' not in session:
        session['csrf_token'] = CSRFProtection.generate_token()
    
    return render_template('enhanced_chatbot.html', session_id=session_id)


@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """Get CSRF token for frontend"""
    if 'csrf_token' not in session:
        session['csrf_token'] = CSRFProtection.generate_token()
    return jsonify({'csrf_token': session['csrf_token']})


@app.route('/health')
def health_check():
    """Health check endpoint"""
    checks = {
        'status': 'healthy',
        'soc_initialized': soc is not None,
        'timestamp': datetime.utcnow().isoformat()
    }

    if soc:
        checks.update({
            'soc_enabled': soc.soc_enabled,
            'uptime': time.time() - soc.start_time
        })

    status_code = 200 if checks['status'] == 'healthy' else 503
    return jsonify(checks), status_code


@app.route('/api/unblock-ip', methods=['POST'])
@require_csrf
def unblock_ip_endpoint():
    """Unblock an IP address"""
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'error': 'IP address required'}), 400

        ip_to_unblock = data.get('ip')

        if not soc:
            return jsonify({'error': 'SOC system not initialized'}), 503

        # Unblock the IP
        success = soc.real_remediator.unblock_ip(ip_to_unblock)

        if success:
            logger.info(f"✅ IP unblocked: {ip_to_unblock}")
            return jsonify({
                'success': True,
                'message': f'IP {ip_to_unblock} has been unblocked',
                'ip': ip_to_unblock
            })
        else:
            return jsonify({
                'success': False,
                'message': f'IP {ip_to_unblock} was not blocked'
            }), 404

    except Exception as e:
        logger.error(f"Error unblocking IP: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """Get list of currently blocked IPs"""
    try:
        if not soc:
            return jsonify({'error': 'SOC system not initialized'}), 503

        blocked_ips = soc.real_remediator.get_blocked_ips()
        return jsonify({
            'blocked_ips': blocked_ips,
            'count': len(blocked_ips)
        })

    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/execute-remediation', methods=['POST'])
@require_csrf
def execute_remediation():
    """Execute a remediation action (for manual mode approval)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request body'}), 400

        action_type = data.get('action_type')
        target = data.get('target')
        alert_id = data.get('alert_id', 'manual_approval')
        session_id = data.get('session_id') or session.get('session_id', 'unknown')

        if not action_type or not target:
            return jsonify({'error': 'action_type and target required'}), 400

        if not soc:
            return jsonify({'error': 'SOC system not initialized'}), 503

        logger.info(f"📋 MANUAL APPROVAL: Executing {action_type} on {target}")

        result = {
            'success': False,
            'action_type': action_type,
            'target': target,
            'message': ''
        }

        # Execute the remediation action
        if action_type == 'block_ip':
            soc.real_remediator.block_ip(
                target,
                reason="Manual approval - Security threat",
                duration=3600,
                alert_id=alert_id
            )
            result['success'] = True
            result['message'] = f'IP {target} blocked for 1 hour'

            # Emit workflow log
            socketio.emit('workflow_log', {
                'agent': 'Remediator',
                'action': 'IP address blocked (Manual Approval)',
                'type': 'danger',
                'details': f'Target: {target} | Duration: 1 hour | Approved by user',
                'timestamp': datetime.utcnow().isoformat()
            }, room=session_id)

        elif action_type == 'terminate_session':
            soc.real_remediator.terminate_session(
                target,
                reason="Manual approval - Security threat",
                alert_id=alert_id
            )
            result['success'] = True
            result['message'] = f'Session {target} terminated'

            # Emit workflow log
            socketio.emit('workflow_log', {
                'agent': 'Remediator',
                'action': 'Session terminated (Manual Approval)',
                'type': 'danger',
                'details': f'Session: {target} | Approved by user',
                'timestamp': datetime.utcnow().isoformat()
            }, room=session_id)

        else:
            return jsonify({'error': f'Unknown action type: {action_type}'}), 400

        logger.info(f"✅ Remediation executed: {action_type} on {target}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error executing remediation: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/chat', methods=['POST'])
@limiter.limit("10 per minute")
@require_csrf
def chat():
    """Handle chat messages with full SOC monitoring"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request body'}), 400

        message = data.get('message', '')
        security_mode = data.get('security_mode', 'security_aware')
        auto_remediation = data.get('auto_remediation', False)  # Get remediation mode from frontend
        
        # Validate input
        is_valid, sanitized_message, error = InputValidator.validate_message(message)
        if not is_valid:
            return jsonify({'error': error or 'Invalid input'}), 400
        
        # Allow user_id and session_id from request body for testing, otherwise use session
        user_id = data.get('user_id') or session.get('user_id', 'anonymous')
        session_id = data.get('session_id') or session.get('session_id', str(uuid.uuid4()))
        user_ip = request.remote_addr or '127.0.0.1'
        
        if not soc:
            return jsonify({'error': 'SOC system not initialized'}), 503
        
        # Process message
        result = soc.process_chat_message(
            sanitized_message, user_id, session_id, user_ip, security_mode, auto_remediation
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in chat endpoint: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/soc/toggle', methods=['POST'])
@limiter.limit("5 per minute")
@require_csrf
def toggle_soc():
    """Toggle SOC monitoring on/off"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', True) if data else True
        
        if not soc:
            return jsonify({'error': 'SOC system not initialized'}), 503
        
        result = soc.toggle_soc(enabled)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in toggle_soc: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/soc/status')
@limiter.limit("30 per minute")
def get_soc_status():
    """Get comprehensive SOC status"""
    if not soc:
        return jsonify({'error': 'SOC system not initialized'}), 503
    
    try:
        return jsonify({
            "soc_enabled": soc.soc_enabled,
            "monitoring": True,
            "total_alerts": len(soc.soc_alerts),
            "active_sessions": len(soc.active_sessions),
            "ai_stats": soc.ai_integration.get_statistics() if hasattr(soc.ai_integration, 'get_statistics') else {},
            "fp_detector_stats": soc.fp_detector.get_statistics() if hasattr(soc.fp_detector, 'get_statistics') else {},
            "remediation_stats": soc.real_remediator.get_statistics() if hasattr(soc.real_remediator, 'get_statistics') else {},
            "blocked_entities": soc.real_remediator.get_blocked_entities() if hasattr(soc.real_remediator, 'get_blocked_entities') else {},
            "rate_limits": soc.real_remediator.get_rate_limits() if hasattr(soc.real_remediator, 'get_rate_limits') else {},
            "uptime": time.time() - soc.start_time
        })
    except Exception as e:
        logger.error(f"Error in get_soc_status: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/security/alerts')
@limiter.limit("30 per minute")
def get_security_alerts():
    """Get recent security alerts"""
    if not soc:
        return jsonify({'error': 'SOC system not initialized'}), 503
    
    try:
        serialized_alerts = []
        for alert_data in soc.soc_alerts[-20:]:
            alert = alert_data['alert']
            fp_score = alert_data.get('fp_score')
            
            serialized_alert = {
                'timestamp': alert_data['timestamp'],
                'user_id': alert_data['user_id'],
                'session_id': alert_data['session_id'],
                'message': alert_data['message'][:100],
                'src_ip': alert_data['src_ip'],
                'alert': {
                    'id': alert.id,
                    'severity': alert.severity,
                    'title': alert.title,
                    'description': alert.description,
                    'threat_type': alert.threat_type.value,
                    'rule_id': alert.rule_id,
                    'false_positive_probability': alert.false_positive_probability
                },
                'false_positive_analysis': {
                    'probability': fp_score.false_positive_probability,
                    'recommended_action': fp_score.recommended_action,
                    'reasoning': fp_score.reasoning
                } if fp_score else None
            }
            serialized_alerts.append(serialized_alert)
        
        return jsonify({
            'alerts': serialized_alerts,
            'total_alerts': len(soc.soc_alerts)
        })
    except Exception as e:
        logger.error(f"Error in get_security_alerts: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/test/scenario/<scenario_name>', methods=['POST'])
@limiter.limit("5 per minute")
@require_csrf
def run_test_scenario(scenario_name: str):
    """Run attack scenario for testing"""
    if not soc:
        return jsonify({'error': 'SOC system not initialized'}), 503

    try:
        result = soc.run_attack_scenario(scenario_name)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in run_test_scenario: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


# Incremental Learning API Endpoints
@app.route('/api/learning/report-missed-attack', methods=['POST'])
@limiter.limit("10 per minute")
@require_csrf
def report_missed_attack():
    """
    Report an attack that was not detected by the system

    This allows users/analysts to provide feedback on false negatives,
    enabling the system to learn and improve detection.

    Request Body:
    {
        "message": "The attack message that was missed",
        "user_id": "user_id",
        "session_id": "session_id",
        "actual_threat_type": "PROMPT_INJECTION",
        "severity": "HIGH",
        "reported_by": "user|analyst|automated_test",
        "metadata": {}
    }
    """
    if not soc or not hasattr(soc, 'learning_system'):
        return jsonify({'error': 'Learning system not initialized'}), 503

    try:
        data = request.get_json()

        if not data or 'message' not in data:
            return jsonify({'error': 'Missing required field: message'}), 400

        attack_id = soc.learning_system.report_missed_attack(
            message=data['message'],
            user_id=data.get('user_id', session.get('user_id', 'unknown')),
            session_id=data.get('session_id', session.get('session_id', 'unknown')),
            reported_by=data.get('reported_by', 'user'),
            actual_threat_type=data.get('actual_threat_type', 'PROMPT_INJECTION'),
            severity=data.get('severity', 'HIGH'),
            metadata=data.get('metadata', {})
        )

        return jsonify({
            'success': True,
            'attack_id': attack_id,
            'message': 'Thank you for reporting! The system will learn from this attack.',
            'status': 'processing' if soc.learning_system.auto_update else 'queued'
        })

    except Exception as e:
        logger.error(f"Error in report_missed_attack: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/learning/metrics', methods=['GET'])
def get_learning_metrics():
    """Get current learning metrics"""
    if not soc or not hasattr(soc, 'learning_system'):
        return jsonify({'error': 'Learning system not initialized'}), 503

    try:
        metrics = soc.learning_system.get_learning_metrics()

        return jsonify({
            'success': True,
            'metrics': {
                'total_missed_attacks': metrics.total_missed_attacks,
                'patterns_learned': metrics.patterns_learned,
                'variations_generated': metrics.variations_generated,
                'detection_improvement': round(metrics.detection_improvement, 2),
                'false_negative_rate': round(metrics.false_negative_rate, 2),
                'learning_rate': metrics.learning_rate,
                'last_update': metrics.last_update,
                'last_update_human': datetime.fromtimestamp(metrics.last_update).strftime('%Y-%m-%d %H:%M:%S')
            }
        })

    except Exception as e:
        logger.error(f"Error in get_learning_metrics: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/learning/export-patterns', methods=['GET'])
@limiter.limit("2 per hour")
def export_learned_patterns():
    """Export learned patterns for review"""
    if not soc or not hasattr(soc, 'learning_system'):
        return jsonify({'error': 'Learning system not initialized'}), 503

    try:
        output_file = f"learned_patterns_{int(time.time())}.json"
        patterns_count = soc.learning_system.export_learned_patterns(output_file)

        return jsonify({
            'success': True,
            'patterns_exported': patterns_count,
            'output_file': output_file,
            'message': f'Exported {patterns_count} learned patterns to {output_file}'
        })

    except Exception as e:
        logger.error(f"Error in export_learned_patterns: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/learning/process-pending', methods=['POST'])
@limiter.limit("5 per hour")
@require_csrf
def process_pending_attacks():
    """Process all pending missed attacks"""
    if not soc or not hasattr(soc, 'learning_system'):
        return jsonify({'error': 'Learning system not initialized'}), 503

    try:
        results = soc.learning_system.process_all_pending()

        return jsonify({
            'success': True,
            'results': results,
            'message': f"Processed {results['total_processed']} attacks, generated {results['variations_generated']} variations"
        })

    except Exception as e:
        logger.error(f"Error in process_pending_attacks: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


# WebSocket handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    session_id = session.get('session_id')
    if session_id and soc:
        join_room(session_id)
        soc.active_sessions[session_id] = {
            'connected_at': datetime.utcnow().isoformat(),
            'user_id': session.get('user_id')
        }
        emit('connected', {'message': 'Connected to SOC-protected chatbot'})
        logger.info(f"Client connected and joined room: {session_id}")


@socketio.on('join_session')
def handle_join_session(data):
    """Handle explicit join_session request from client"""
    session_id = data.get('session_id')
    if session_id:
        join_room(session_id)
        emit('joined', {'session_id': session_id})
        logger.info(f"Client explicitly joined session room: {session_id}")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    session_id = session.get('session_id')
    if session_id and soc and session_id in soc.active_sessions:
        leave_room(session_id)
        del soc.active_sessions[session_id]
        logger.info(f"Client disconnected from room: {session_id}")


if __name__ == '__main__':
    logger.info("=" * 70)
    logger.info("  SECURE SOC AI AGENTS - WEB APPLICATION")
    logger.info("=" * 70)
    logger.info("[OK] Security Features: Active")
    logger.info("[OK] Input Validation: Active")
    logger.info("[OK] CSRF Protection: Active")
    logger.info("[OK] Rate Limiting: Active")
    logger.info("[OK] SOC Monitoring: Active")
    logger.info("=" * 70)
    logger.info("Web interface: http://localhost:5000")
    logger.info("Health check: http://localhost:5000/health")
    logger.info("=" * 70)
    
    # Run with production settings
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    socketio.run(
        app,
        debug=debug_mode,
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        allow_unsafe_werkzeug=True
    )


