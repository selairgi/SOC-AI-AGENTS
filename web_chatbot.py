#!/usr/bin/env python3
"""
Web-based Chatbot with SOC AI Agents Integration
A Flask web application that provides a chatbot interface with automatic SOC security monitoring
"""

import asyncio
import json
import time
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
import uuid

# Import SOC components
from security_rules import SecurityRulesEngine
from soc_analyst import SOCAnalyst
from message_bus import MessageBus
from models import LogEntry, Alert, AgentType
from remediator import Remediator
from environment_config import EnvironmentConfig

app = Flask(__name__)
app.config['SECRET_KEY'] = 'soc_ai_agents_secret_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize SOC components
class SOCWebIntegration:
    def __init__(self):
        self.rules_engine = SecurityRulesEngine()
        self.bus = MessageBus()
        self.remediator_queue = asyncio.Queue()
        self.analyst = SOCAnalyst(self.bus, self.remediator_queue)
        self.remediator = Remediator()
        self.config = EnvironmentConfig()
        self.config.apply_preset("development")
        
        # Chatbot state
        self.active_sessions = {}
        self.chat_history = {}
        self.soc_alerts = []
        self.start_time = time.time()
        
        # Start SOC monitoring in background
        self.start_soc_monitoring()
    
    def start_soc_monitoring(self):
        """Start SOC monitoring in background thread."""
        def run_soc():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._run_soc_components())
        
        soc_thread = threading.Thread(target=run_soc, daemon=True)
        soc_thread.start()
    
    async def _run_soc_components(self):
        """Run SOC components asynchronously."""
        try:
            await asyncio.gather(
                self.analyst.run(),
                self.remediator.run(self.remediator_queue)
            )
        except Exception as e:
            print(f"SOC monitoring error: {e}")
    
    def analyze_chat_message(self, message, user_id, session_id, user_ip="127.0.0.1"):
        """Analyze chat message for security threats."""
        # Create log entry for SOC analysis
        log = LogEntry(
            timestamp=time.time(),
            source="web_chatbot",
            message=message,
            agent_id="web_chatbot_agent",
            user_id=user_id,
            session_id=session_id,
            src_ip=user_ip,
            request_id=f"chat_{int(time.time()*1000)}",
            status_code=200,
            extra={
                "agent_type": "general",
                "chatbot_context": True,
                "web_interface": True
            }
        )
        
        # Test against security rules
        alert = self.rules_engine.analyze_log(log)
        
        if alert:
            # Store alert
            alert_data = {
                "timestamp": datetime.now().isoformat(),
                "user_id": user_id,
                "session_id": session_id,
                "alert": alert,
                "message": message,
                "src_ip": user_ip
            }
            self.soc_alerts.append(alert_data)
            
            # Send alert to SOC analyst for processing
            self._send_alert_to_analyst_sync(alert, log)
            
            # Emit real-time alert to web interface
            socketio.emit('security_alert', {
                'alert_id': alert.id,
                'rule_id': alert.rule_id,
                'severity': alert.severity,
                'threat_type': alert.threat_type.value,
                'title': alert.title,
                'description': alert.description,
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id,
                'session_id': session_id
            })
            
            # Log the alert for SOC monitoring
            print(f"🚨 SECURITY ALERT: {alert.severity.upper()} - {alert.title}")
            print(f"   Rule: {alert.rule_id} | Threat: {alert.threat_type.value}")
            print(f"   User: {user_id} | Session: {session_id}")
            print(f"   Message: {message[:100]}...")
            
            return alert
        
        return None
    
    async def _send_alert_to_analyst(self, alert, log):
        """Send alert to SOC analyst for processing."""
        try:
            # Publish alert to message bus for SOC analyst
            await self.bus.publish_alert(alert)
            print(f"📤 Alert {alert.id} sent to SOC analyst for analysis")
        except Exception as e:
            print(f"❌ Error sending alert to analyst: {e}")
    
    def _send_alert_to_analyst_sync(self, alert, log):
        """Synchronous wrapper for sending alert to analyst."""
        try:
            # Publish alert to message bus for SOC analyst (synchronous)
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self.bus.publish_alert(alert))
                print(f"📤 Alert {alert.id} sent to SOC analyst for analysis")
            finally:
                loop.close()
        except Exception as e:
            print(f"❌ Error sending alert to analyst: {e}")
    
    def get_chatbot_response(self, message, user_id, session_id):
        """Generate chatbot response based on message."""
        # Simple chatbot logic - can be enhanced with actual AI
        responses = {
            "hello": "Hello! I'm a chatbot protected by SOC AI Agents. How can I help you today?",
            "help": "I can help you with various tasks. I'm monitored by SOC security systems for your protection.",
            "security": "This chatbot is protected by SOC AI Agents that monitor for threats like prompt injection, data exfiltration, and malicious inputs.",
            "soc": "SOC (Security Operations Center) AI Agents provide real-time security monitoring for this chatbot environment.",
            "threat": "If any security threats are detected, the SOC system will automatically respond with appropriate countermeasures.",
            "default": "I understand. I'm here to help, and I'm protected by advanced SOC security monitoring."
        }
        
        message_lower = message.lower()
        
        for key, response in responses.items():
            if key in message_lower:
                return response
        
        return responses["default"]

# Initialize SOC integration
soc_integration = SOCWebIntegration()

@app.route('/')
def index():
    """Main chat interface."""
    session_id = str(uuid.uuid4())
    session['session_id'] = session_id
    session['user_id'] = f"user_{int(time.time())}"
    return render_template('enhanced_chat.html', session_id=session_id)

@app.route('/dashboard')
def dashboard():
    """SOC Dashboard interface."""
    return render_template('soc_dashboard.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    """Handle chat messages."""
    data = request.get_json()
    message = data.get('message', '')
    user_id = session.get('user_id', 'anonymous')
    session_id = session.get('session_id', str(uuid.uuid4()))
    user_ip = request.remote_addr
    
    # Analyze message for security threats
    alert = soc_integration.analyze_chat_message(message, user_id, session_id, user_ip)
    
    # Generate chatbot response
    response = soc_integration.get_chatbot_response(message, user_id, session_id)
    
    # Store chat history
    if session_id not in soc_integration.chat_history:
        soc_integration.chat_history[session_id] = []
    
    soc_integration.chat_history[session_id].append({
        'timestamp': datetime.now().isoformat(),
        'user_message': message,
        'bot_response': response,
        'security_alert': alert.id if alert else None
    })
    
    return jsonify({
        'response': response,
        'security_alert': {
            'detected': alert is not None,
            'alert_id': alert.id if alert else None,
            'rule_id': alert.rule_id if alert else None,
            'severity': alert.severity if alert else None,
            'threat_type': alert.threat_type.value if alert else None
        }
    })

@app.route('/api/security/alerts')
def get_security_alerts():
    """Get recent security alerts."""
    # Convert alerts to JSON-serializable format
    serialized_alerts = []
    for alert_data in soc_integration.soc_alerts[-10:]:
        alert = alert_data['alert']
        serialized_alert = {
            'timestamp': alert_data['timestamp'],
            'user_id': alert_data['user_id'],
            'session_id': alert_data['session_id'],
            'message': alert_data['message'],
            'src_ip': alert_data['src_ip'],
            'alert': {
                'id': alert.id,
                'timestamp': alert.timestamp,
                'severity': alert.severity,
                'title': alert.title,
                'description': alert.description,
                'threat_type': alert.threat_type.value,
                'agent_id': alert.agent_id,
                'rule_id': alert.rule_id,
                'correlated': alert.correlated,
                'false_positive_probability': alert.false_positive_probability
            }
        }
        serialized_alerts.append(serialized_alert)
    
    return jsonify({
        'alerts': serialized_alerts,
        'total_alerts': len(soc_integration.soc_alerts)
    })

@app.route('/api/security/status')
def get_security_status():
    """Get SOC security status."""
    return jsonify({
        'status': 'active',
        'monitoring': True,
        'total_alerts': len(soc_integration.soc_alerts),
        'active_sessions': len(soc_integration.active_sessions),
        'rules_loaded': len(soc_integration.rules_engine.rules),
        'analyst_status': 'online',
        'remediator_status': 'online',
        'last_alert': soc_integration.soc_alerts[-1]['timestamp'] if soc_integration.soc_alerts else None
    })

@app.route('/api/security/block', methods=['POST'])
def block_threat():
    """Block a specific threat (IP, user, etc.)."""
    data = request.get_json()
    threat_type = data.get('threat_type')
    threat_id = data.get('threat_id')
    
    if not threat_type or not threat_id:
        return jsonify({'error': 'Missing threat_type or threat_id'}), 400
    
    # In a real implementation, this would call the remediator
    print(f"🛡️ Blocking {threat_type}: {threat_id}")
    
    return jsonify({
        'success': True,
        'message': f'Successfully blocked {threat_type}: {threat_id}',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/security/investigate', methods=['POST'])
def investigate_threat():
    """Start investigation of a specific threat."""
    data = request.get_json()
    threat_id = data.get('threat_id')
    rule_id = data.get('rule_id')
    
    if not threat_id:
        return jsonify({'error': 'Missing threat_id'}), 400
    
    # In a real implementation, this would create an investigation ticket
    print(f"🔍 Starting investigation for threat: {threat_id}")
    
    return jsonify({
        'success': True,
        'message': f'Investigation started for threat: {threat_id}',
        'investigation_id': f'INV-{int(time.time())}',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/security/metrics')
def get_security_metrics():
    """Get security metrics and statistics."""
    alerts_by_severity = {}
    alerts_by_threat_type = {}
    
    for alert_data in soc_integration.soc_alerts:
        alert = alert_data['alert']
        
        # Count by severity
        severity = alert.severity
        alerts_by_severity[severity] = alerts_by_severity.get(severity, 0) + 1
        
        # Count by threat type
        threat_type = alert.threat_type.value
        alerts_by_threat_type[threat_type] = alerts_by_threat_type.get(threat_type, 0) + 1
    
    return jsonify({
        'total_alerts': len(soc_integration.soc_alerts),
        'alerts_by_severity': alerts_by_severity,
        'alerts_by_threat_type': alerts_by_threat_type,
        'active_sessions': len(soc_integration.active_sessions),
        'rules_loaded': len(soc_integration.rules_engine.rules),
        'uptime': time.time() - soc_integration.start_time if hasattr(soc_integration, 'start_time') else 0
    })

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    session_id = session.get('session_id')
    if session_id:
        join_room(session_id)
        soc_integration.active_sessions[session_id] = {
            'connected_at': datetime.now().isoformat(),
            'user_id': session.get('user_id')
        }
        emit('connected', {'message': 'Connected to SOC-protected chatbot'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    session_id = session.get('session_id')
    if session_id:
        leave_room(session_id)
        if session_id in soc_integration.active_sessions:
            del soc_integration.active_sessions[session_id]

@socketio.on('join_session')
def handle_join_session(data):
    """Handle joining a session."""
    session_id = data.get('session_id')
    if session_id:
        join_room(session_id)

if __name__ == '__main__':
    print("🛡️  SOC AI AGENTS - WEB CHATBOT")
    print("=" * 50)
    print("Starting web chatbot with SOC security monitoring...")
    print("🌐 Web interface: http://localhost:5000")
    print("🛡️  SOC monitoring: ACTIVE")
    print("🔒 Security rules: LOADED")
    print("=" * 50)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

