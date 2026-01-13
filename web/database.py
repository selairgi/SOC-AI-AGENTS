"""
Database helper for PostgreSQL operations
Handles feedback storage and alert history
"""

import os
import logging
import psycopg2
import psycopg2.extras
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger("Database")


class DatabaseConnection:
    """PostgreSQL database connection manager"""

    def __init__(self):
        self.connection_url = os.getenv('POSTGRES_URL')
        if not self.connection_url:
            logger.warning("POSTGRES_URL not set, feedback persistence disabled")
            self.enabled = False
        else:
            self.enabled = True
            logger.info("Database connection configured")

    @contextmanager
    def get_connection(self):
        """Get database connection context manager"""
        if not self.enabled:
            yield None
            return

        conn = None
        try:
            conn = psycopg2.connect(self.connection_url)
            yield conn
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def save_alert_history(self, alert_data: Dict[str, Any]) -> bool:
        """Save alert to history for feedback reference"""
        if not self.enabled:
            return False

        try:
            with self.get_connection() as conn:
                if not conn:
                    return False

                cursor = conn.cursor()

                # Extract alert details
                alert = alert_data.get('alert')
                if not alert:
                    logger.error("No alert object in alert_data")
                    return False

                # Get alert ID
                alert_id = alert.id if hasattr(alert, 'id') else alert_data.get('alert_id', 'unknown')
                logger.debug(f"Saving alert {alert_id} to PostgreSQL")

                # Extract evidence and intent analysis
                evidence = alert.evidence if hasattr(alert, 'evidence') else {}
                intent_analysis = evidence.get('intent_analysis', {})

                # Get reasoning from multiple possible locations
                reasoning = []
                if intent_analysis.get('reasoning'):
                    reasoning = intent_analysis.get('reasoning', [])
                elif evidence.get('reasoning'):
                    reasoning = evidence.get('reasoning', [])
                elif hasattr(alert, 'reasoning'):
                    reasoning = alert.reasoning if isinstance(alert.reasoning, list) else [alert.reasoning]

                # Get suspicious keywords
                suspicious_keywords = evidence.get('keywords', [])

                cursor.execute("""
                    INSERT INTO alert_history (
                        alert_id, message, user_id, session_id, src_ip,
                        severity, threat_type, detection_method,
                        fp_probability, confidence, danger_score,
                        reasoning, suspicious_keywords, intent_type,
                        session_risk_score, escalation_detected, slow_injection_detected,
                        recommended_action, action_taken
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s,
                        %s, %s
                    )
                    ON CONFLICT (alert_id) DO UPDATE SET
                        action_taken = EXCLUDED.action_taken,
                        recommended_action = EXCLUDED.recommended_action
                """, (
                    alert_id,
                    alert_data.get('message'),
                    alert_data.get('user_id'),
                    alert_data.get('session_id'),
                    alert_data.get('src_ip'),

                    alert.severity if hasattr(alert, 'severity') else 'medium',
                    alert.threat_type.value if hasattr(alert, 'threat_type') else 'UNKNOWN',
                    alert_data.get('detection_method', 'unknown'),

                    alert_data.get('fp_probability', 0.0),
                    evidence.get('confidence', alert_data.get('confidence', 0.5)),
                    intent_analysis.get('danger_score', 0.0),

                    reasoning if isinstance(reasoning, list) else [],
                    suspicious_keywords if isinstance(suspicious_keywords, list) else [],
                    intent_analysis.get('intent_type', 'unknown'),

                    alert_data.get('session_risk', {}).get('risk_score', 0.0),
                    alert_data.get('session_risk', {}).get('escalation_detected', False),
                    alert_data.get('session_risk', {}).get('slow_injection_detected', False),

                    alert_data.get('recommended_action', 'monitor'),
                    alert_data.get('action_taken')
                ))

                logger.info(f"✅ Saved alert {alert_id} to PostgreSQL")
                return True

        except Exception as e:
            logger.error(f"Failed to save alert history: {e}")
            return False

    def save_operator_feedback(self, feedback_data: Dict[str, Any]) -> bool:
        """
        Save operator feedback to database

        Args:
            feedback_data: {
                'alert_id': str,
                'message': str,
                'user_id': str,
                'session_id': str,
                'predicted_label': str,  # 'safe', 'investigate', 'block'
                'actual_label': str,     # 'safe' or 'threat'
                'fp_probability': float,
                'confidence': float,
                'threat_score': float,
                'detection_method': str,
                'reasoning': List[str],
                'suspicious_keywords': List[str],
                'operator_id': str,
                'operator_notes': str
            }
        """
        if not self.enabled:
            logger.warning("Database not enabled, feedback not saved")
            return False

        try:
            with self.get_connection() as conn:
                if not conn:
                    return False

                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO operator_feedback (
                        alert_id, message, user_id, session_id,
                        predicted_label, actual_label,
                        fp_probability, confidence, threat_score,
                        detection_method, reasoning, suspicious_keywords,
                        operator_id, operator_notes,
                        message_timestamp
                    ) VALUES (
                        %s, %s, %s, %s,
                        %s, %s,
                        %s, %s, %s,
                        %s, %s, %s,
                        %s, %s,
                        %s
                    )
                    ON CONFLICT (alert_id) DO UPDATE SET
                        actual_label = EXCLUDED.actual_label,
                        operator_id = EXCLUDED.operator_id,
                        operator_notes = EXCLUDED.operator_notes,
                        feedback_timestamp = CURRENT_TIMESTAMP
                """, (
                    feedback_data['alert_id'],
                    feedback_data['message'],
                    feedback_data.get('user_id'),
                    feedback_data.get('session_id'),

                    feedback_data['predicted_label'],
                    feedback_data['actual_label'],

                    feedback_data.get('fp_probability'),
                    feedback_data.get('confidence'),
                    feedback_data.get('threat_score'),

                    feedback_data.get('detection_method'),
                    feedback_data.get('reasoning', []),
                    feedback_data.get('suspicious_keywords', []),

                    feedback_data.get('operator_id', 'operator'),
                    feedback_data.get('operator_notes', ''),

                    self._parse_timestamp(feedback_data.get('message_timestamp'))
                ))

                logger.info(f"Saved feedback for alert {feedback_data['alert_id']}: {feedback_data['actual_label']}")
                return True

        except Exception as e:
            logger.error(f"Failed to save operator feedback: {e}")
            return False

    def get_alert_details(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve alert details by ID"""
        if not self.enabled:
            logger.warning(f"Database not enabled, cannot get alert {alert_id}")
            return None

        try:
            logger.debug(f"Querying PostgreSQL for alert {alert_id}")
            with self.get_connection() as conn:
                if not conn:
                    logger.error("Failed to get database connection")
                    return None

                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

                cursor.execute("""
                    SELECT * FROM alert_history WHERE alert_id = %s
                """, (alert_id,))

                result = cursor.fetchone()

                if result:
                    logger.info(f"✅ Found alert {alert_id} in PostgreSQL")
                    return dict(result)
                else:
                    logger.warning(f"Alert {alert_id} not found in PostgreSQL")
                    return None

        except Exception as e:
            logger.error(f"Failed to get alert details for {alert_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None

    def get_feedback_statistics(self) -> Dict[str, Any]:
        """Get feedback statistics for learning system"""
        if not self.enabled:
            return {
                'total_feedback': 0,
                'false_positives': 0,
                'confirmed_threats': 0,
                'feedback_rate': 0.0
            }

        try:
            with self.get_connection() as conn:
                if not conn:
                    return {}

                cursor = conn.cursor()

                # Total feedback count
                cursor.execute("SELECT COUNT(*) FROM operator_feedback")
                total = cursor.fetchone()[0]

                # False positives (predicted threat, actually safe)
                cursor.execute("""
                    SELECT COUNT(*) FROM operator_feedback
                    WHERE predicted_label IN ('investigate', 'block')
                    AND actual_label = 'safe'
                """)
                fp_count = cursor.fetchone()[0]

                # Confirmed threats
                cursor.execute("""
                    SELECT COUNT(*) FROM operator_feedback
                    WHERE actual_label = 'threat'
                """)
                threat_count = cursor.fetchone()[0]

                # Total alerts
                cursor.execute("SELECT COUNT(*) FROM alert_history")
                total_alerts = cursor.fetchone()[0]

                return {
                    'total_feedback': total,
                    'false_positives': fp_count,
                    'confirmed_threats': threat_count,
                    'feedback_rate': (total / total_alerts * 100) if total_alerts > 0 else 0.0
                }

        except Exception as e:
            logger.error(f"Failed to get feedback statistics: {e}")
            return {}

    def get_recent_feedback(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent operator feedback"""
        if not self.enabled:
            return []

        try:
            with self.get_connection() as conn:
                if not conn:
                    return []

                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

                cursor.execute("""
                    SELECT * FROM operator_feedback
                    ORDER BY feedback_timestamp DESC
                    LIMIT %s
                """, (limit,))

                return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            logger.error(f"Failed to get recent feedback: {e}")
            return []

    def _parse_timestamp(self, timestamp_value) -> datetime:
        """
        Parse timestamp from various formats (ISO string, Unix timestamp, or None)

        Args:
            timestamp_value: Can be:
                - ISO format string: "2026-01-03T21:34:40.123456"
                - Unix timestamp (float/int): 1735934000.123
                - None: defaults to current time

        Returns:
            datetime object
        """
        if timestamp_value is None:
            return datetime.now()

        # If it's already a datetime object, return it
        if isinstance(timestamp_value, datetime):
            return timestamp_value

        # If it's a string (ISO format), parse it
        if isinstance(timestamp_value, str):
            try:
                # Handle ISO format: "2026-01-03T21:34:40.123456"
                return datetime.fromisoformat(timestamp_value.replace('Z', '+00:00'))
            except ValueError:
                logger.warning(f"Failed to parse timestamp string: {timestamp_value}, using current time")
                return datetime.now()

        # If it's a number (Unix timestamp), convert it
        if isinstance(timestamp_value, (int, float)):
            try:
                return datetime.fromtimestamp(timestamp_value)
            except (ValueError, OSError) as e:
                logger.warning(f"Failed to parse timestamp number: {timestamp_value}, using current time. Error: {e}")
                return datetime.now()

        # Fallback to current time
        logger.warning(f"Unknown timestamp type: {type(timestamp_value)}, using current time")
        return datetime.now()


# Global database instance
db = DatabaseConnection()
