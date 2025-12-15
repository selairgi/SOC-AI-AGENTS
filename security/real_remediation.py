"""
Real Remediation Module
Implements actual remediation actions at application level:
- Rate limiting
- Session termination
- IP blocking
- User suspension
- Alert notifications
"""

import time
import logging
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading


@dataclass
class BlockedEntity:
    """Represents a blocked entity (IP, user, session)"""
    entity_id: str
    entity_type: str  # "ip", "user", "session"
    reason: str
    blocked_at: float
    blocked_until: Optional[float] = None  # None = permanent
    alert_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RateLimitBucket:
    """Rate limit bucket for tracking requests"""
    entity_id: str
    requests: deque = field(default_factory=deque)
    limit: int = 10
    window: float = 60.0  # seconds
    blocked_until: Optional[float] = None


class RealRemediationEngine:
    """
    Real remediation engine that actually takes actions.
    All actions are at application level and don't require system privileges.
    """

    def __init__(self):
        self.logger = logging.getLogger("RealRemediationEngine")

        # Blocked entities
        self.blocked_ips: Dict[str, BlockedEntity] = {}
        self.blocked_users: Dict[str, BlockedEntity] = {}
        self.blocked_sessions: Dict[str, BlockedEntity] = {}

        # Rate limiting
        self.rate_limit_buckets: Dict[str, RateLimitBucket] = {}
        self.default_rate_limit = 10  # requests per minute
        self.rate_limit_window = 60.0  # seconds

        # Suspended users
        self.suspended_users: Dict[str, BlockedEntity] = {}

        # Session tracking
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.terminated_sessions: Set[str] = set()

        # Alert history
        self.alert_history: List[Dict[str, Any]] = []

        # Statistics
        self.stats = {
            "ips_blocked": 0,
            "users_suspended": 0,
            "sessions_terminated": 0,
            "rate_limits_applied": 0,
            "total_actions": 0,
            "actions_by_type": defaultdict(int)
        }

        # Lock for thread safety
        self.lock = threading.Lock()

        # Start cleanup thread
        self._start_cleanup_thread()

        self.logger.info("Real Remediation Engine initialized")

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked"""
        with self.lock:
            if ip in self.blocked_ips:
                block = self.blocked_ips[ip]
                # Check if block has expired
                if block.blocked_until and time.time() > block.blocked_until:
                    del self.blocked_ips[ip]
                    self.logger.info(f"IP block expired for {ip}")
                    return False
                return True
            return False

    def is_user_blocked(self, user_id: str) -> bool:
        """Check if a user is blocked or suspended"""
        with self.lock:
            if user_id in self.blocked_users:
                block = self.blocked_users[user_id]
                if block.blocked_until and time.time() > block.blocked_until:
                    del self.blocked_users[user_id]
                    self.logger.info(f"User block expired for {user_id}")
                    return False
                return True
            if user_id in self.suspended_users:
                suspension = self.suspended_users[user_id]
                if suspension.blocked_until and time.time() > suspension.blocked_until:
                    del self.suspended_users[user_id]
                    self.logger.info(f"User suspension expired for {user_id}")
                    return False
                return True
            return False

    def is_session_terminated(self, session_id: str) -> bool:
        """Check if a session is terminated"""
        return session_id in self.terminated_sessions

    def check_rate_limit(self, entity_id: str, entity_type: str = "ip") -> tuple[bool, Optional[float]]:
        """
        Check if entity is rate limited.

        Returns:
            (is_allowed, retry_after_seconds)
        """
        with self.lock:
            bucket_key = f"{entity_type}:{entity_id}"

            # Check if explicitly rate limited
            if bucket_key in self.rate_limit_buckets:
                bucket = self.rate_limit_buckets[bucket_key]

                # Check if still blocked
                if bucket.blocked_until and time.time() < bucket.blocked_until:
                    retry_after = bucket.blocked_until - time.time()
                    return False, retry_after

                # Clean old requests
                current_time = time.time()
                cutoff_time = current_time - bucket.window
                while bucket.requests and bucket.requests[0] < cutoff_time:
                    bucket.requests.popleft()

                # Check rate limit
                if len(bucket.requests) >= bucket.limit:
                    # Rate limit exceeded
                    bucket.blocked_until = current_time + bucket.window
                    retry_after = bucket.window
                    self.logger.warning(
                        f"Rate limit exceeded for {entity_type} {entity_id}: "
                        f"{len(bucket.requests)} requests in {bucket.window}s window"
                    )
                    return False, retry_after

                # Add current request
                bucket.requests.append(current_time)
                return True, None

            # No rate limit applied - allow
            return True, None

    def block_ip(
        self,
        ip: str,
        reason: str,
        duration: Optional[float] = None,
        alert_id: Optional[str] = None
    ) -> bool:
        """
        Block an IP address.

        Args:
            ip: IP address to block
            reason: Reason for blocking
            duration: Duration in seconds (None = permanent)
            alert_id: Associated alert ID

        Returns:
            True if successfully blocked
        """
        with self.lock:
            blocked_until = time.time() + duration if duration else None

            block = BlockedEntity(
                entity_id=ip,
                entity_type="ip",
                reason=reason,
                blocked_at=time.time(),
                blocked_until=blocked_until,
                alert_id=alert_id,
                metadata={"duration": duration}
            )

            self.blocked_ips[ip] = block
            self.stats["ips_blocked"] += 1
            self.stats["total_actions"] += 1
            self.stats["actions_by_type"]["block_ip"] += 1

            duration_str = f"{duration}s" if duration else "permanently"
            self.logger.warning(f"🚫 BLOCKED IP: {ip} {duration_str} - Reason: {reason}")

            self._record_action("block_ip", {
                "ip": ip,
                "reason": reason,
                "duration": duration,
                "alert_id": alert_id
            })

            return True

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self.logger.info(f"✅ Unblocked IP: {ip}")
                return True
            return False

    def suspend_user(
        self,
        user_id: str,
        reason: str,
        duration: Optional[float] = None,
        alert_id: Optional[str] = None
    ) -> bool:
        """
        Suspend a user account.

        Args:
            user_id: User ID to suspend
            reason: Reason for suspension
            duration: Duration in seconds (None = permanent)
            alert_id: Associated alert ID

        Returns:
            True if successfully suspended
        """
        with self.lock:
            blocked_until = time.time() + duration if duration else None

            suspension = BlockedEntity(
                entity_id=user_id,
                entity_type="user",
                reason=reason,
                blocked_at=time.time(),
                blocked_until=blocked_until,
                alert_id=alert_id,
                metadata={"duration": duration}
            )

            self.suspended_users[user_id] = suspension
            self.stats["users_suspended"] += 1
            self.stats["total_actions"] += 1
            self.stats["actions_by_type"]["suspend_user"] += 1

            duration_str = f"{duration}s" if duration else "permanently"
            self.logger.warning(f"🚫 SUSPENDED USER: {user_id} {duration_str} - Reason: {reason}")

            self._record_action("suspend_user", {
                "user_id": user_id,
                "reason": reason,
                "duration": duration,
                "alert_id": alert_id
            })

            return True

    def terminate_session(
        self,
        session_id: str,
        reason: str,
        alert_id: Optional[str] = None
    ) -> bool:
        """
        Terminate a session.

        Args:
            session_id: Session ID to terminate
            reason: Reason for termination
            alert_id: Associated alert ID

        Returns:
            True if successfully terminated
        """
        with self.lock:
            self.terminated_sessions.add(session_id)

            # Remove from active sessions if present
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]

            self.stats["sessions_terminated"] += 1
            self.stats["total_actions"] += 1
            self.stats["actions_by_type"]["terminate_session"] += 1

            self.logger.warning(f"🚫 TERMINATED SESSION: {session_id} - Reason: {reason}")

            self._record_action("terminate_session", {
                "session_id": session_id,
                "reason": reason,
                "alert_id": alert_id
            })

            return True

    def apply_rate_limit(
        self,
        entity_id: str,
        entity_type: str = "ip",
        limit: int = 10,
        window: float = 60.0,
        alert_id: Optional[str] = None
    ) -> bool:
        """
        Apply rate limiting to an entity.

        Args:
            entity_id: Entity to rate limit (IP, user, etc.)
            entity_type: Type of entity ("ip", "user", "session")
            limit: Number of requests allowed
            window: Time window in seconds
            alert_id: Associated alert ID

        Returns:
            True if successfully applied
        """
        with self.lock:
            bucket_key = f"{entity_type}:{entity_id}"

            bucket = RateLimitBucket(
                entity_id=entity_id,
                requests=deque(),
                limit=limit,
                window=window
            )

            self.rate_limit_buckets[bucket_key] = bucket
            self.stats["rate_limits_applied"] += 1
            self.stats["total_actions"] += 1
            self.stats["actions_by_type"]["rate_limit"] += 1

            self.logger.warning(
                f"⏱️  RATE LIMIT APPLIED: {entity_type} {entity_id} - "
                f"{limit} requests per {window}s"
            )

            self._record_action("rate_limit", {
                "entity_id": entity_id,
                "entity_type": entity_type,
                "limit": limit,
                "window": window,
                "alert_id": alert_id
            })

            return True

    def remove_rate_limit(self, entity_id: str, entity_type: str = "ip") -> bool:
        """Remove rate limiting from an entity"""
        with self.lock:
            bucket_key = f"{entity_type}:{entity_id}"
            if bucket_key in self.rate_limit_buckets:
                del self.rate_limit_buckets[bucket_key]
                self.logger.info(f"✅ Removed rate limit: {entity_type} {entity_id}")
                return True
            return False

    def record_alert(
        self,
        alert_id: str,
        severity: str,
        threat_type: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Record an alert for tracking"""
        alert_record = {
            "alert_id": alert_id,
            "timestamp": time.time(),
            "severity": severity,
            "threat_type": threat_type,
            "description": description,
            "metadata": metadata or {}
        }

        self.alert_history.append(alert_record)

        # Keep only last 1000 alerts
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-1000:]

        self.logger.info(f"📝 Recorded alert: {alert_id} ({severity}) - {threat_type}")

    def get_blocked_entities(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all currently blocked entities"""
        with self.lock:
            return {
                "ips": [
                    {
                        "ip": ip,
                        "reason": block.reason,
                        "blocked_at": block.blocked_at,
                        "blocked_until": block.blocked_until,
                        "alert_id": block.alert_id
                    }
                    for ip, block in self.blocked_ips.items()
                ],
                "users": [
                    {
                        "user_id": user,
                        "reason": block.reason,
                        "blocked_at": block.blocked_at,
                        "blocked_until": block.blocked_until,
                        "alert_id": block.alert_id
                    }
                    for user, block in self.suspended_users.items()
                ],
                "sessions": list(self.terminated_sessions)
            }

    def get_rate_limits(self) -> List[Dict[str, Any]]:
        """Get all active rate limits"""
        with self.lock:
            return [
                {
                    "entity_id": bucket.entity_id,
                    "limit": bucket.limit,
                    "window": bucket.window,
                    "current_requests": len(bucket.requests),
                    "blocked_until": bucket.blocked_until
                }
                for bucket in self.rate_limit_buckets.values()
            ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get remediation statistics"""
        with self.lock:
            return {
                **self.stats,
                "currently_blocked_ips": len(self.blocked_ips),
                "currently_suspended_users": len(self.suspended_users),
                "currently_terminated_sessions": len(self.terminated_sessions),
                "active_rate_limits": len(self.rate_limit_buckets),
                "recent_alerts": len(self.alert_history)
            }

    def _record_action(self, action_type: str, details: Dict[str, Any]):
        """Record an action for audit trail"""
        # This could be extended to write to a database or log file
        self.logger.debug(f"Action recorded: {action_type} - {details}")

    def _cleanup_expired_blocks(self):
        """Clean up expired blocks and rate limits"""
        with self.lock:
            current_time = time.time()

            # Cleanup expired IP blocks
            expired_ips = [
                ip for ip, block in self.blocked_ips.items()
                if block.blocked_until and current_time > block.blocked_until
            ]
            for ip in expired_ips:
                del self.blocked_ips[ip]
                self.logger.debug(f"Cleaned up expired IP block: {ip}")

            # Cleanup expired user suspensions
            expired_users = [
                user for user, block in self.suspended_users.items()
                if block.blocked_until and current_time > block.blocked_until
            ]
            for user in expired_users:
                del self.suspended_users[user]
                self.logger.debug(f"Cleaned up expired user suspension: {user}")

            # Cleanup expired rate limit blocks
            for bucket_key, bucket in list(self.rate_limit_buckets.items()):
                if bucket.blocked_until and current_time > bucket.blocked_until:
                    bucket.blocked_until = None

                # Clean old requests
                cutoff_time = current_time - bucket.window
                while bucket.requests and bucket.requests[0] < cutoff_time:
                    bucket.requests.popleft()

    def _start_cleanup_thread(self):
        """Start background thread for cleanup"""
        def cleanup_loop():
            while True:
                time.sleep(60)  # Run every minute
                try:
                    self._cleanup_expired_blocks()
                except Exception as e:
                    self.logger.error(f"Error in cleanup thread: {e}")

        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
        self.logger.info("Cleanup thread started")

    def clear_all(self):
        """Clear all blocks and rate limits (for testing)"""
        with self.lock:
            self.blocked_ips.clear()
            self.blocked_users.clear()
            self.suspended_users.clear()
            self.terminated_sessions.clear()
            self.rate_limit_buckets.clear()
            self.logger.info("All blocks and rate limits cleared")
