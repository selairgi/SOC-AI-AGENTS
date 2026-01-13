"""
Execution Tracker - Idempotency and audit trail for remediation actions.

Prevents duplicate execution and provides audit logging.
"""

import hashlib
import time
import uuid
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from threading import Lock


@dataclass
class ExecutionRecord:
    """Record of an executed action."""
    execution_id: str
    action: str
    target: str
    correlation_id: str
    timestamp: float
    status: str  # executed, skipped, failed, pending
    dry_run: bool = False
    result: Optional[str] = None
    error: Optional[str] = None
    ttl: int = 3600  # 1 hour default

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ExecutionTracker:
    """
    Tracks executed actions for idempotency and audit.

    Features:
    - Prevents duplicate execution within TTL
    - Maintains audit trail
    - Thread-safe operations
    - Automatic cleanup of expired records

    Usage:
        tracker = ExecutionTracker()

        # Check if already executed
        if tracker.is_executed("block_ip", "192.168.1.1", "corr-123"):
            print("Already executed, skipping")
        else:
            # Execute and record
            tracker.record("block_ip", "192.168.1.1", "corr-123", "executed")
    """

    def __init__(
        self,
        default_ttl: int = 3600,
        max_records: int = 10000,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize execution tracker.

        Args:
            default_ttl: Default time-to-live for records in seconds
            max_records: Maximum records before forced cleanup
            logger: Optional logger instance
        """
        self.default_ttl = default_ttl
        self.max_records = max_records
        self.logger = logger or logging.getLogger("ExecutionTracker")

        self._records: Dict[str, ExecutionRecord] = {}
        self._hashes: Dict[str, str] = {}  # hash -> execution_id
        self._lock = Lock()

        # Stats
        self.stats = {
            "total_recorded": 0,
            "duplicates_prevented": 0,
            "cleanups_performed": 0
        }

    def _generate_hash(self, action: str, target: str, correlation_id: str) -> str:
        """Generate unique hash for action."""
        content = f"{action}:{target}:{correlation_id}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _generate_id(self) -> str:
        """Generate unique execution ID."""
        return str(uuid.uuid4())[:12]

    def is_executed(
        self,
        action: str,
        target: str,
        correlation_id: str
    ) -> bool:
        """
        Check if action was already executed.

        Args:
            action: Action type
            target: Target identifier
            correlation_id: Correlation ID

        Returns:
            True if already executed within TTL
        """
        action_hash = self._generate_hash(action, target, correlation_id)

        with self._lock:
            if action_hash not in self._hashes:
                return False

            exec_id = self._hashes[action_hash]
            if exec_id not in self._records:
                return False

            record = self._records[exec_id]

            # Check TTL
            if time.time() - record.timestamp > record.ttl:
                return False

            # Check status
            if record.status in ("executed", "skipped"):
                self.stats["duplicates_prevented"] += 1
                return True

        return False

    def get_record(
        self,
        action: str,
        target: str,
        correlation_id: str
    ) -> Optional[ExecutionRecord]:
        """Get existing execution record if any."""
        action_hash = self._generate_hash(action, target, correlation_id)

        with self._lock:
            if action_hash in self._hashes:
                exec_id = self._hashes[action_hash]
                return self._records.get(exec_id)
        return None

    def record(
        self,
        action: str,
        target: str,
        correlation_id: str,
        status: str,
        dry_run: bool = False,
        result: Optional[str] = None,
        error: Optional[str] = None,
        ttl: Optional[int] = None
    ) -> str:
        """
        Record an action execution.

        Args:
            action: Action type
            target: Target identifier
            correlation_id: Correlation ID
            status: Execution status
            dry_run: If this was a dry run
            result: Optional result message
            error: Optional error message
            ttl: Optional custom TTL

        Returns:
            Execution ID
        """
        exec_id = self._generate_id()
        action_hash = self._generate_hash(action, target, correlation_id)

        record = ExecutionRecord(
            execution_id=exec_id,
            action=action,
            target=target,
            correlation_id=correlation_id,
            timestamp=time.time(),
            status=status,
            dry_run=dry_run,
            result=result,
            error=error,
            ttl=ttl or self.default_ttl
        )

        with self._lock:
            self._records[exec_id] = record
            self._hashes[action_hash] = exec_id
            self.stats["total_recorded"] += 1

            # Cleanup if too many records
            if len(self._records) > self.max_records:
                self._cleanup_expired()

        self.logger.debug(f"Recorded: {action}:{target} -> {status}")
        return exec_id

    def update_status(
        self,
        execution_id: str,
        status: str,
        result: Optional[str] = None,
        error: Optional[str] = None
    ) -> bool:
        """Update status of existing record."""
        with self._lock:
            if execution_id not in self._records:
                return False

            record = self._records[execution_id]
            record.status = status
            if result:
                record.result = result
            if error:
                record.error = error
            return True

    def _cleanup_expired(self) -> int:
        """Remove expired records. Must be called with lock held."""
        now = time.time()
        expired_ids = [
            exec_id for exec_id, record in self._records.items()
            if now - record.timestamp > record.ttl
        ]

        for exec_id in expired_ids:
            del self._records[exec_id]

        # Clean up orphaned hashes
        valid_ids = set(self._records.keys())
        orphaned = [h for h, eid in self._hashes.items() if eid not in valid_ids]
        for h in orphaned:
            del self._hashes[h]

        if expired_ids:
            self.stats["cleanups_performed"] += 1
            self.logger.debug(f"Cleaned up {len(expired_ids)} expired records")

        return len(expired_ids)

    def cleanup(self) -> int:
        """Manually trigger cleanup."""
        with self._lock:
            return self._cleanup_expired()

    def get_history(
        self,
        correlation_id: Optional[str] = None,
        action: Optional[str] = None,
        hours: int = 24,
        limit: int = 100
    ) -> List[ExecutionRecord]:
        """
        Get execution history.

        Args:
            correlation_id: Filter by correlation ID
            action: Filter by action type
            hours: How far back to look
            limit: Maximum records to return

        Returns:
            List of execution records
        """
        cutoff = time.time() - (hours * 3600)

        with self._lock:
            records = [
                r for r in self._records.values()
                if r.timestamp >= cutoff
                and (correlation_id is None or r.correlation_id == correlation_id)
                and (action is None or r.action == action)
            ]

        # Sort by timestamp descending
        records.sort(key=lambda r: r.timestamp, reverse=True)
        return records[:limit]

    def export_audit_log(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Export audit log for given time period."""
        records = self.get_history(hours=hours, limit=10000)
        return [
            {
                **r.to_dict(),
                "timestamp_iso": datetime.fromtimestamp(r.timestamp).isoformat()
            }
            for r in records
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get tracker statistics."""
        with self._lock:
            status_counts = {}
            for r in self._records.values():
                status_counts[r.status] = status_counts.get(r.status, 0) + 1

            return {
                **self.stats,
                "active_records": len(self._records),
                "status_breakdown": status_counts,
                "duplicate_rate": (
                    self.stats["duplicates_prevented"] /
                    max(self.stats["total_recorded"], 1)
                )
            }
