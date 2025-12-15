"""
Execution tracking and idempotency for SOC AI Agents.
Tracks executed actions to prevent duplicate execution and provides audit trail.
"""

import asyncio
import hashlib
import time
import uuid
from typing import Dict, Set, Optional, List, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import json
import logging

# Import config from current package
try:
    from .config import LOG_GENERATION_INTERVAL
except ImportError:
    from shared.config import LOG_GENERATION_INTERVAL


@dataclass
class ExecutionRecord:
    """Record of an executed action for idempotency tracking."""
    execution_id: str
    playbook_id: str
    action_id: str
    action_name: str
    target: str
    timestamp: float
    status: str  # "executed", "skipped", "failed"
    result: Optional[str] = None
    error: Optional[str] = None
    ttl: float = 3600  # 1 hour default TTL


@dataclass
class PlaybookExecution:
    """Record of a playbook execution."""
    playbook_id: str
    alert_id: str
    timestamp: float
    status: str  # "pending", "executing", "completed", "failed"
    actions: List[str]
    executed_actions: Set[str] = None
    failed_actions: Set[str] = None
    ttl: float = 3600  # 1 hour default TTL


class ExecutionTracker:
    """Tracks executed actions to ensure idempotency and prevent duplicate execution."""
    
    def __init__(self, default_ttl: int = 3600):
        self.default_ttl = default_ttl
        self.logger = logging.getLogger("ExecutionTracker")
        
        # In-memory storage (in production, use Redis or similar)
        self._execution_records: Dict[str, ExecutionRecord] = {}
        self._playbook_executions: Dict[str, PlaybookExecution] = {}
        self._action_hashes: Dict[str, str] = {}  # action_hash -> execution_id
        
        # Statistics
        self.stats = {
            "total_executions": 0,
            "duplicate_skipped": 0,
            "execution_failures": 0,
            "playbook_executions": 0,
            "playbook_failures": 0
        }
        
        # Start cleanup thread
        self._cleanup_thread = None
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        """Start background thread to clean up expired records."""
        import threading

        def cleanup():
            while True:
                try:
                    self._cleanup_expired_records_sync()
                    time.sleep(60)  # Cleanup every minute
                except Exception as e:
                    self.logger.error(f"Error in cleanup thread: {e}")

        self._cleanup_thread = threading.Thread(target=cleanup, daemon=True)
        self._cleanup_thread.start()
    
    def _cleanup_expired_records_sync(self):
        """Remove expired execution records (synchronous version)."""
        current_time = time.time()

        # Clean up execution records
        expired_executions = [
            exec_id for exec_id, record in self._execution_records.items()
            if current_time - record.timestamp > record.ttl
        ]

        for exec_id in expired_executions:
            del self._execution_records[exec_id]

        # Clean up playbook executions
        expired_playbooks = [
            playbook_id for playbook_id, playbook in self._playbook_executions.items()
            if current_time - playbook.timestamp > playbook.ttl
        ]

        for playbook_id in expired_playbooks:
            del self._playbook_executions[playbook_id]

        # Clean up action hashes
        expired_hashes = [
            action_hash for action_hash, exec_id in self._action_hashes.items()
            if exec_id not in self._execution_records
        ]

        for action_hash in expired_hashes:
            del self._action_hashes[action_hash]

        if expired_executions or expired_playbooks or expired_hashes:
            self.logger.debug(
                f"Cleaned up {len(expired_executions)} executions, "
                f"{len(expired_playbooks)} playbooks, "
                f"{len(expired_hashes)} hashes"
            )

    async def _cleanup_expired_records(self):
        """Remove expired execution records."""
        current_time = time.time()
        
        # Clean up execution records
        expired_executions = [
            exec_id for exec_id, record in self._execution_records.items()
            if current_time - record.timestamp > record.ttl
        ]
        
        for exec_id in expired_executions:
            del self._execution_records[exec_id]
        
        # Clean up playbook executions
        expired_playbooks = [
            playbook_id for playbook_id, playbook in self._playbook_executions.items()
            if current_time - playbook.timestamp > playbook.ttl
        ]
        
        for playbook_id in expired_playbooks:
            del self._playbook_executions[playbook_id]
        
        # Clean up action hashes
        expired_hashes = [
            action_hash for action_hash, exec_id in self._action_hashes.items()
            if exec_id not in self._execution_records
        ]
        
        for action_hash in expired_hashes:
            del self._action_hashes[action_hash]
        
        if expired_executions or expired_playbooks:
            self.logger.debug(f"Cleaned up {len(expired_executions)} executions and {len(expired_playbooks)} playbooks")
    
    def _generate_action_hash(self, action_name: str, target: str, playbook_id: str) -> str:
        """Generate a unique hash for an action to detect duplicates."""
        content = f"{action_name}:{target}:{playbook_id}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _generate_execution_id(self) -> str:
        """Generate a unique execution ID."""
        return str(uuid.uuid4())
    
    def _generate_playbook_id(self, alert_id: str, action: str) -> str:
        """Generate a unique playbook ID."""
        content = f"{alert_id}:{action}:{time.time()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _generate_action_id(self, action_name: str, target: str) -> str:
        """Generate a unique action ID."""
        content = f"{action_name}:{target}:{time.time()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def is_action_executed(self, action_name: str, target: str, playbook_id: str) -> tuple[bool, Optional[ExecutionRecord]]:
        """Check if an action has already been executed within TTL."""
        action_hash = self._generate_action_hash(action_name, target, playbook_id)
        
        if action_hash in self._action_hashes:
            execution_id = self._action_hashes[action_hash]
            if execution_id in self._execution_records:
                record = self._execution_records[execution_id]
                # Check if still within TTL
                if time.time() - record.timestamp <= record.ttl:
                    return True, record
        
        return False, None
    
    def record_action_execution(self, action_name: str, target: str, playbook_id: str, 
                              status: str, result: Optional[str] = None, error: Optional[str] = None) -> str:
        """Record an action execution."""
        execution_id = self._generate_execution_id()
        action_id = self._generate_action_id(action_name, target)
        action_hash = self._generate_action_hash(action_name, target, playbook_id)
        
        record = ExecutionRecord(
            execution_id=execution_id,
            playbook_id=playbook_id,
            action_id=action_id,
            action_name=action_name,
            target=target,
            timestamp=time.time(),
            status=status,
            result=result,
            error=error,
            ttl=self.default_ttl
        )
        
        self._execution_records[execution_id] = record
        self._action_hashes[action_hash] = execution_id
        
        self.stats["total_executions"] += 1
        if status == "skipped":
            self.stats["duplicate_skipped"] += 1
        elif status == "failed":
            self.stats["execution_failures"] += 1
        
        self.logger.debug(f"Recorded action execution: {action_name}:{target} -> {status}")
        return execution_id
    
    def start_playbook_execution(self, alert_id: str, action: str, actions: List[str]) -> str:
        """Start tracking a playbook execution."""
        playbook_id = self._generate_playbook_id(alert_id, action)
        
        playbook_execution = PlaybookExecution(
            playbook_id=playbook_id,
            alert_id=alert_id,
            timestamp=time.time(),
            status="pending",
            actions=actions,
            executed_actions=set(),
            failed_actions=set(),
            ttl=self.default_ttl
        )
        
        self._playbook_executions[playbook_id] = playbook_execution
        self.stats["playbook_executions"] += 1
        
        self.logger.debug(f"Started playbook execution: {playbook_id}")
        return playbook_id
    
    def update_playbook_execution(self, playbook_id: str, action_id: str, status: str):
        """Update playbook execution with action result."""
        if playbook_id not in self._playbook_executions:
            self.logger.warning(f"Playbook execution not found: {playbook_id}")
            return
        
        playbook = self._playbook_executions[playbook_id]
        
        if status == "executed":
            playbook.executed_actions.add(action_id)
        elif status == "failed":
            playbook.failed_actions.add(action_id)
        
        # Update overall playbook status
        total_actions = len(playbook.actions)
        executed_count = len(playbook.executed_actions)
        failed_count = len(playbook.failed_actions)
        
        if executed_count + failed_count == total_actions:
            if failed_count == 0:
                playbook.status = "completed"
            else:
                playbook.status = "failed"
                self.stats["playbook_failures"] += 1
        
        self.logger.debug(f"Updated playbook execution: {playbook_id} -> {playbook.status}")
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics."""
        return {
            **self.stats,
            "active_executions": len(self._execution_records),
            "active_playbooks": len(self._playbook_executions),
            "duplicate_rate": (
                self.stats["duplicate_skipped"] / max(self.stats["total_executions"], 1)
            ) * 100
        }
    
    def get_playbook_execution(self, playbook_id: str) -> Optional[PlaybookExecution]:
        """Get playbook execution details."""
        return self._playbook_executions.get(playbook_id)
    
    def get_action_execution_history(self, action_name: str, target: str, 
                                   hours: int = 24) -> List[ExecutionRecord]:
        """Get execution history for a specific action and target."""
        cutoff_time = time.time() - (hours * 3600)
        
        return [
            record for record in self._execution_records.values()
            if (record.action_name == action_name and 
                record.target == target and 
                record.timestamp >= cutoff_time)
        ]
    
    def export_audit_log(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Export audit log for the specified time period."""
        cutoff_time = time.time() - (hours * 3600)
        
        audit_records = []
        
        # Add execution records
        for record in self._execution_records.values():
            if record.timestamp >= cutoff_time:
                audit_records.append({
                    "type": "action_execution",
                    "timestamp": datetime.fromtimestamp(record.timestamp).isoformat(),
                    "data": asdict(record)
                })
        
        # Add playbook executions
        for playbook in self._playbook_executions.values():
            if playbook.timestamp >= cutoff_time:
                audit_records.append({
                    "type": "playbook_execution",
                    "timestamp": datetime.fromtimestamp(playbook.timestamp).isoformat(),
                    "data": asdict(playbook)
                })
        
        # Sort by timestamp
        audit_records.sort(key=lambda x: x["timestamp"])
        return audit_records
    
    def stop(self):
        """Stop the execution tracker and cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
        self.logger.info("Execution tracker stopped")
