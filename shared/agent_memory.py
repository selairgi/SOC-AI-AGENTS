"""
Agent Memory System
Provides persistent storage for agent patterns, decisions, and learning.
Supports large-scale memory for prompt injection patterns, alert analysis, and remediation decisions.
"""

import json
import time
import logging
import sqlite3
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict
import threading
from contextlib import contextmanager


@dataclass
class PromptInjectionPattern:
    """Stored prompt injection pattern"""
    pattern_id: str
    pattern: str
    pattern_type: str  # "regex", "keyword", "semantic"
    severity: str
    threat_type: str
    confidence: float
    first_seen: float
    last_seen: float
    detection_count: int
    false_positive_count: int
    true_positive_count: int
    metadata: Dict[str, Any]


@dataclass
class AlertDecision:
    """Stored alert analysis decision"""
    decision_id: str
    alert_id: str
    certainty_score: float
    false_positive_probability: float
    decision: str  # "alert", "false_positive", "investigate"
    reasoning: List[str]
    timestamp: float
    was_correct: Optional[bool] = None  # For learning
    metadata: Dict[str, Any] = None


@dataclass
class RemediationDecision:
    """Stored remediation decision"""
    remediation_id: str
    alert_id: str
    action: str
    target: str
    is_lab_test: bool
    was_blocked: bool
    certainty_score: float
    timestamp: float
    metadata: Dict[str, Any] = None


class AgentMemory:
    """
    Persistent memory system for SOC agents.
    Stores patterns, decisions, and learning data for fine-tuning.
    Uses connection pooling for improved performance.
    """

    def __init__(self, db_path: str = "agent_memory.db", pool_size: int = 5):
        self.logger = logging.getLogger("AgentMemory")
        self.db_path = db_path
        self.lock = threading.Lock()
        self.pool_size = pool_size

        # Connection pool (simple implementation)
        self._connection_pool: List[sqlite3.Connection] = []
        self._pool_lock = threading.Lock()

        # Initialize database and connection pool
        self._init_database()
        self._init_connection_pool()

        # In-memory caches for performance
        self.pattern_cache: Dict[str, PromptInjectionPattern] = {}
        self.decision_cache: Dict[str, AlertDecision] = {}
        self._load_patterns_to_cache()

        self.logger.info(f"Agent Memory initialized with database: {db_path} (pool size: {pool_size})")

    def _init_connection_pool(self):
        """Initialize connection pool"""
        with self._pool_lock:
            for _ in range(self.pool_size):
                conn = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,
                    timeout=5.0
                )
                conn.row_factory = sqlite3.Row
                self._connection_pool.append(conn)
            self.logger.debug(f"Initialized connection pool with {self.pool_size} connections")

    @contextmanager
    def _get_connection(self):
        """Get a connection from the pool (context manager)"""
        conn = None
        try:
            with self._pool_lock:
                if self._connection_pool:
                    conn = self._connection_pool.pop()
                else:
                    # Pool exhausted, create temporary connection
                    self.logger.warning("Connection pool exhausted, creating temporary connection")
                    conn = sqlite3.connect(
                        self.db_path,
                        check_same_thread=False,
                        timeout=5.0
                    )
                    conn.row_factory = sqlite3.Row
            yield conn
        finally:
            if conn:
                with self._pool_lock:
                    if len(self._connection_pool) < self.pool_size:
                        self._connection_pool.append(conn)
                    else:
                        # Pool is full, close this connection
                        conn.close()
    
    def _init_database(self):
        """Initialize SQLite database with required tables (called before pool init)"""
        # Create a temporary connection just for table creation
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=5.0)
        try:
            cursor = conn.cursor()

            # Prompt injection patterns table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS prompt_injection_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    pattern TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    detection_count INTEGER DEFAULT 0,
                    false_positive_count INTEGER DEFAULT 0,
                    true_positive_count INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """)

            # Alert decisions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alert_decisions (
                    decision_id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    certainty_score REAL NOT NULL,
                    false_positive_probability REAL NOT NULL,
                    decision TEXT NOT NULL,
                    reasoning TEXT,
                    timestamp REAL NOT NULL,
                    was_correct INTEGER,
                    metadata TEXT
                )
            """)

            # Remediation decisions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remediation_decisions (
                    remediation_id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    is_lab_test INTEGER NOT NULL,
                    was_blocked INTEGER NOT NULL,
                    certainty_score REAL NOT NULL,
                    timestamp REAL NOT NULL,
                    metadata TEXT
                )
            """)
        
            # Pattern learning history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pattern_learning (
                    learning_id TEXT PRIMARY KEY,
                    pattern_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (pattern_id) REFERENCES prompt_injection_patterns(pattern_id)
                )
            """)

            conn.commit()
        finally:
            conn.close()
    
    def store_prompt_injection_pattern(
        self,
        pattern: str,
        pattern_type: str = "regex",
        severity: str = "high",
        threat_type: str = "prompt_injection",
        confidence: float = 0.8,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Store a new prompt injection pattern"""
        pattern_id = f"PAT_{int(time.time()*1000)}_{hash(pattern) % 10000}"
        
        with self.lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Check if pattern already exists
                cursor.execute(
                    "SELECT pattern_id FROM prompt_injection_patterns WHERE pattern = ?",
                    (pattern,)
                )
                existing = cursor.fetchone()

                if existing:
                    # Update existing pattern
                    pattern_id = existing[0]
                    cursor.execute("""
                        UPDATE prompt_injection_patterns
                        SET last_seen = ?, detection_count = detection_count + 1
                        WHERE pattern_id = ?
                    """, (time.time(), pattern_id))
                else:
                    # Insert new pattern
                    cursor.execute("""
                        INSERT INTO prompt_injection_patterns
                        (pattern_id, pattern, pattern_type, severity, threat_type,
                         confidence, first_seen, last_seen, detection_count, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    """, (
                        pattern_id, pattern, pattern_type, severity, threat_type,
                        confidence, time.time(), time.time(), json.dumps(metadata or {})
                    ))

                conn.commit()
        
        # Update cache (outside lock to avoid deadlock)
        # Don't reload cache immediately - it will be reloaded on next access
        # This prevents deadlock from nested lock acquisition
        
        self.logger.info(f"Stored prompt injection pattern: {pattern_id}")
        return pattern_id
    
    def get_prompt_injection_patterns(
        self,
        threat_type: Optional[str] = None,
        min_confidence: float = 0.0
    ) -> List[PromptInjectionPattern]:
        """Retrieve prompt injection patterns"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=5.0)
            cursor = conn.cursor()
            
            query = """
                SELECT pattern_id, pattern, pattern_type, severity, threat_type,
                       confidence, first_seen, last_seen, detection_count,
                       false_positive_count, true_positive_count, metadata
                FROM prompt_injection_patterns
                WHERE confidence >= ?
            """
            params = [min_confidence]
            
            if threat_type:
                query += " AND threat_type = ?"
                params.append(threat_type)
            
            query += " ORDER BY detection_count DESC, confidence DESC"
            
            try:
                cursor.execute(query, params)
                rows = cursor.fetchall()
            except sqlite3.OperationalError as e:
                # Table might not exist yet (e.g., in-memory database with separate connections)
                if "no such table" in str(e).lower():
                    conn.close()
                    return []
                raise
            conn.close()
            
            patterns = []
            for row in rows:
                patterns.append(PromptInjectionPattern(
                    pattern_id=row[0],
                    pattern=row[1],
                    pattern_type=row[2],
                    severity=row[3],
                    threat_type=row[4],
                    confidence=row[5],
                    first_seen=row[6],
                    last_seen=row[7],
                    detection_count=row[8],
                    false_positive_count=row[9],
                    true_positive_count=row[10],
                    metadata=json.loads(row[11] or "{}")
                ))
            
            return patterns
    
    def store_alert_decision(
        self,
        alert_id: str,
        certainty_score: float,
        false_positive_probability: float,
        decision: str,
        reasoning: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Store an alert analysis decision"""
        decision_id = f"DEC_{int(time.time()*1000)}_{hash(alert_id) % 10000}"
        
        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=5.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO alert_decisions
                (decision_id, alert_id, certainty_score, false_positive_probability,
                 decision, reasoning, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                decision_id, alert_id, certainty_score, false_positive_probability,
                decision, json.dumps(reasoning), time.time(), json.dumps(metadata or {})
            ))
            
            conn.commit()
            conn.close()
            
            # Update cache
            decision_obj = AlertDecision(
                decision_id=decision_id,
                alert_id=alert_id,
                certainty_score=certainty_score,
                false_positive_probability=false_positive_probability,
                decision=decision,
                reasoning=reasoning,
                timestamp=time.time(),
                metadata=metadata or {}
            )
            self.decision_cache[decision_id] = decision_obj
        
        self.logger.debug(f"Stored alert decision: {decision_id} for alert: {alert_id}")
        return decision_id
    
    def update_alert_decision_correctness(
        self,
        decision_id: str,
        was_correct: bool
    ):
        """Update whether an alert decision was correct (for learning)"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=5.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE alert_decisions
                SET was_correct = ?
                WHERE decision_id = ?
            """, (1 if was_correct else 0, decision_id))
            
            conn.commit()
            conn.close()
            
            # Update cache
            if decision_id in self.decision_cache:
                self.decision_cache[decision_id].was_correct = was_correct
    
    def store_remediation_decision(
        self,
        alert_id: str,
        action: str,
        target: str,
        is_lab_test: bool,
        was_blocked: bool,
        certainty_score: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Store a remediation decision"""
        remediation_id = f"REM_{int(time.time()*1000)}_{hash(alert_id) % 10000}"
        
        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=5.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO remediation_decisions
                (remediation_id, alert_id, action, target, is_lab_test,
                 was_blocked, certainty_score, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                remediation_id, alert_id, action, target,
                1 if is_lab_test else 0, 1 if was_blocked else 0,
                certainty_score, time.time(), json.dumps(metadata or {})
            ))
            
            conn.commit()
            conn.close()
        
        self.logger.debug(f"Stored remediation decision: {remediation_id}")
        return remediation_id
    
    def get_alert_decision_statistics(self) -> Dict[str, Any]:
        """Get statistics about alert decisions"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=5.0)
            cursor = conn.cursor()
            
            # Total decisions
            cursor.execute("SELECT COUNT(*) FROM alert_decisions")
            total = cursor.fetchone()[0]
            
            # Decisions by type
            cursor.execute("""
                SELECT decision, COUNT(*) 
                FROM alert_decisions 
                GROUP BY decision
            """)
            by_decision = dict(cursor.fetchall())
            
            # Average certainty scores
            cursor.execute("""
                SELECT AVG(certainty_score), AVG(false_positive_probability)
                FROM alert_decisions
            """)
            avg_scores = cursor.fetchone()
            
            # Correctness rate (where was_correct is set)
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN was_correct = 1 THEN 1 ELSE 0 END) as correct
                FROM alert_decisions
                WHERE was_correct IS NOT NULL
            """)
            correctness = cursor.fetchone()
            
            conn.close()
            
            correctness_rate = (
                correctness[1] / correctness[0] if correctness[0] > 0 else 0.0
            )
            
            return {
                "total_decisions": total,
                "by_decision": by_decision,
                "avg_certainty_score": avg_scores[0] or 0.0,
                "avg_false_positive_probability": avg_scores[1] or 0.0,
                "correctness_rate": correctness_rate,
                "total_with_feedback": correctness[0]
            }
    
    def _load_patterns_to_cache(self):
        """Load patterns into memory cache"""
        patterns = self.get_prompt_injection_patterns()
        self.pattern_cache = {p.pattern_id: p for p in patterns}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall memory statistics"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=5.0)
            cursor = conn.cursor()
            
            stats = {}
            
            # Pattern statistics
            cursor.execute("SELECT COUNT(*) FROM prompt_injection_patterns")
            stats["total_patterns"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT SUM(detection_count) FROM prompt_injection_patterns")
            stats["total_detections"] = cursor.fetchone()[0] or 0
            
            # Decision statistics
            cursor.execute("SELECT COUNT(*) FROM alert_decisions")
            stats["total_alert_decisions"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM remediation_decisions")
            stats["total_remediation_decisions"] = cursor.fetchone()[0]
            
            conn.close()
            
            return stats

