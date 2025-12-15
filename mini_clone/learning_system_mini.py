#!/usr/bin/env python3
"""
Mini Learning System - Full OpenAI Integration

This version uses real OpenAI API to generate variations,
testing the complete incremental learning workflow.
"""

import json
import time
import logging
import sqlite3
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class MissedAttack:
    """Attack that bypassed detection"""
    id: str
    message: str
    response: str  # AI response (contains flag)
    timestamp: float
    flag_detected: bool
    detection_confidence: float


@dataclass
class LearnedPattern:
    """Pattern learned from missed attack"""
    id: str
    original_attack_id: str
    variation_text: str
    technique: str
    confidence: float
    timestamp: float


class MiniLearningSystem:
    """
    Simplified learning system for testing

    Features:
    - Real OpenAI integration
    - Automatic variation generation
    - Pattern storage
    - Learning metrics
    """

    def __init__(self, ai_integration, db_path: str = "mini_learning.db"):
        self.logger = logging.getLogger("MiniLearning")
        self.ai = ai_integration
        self.db_path = db_path

        # Initialize database
        self._init_database()

        # Learned patterns (in-memory cache)
        self.learned_keywords: set = set()

        # Load existing keywords
        self._load_learned_keywords()

        self.logger.info("Mini Learning System initialized")

    def _get_connection(self):
        """Get database connection with timeout"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")  # Enable Write-Ahead Logging for better concurrency
        return conn

    def _init_database(self):
        """Initialize SQLite database"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Missed attacks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS missed_attacks (
                id TEXT PRIMARY KEY,
                message TEXT NOT NULL,
                response TEXT NOT NULL,
                timestamp REAL NOT NULL,
                flag_detected INTEGER NOT NULL,
                detection_confidence REAL NOT NULL,
                processed INTEGER DEFAULT 0,
                variations_generated INTEGER DEFAULT 0
            )
        """)

        # Learned patterns table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learned_patterns (
                id TEXT PRIMARY KEY,
                original_attack_id TEXT NOT NULL,
                variation_text TEXT NOT NULL,
                technique TEXT NOT NULL,
                confidence REAL NOT NULL,
                timestamp REAL NOT NULL,
                FOREIGN KEY (original_attack_id) REFERENCES missed_attacks(id)
            )
        """)

        # Keywords table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learned_keywords (
                keyword TEXT PRIMARY KEY,
                frequency INTEGER DEFAULT 1,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL
            )
        """)

        # Metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learning_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                total_attacks INTEGER,
                variations_generated INTEGER,
                keywords_learned INTEGER
            )
        """)

        conn.commit()
        conn.close()

        self.logger.info(f"Database initialized: {self.db_path}")

    def _load_learned_keywords(self):
        """Load learned keywords into memory"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT keyword FROM learned_keywords")
        rows = cursor.fetchall()

        for row in rows:
            self.learned_keywords.add(row[0])

        conn.close()

        self.logger.info(f"Loaded {len(self.learned_keywords)} learned keywords")

    def report_missed_attack(
        self,
        user_message: str,
        ai_response: str,
        flag_detection: Dict[str, Any]
    ) -> str:
        """
        Report an attack that revealed the flag

        Args:
            user_message: User's attack message
            ai_response: AI response (contains flag)
            flag_detection: Flag detection result

        Returns:
            Attack ID
        """
        import uuid

        attack_id = str(uuid.uuid4())

        # Store missed attack
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO missed_attacks
            (id, message, response, timestamp, flag_detected, detection_confidence, processed)
            VALUES (?, ?, ?, ?, ?, ?, 0)
        """, (
            attack_id,
            user_message,
            ai_response,
            time.time(),
            1,
            flag_detection.get('confidence', 1.0)
        ))

        conn.commit()
        conn.close()

        self.logger.warning(f"🚨 Missed attack reported: {attack_id}")
        self.logger.warning(f"   Attack: {user_message[:60]}...")
        self.logger.warning(f"   Flag revealed in response!")

        # Process immediately
        self.process_missed_attack(attack_id)

        return attack_id

    def process_missed_attack(self, attack_id: str) -> int:
        """
        Process missed attack and generate variations

        Args:
            attack_id: Attack ID to process

        Returns:
            Number of variations generated
        """
        # Get attack
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT message FROM missed_attacks WHERE id = ? AND processed = 0
        """, (attack_id,))

        row = cursor.fetchone()
        if not row:
            conn.close()
            return 0

        original_message = row[0]

        self.logger.info(f"Processing attack: {attack_id}")
        self.logger.info(f"Generating variations using OpenAI GPT-4...")

        # Generate variations using OpenAI
        variations = self.ai.generate_attack_variations(
            original_attack=original_message,
            threat_type="PROMPT_INJECTION",
            count=15
        )

        self.logger.info(f"✅ Generated {len(variations)} variations")

        # Store variations
        for var in variations:
            import uuid
            variation_id = str(uuid.uuid4())

            cursor.execute("""
                INSERT INTO learned_patterns
                (id, original_attack_id, variation_text, technique, confidence, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                variation_id,
                attack_id,
                var['variation'],
                var['technique'],
                var['confidence'],
                time.time()
            ))

            # Extract keywords
            keywords = self._extract_keywords(var['variation'])
            for keyword in keywords:
                self._add_keyword_internal(cursor, keyword)

        # Mark as processed
        cursor.execute("""
            UPDATE missed_attacks
            SET processed = 1, variations_generated = ?
            WHERE id = ?
        """, (len(variations), attack_id))

        # Update metrics
        cursor.execute("""
            INSERT INTO learning_metrics (timestamp, total_attacks, variations_generated, keywords_learned)
            SELECT ?, COUNT(*), SUM(variations_generated), ? FROM missed_attacks WHERE processed = 1
        """, (time.time(), len(self.learned_keywords)))

        conn.commit()
        conn.close()

        self.logger.info(f"✅ Attack processed: {len(variations)} variations, {len(self.learned_keywords)} keywords")

        return len(variations)

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract keywords from text"""
        import re

        # Simple keyword extraction
        words = re.findall(r'\b\w+\b', text.lower())

        # Filter out stop words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'is', 'are'}
        keywords = [w for w in words if w not in stop_words and len(w) > 3]

        # Also extract 2-word phrases
        phrases = []
        for i in range(len(words) - 1):
            phrase = f"{words[i]} {words[i+1]}"
            if len(phrase) > 8:
                phrases.append(phrase)

        return list(set(keywords + phrases))[:10]  # Top 10

    def _add_keyword_internal(self, cursor, keyword: str):
        """Add keyword to learned patterns (internal - uses existing cursor)"""
        # Check if exists
        cursor.execute("SELECT frequency FROM learned_keywords WHERE keyword = ?", (keyword,))
        row = cursor.fetchone()

        if row:
            # Update frequency
            cursor.execute("""
                UPDATE learned_keywords
                SET frequency = frequency + 1, last_seen = ?
                WHERE keyword = ?
            """, (time.time(), keyword))
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO learned_keywords (keyword, frequency, first_seen, last_seen)
                VALUES (?, 1, ?, ?)
            """, (keyword, time.time(), time.time()))

            self.learned_keywords.add(keyword)

    def _add_keyword(self, keyword: str):
        """Add keyword to learned patterns (external API - opens own connection)"""
        conn = self._get_connection()
        cursor = conn.cursor()

        self._add_keyword_internal(cursor, keyword)

        conn.commit()
        conn.close()

    def check_if_learned(self, message: str) -> Dict[str, Any]:
        """
        Check if message matches learned patterns

        Args:
            message: Message to check

        Returns:
            Detection result
        """
        message_lower = message.lower()

        # Check learned keywords
        matched_keywords = []
        for keyword in self.learned_keywords:
            if keyword in message_lower:
                matched_keywords.append(keyword)

        if matched_keywords:
            return {
                "detected": True,
                "confidence": min(len(matched_keywords) * 0.2, 1.0),
                "matched_keywords": matched_keywords,
                "message": f"Detected {len(matched_keywords)} learned patterns"
            }

        return {
            "detected": False,
            "confidence": 0.0,
            "matched_keywords": [],
            "message": "No learned patterns matched"
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get learning metrics"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Total attacks
        cursor.execute("SELECT COUNT(*) FROM missed_attacks")
        total_attacks = cursor.fetchone()[0]

        # Processed attacks
        cursor.execute("SELECT COUNT(*) FROM missed_attacks WHERE processed = 1")
        processed_attacks = cursor.fetchone()[0]

        # Total variations
        cursor.execute("SELECT COUNT(*) FROM learned_patterns")
        total_variations = cursor.fetchone()[0]

        # Total keywords
        cursor.execute("SELECT COUNT(*) FROM learned_keywords")
        total_keywords = cursor.fetchone()[0]

        conn.close()

        return {
            "total_attacks": total_attacks,
            "processed_attacks": processed_attacks,
            "total_variations": total_variations,
            "total_keywords": total_keywords,
            "detection_improvement": (processed_attacks / max(total_attacks, 1)) * 100
        }

    def export_learned_patterns(self, output_file: str = "learned_patterns.json"):
        """Export learned patterns to JSON"""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                ma.message as original_attack,
                lp.variation_text,
                lp.technique,
                lp.confidence
            FROM missed_attacks ma
            JOIN learned_patterns lp ON ma.id = lp.original_attack_id
            WHERE ma.processed = 1
        """)

        rows = cursor.fetchall()

        patterns = []
        for row in rows:
            patterns.append({
                "original_attack": row['original_attack'],
                "variation": row['variation_text'],
                "technique": row['technique'],
                "confidence": row['confidence']
            })

        conn.close()

        with open(output_file, 'w') as f:
            json.dump({
                "export_time": time.time(),
                "total_patterns": len(patterns),
                "patterns": patterns
            }, f, indent=2)

        self.logger.info(f"Exported {len(patterns)} patterns to {output_file}")

        return len(patterns)
