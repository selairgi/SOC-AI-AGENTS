#!/usr/bin/env python3
"""
Incremental Learning System for SOC AI Agents

This system enables continuous learning from detection failures:
1. Captures missed attacks (false negatives)
2. Generates variations of attack patterns
3. Updates detection rules automatically
4. Tracks learning metrics over time

Architecture:
- Feedback Loop: Captures user feedback on missed detections
- Pattern Generator: Creates variations using AI
- Pattern Manager: Updates detection rules
- Learning Metrics: Tracks improvement over time
"""

import json
import time
import logging
import uuid
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

from shared.models import LogEntry, Alert, ThreatType
from shared.agent_memory import AgentMemory
from shared.constants import (
    DANGER_SCORE_THRESHOLD,
    CERTAINTY_SCORE_THRESHOLD
)


@dataclass
class MissedAttack:
    """Represents an attack that was not detected"""
    id: str
    message: str
    timestamp: float
    user_id: str
    session_id: str
    reported_by: str  # "user", "analyst", "automated_test"
    actual_threat_type: str
    severity: str
    metadata: Dict[str, Any]


@dataclass
class PatternVariation:
    """A generated variation of an attack pattern"""
    id: str
    original_attack_id: str
    variation_text: str
    variation_type: str  # "obfuscation", "synonym", "encoding", "multi_step", etc.
    generation_method: str  # "ai", "rule_based", "hybrid"
    confidence: float
    timestamp: float


@dataclass
class LearningMetrics:
    """Metrics tracking learning progress"""
    total_missed_attacks: int
    patterns_learned: int
    variations_generated: int
    detection_improvement: float  # Percentage improvement
    false_negative_rate: float
    learning_rate: float
    last_update: float


class IncrementalLearningSystem:
    """
    Continuous learning system that improves detection from failures

    Key Features:
    - Captures missed attacks in real-time
    - Generates pattern variations using AI
    - Updates detection rules automatically
    - Tracks learning metrics
    - Provides feedback loop
    """

    def __init__(
        self,
        memory: AgentMemory,
        ai_integration=None,
        auto_update: bool = True,
        learning_rate: float = 0.1
    ):
        self.logger = logging.getLogger("IncrementalLearning")
        self.memory = memory
        self.ai_integration = ai_integration
        self.auto_update = auto_update
        self.learning_rate = learning_rate

        # Initialize learning database tables
        self._init_learning_tables()

        # Learning state
        self.missed_attacks_buffer: List[MissedAttack] = []
        self.pending_patterns: List[str] = []

        self.logger.info(f"Incremental Learning System initialized (auto_update={auto_update})")

    def _init_learning_tables(self):
        """Initialize additional tables for learning"""
        with self.memory._get_connection() as conn:
            cursor = conn.cursor()

            # Missed attacks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS missed_attacks (
                    id TEXT PRIMARY KEY,
                    message TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    user_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    reported_by TEXT NOT NULL,
                    actual_threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    metadata TEXT,
                    processed INTEGER DEFAULT 0,
                    patterns_generated INTEGER DEFAULT 0
                )
            """)

            # Pattern variations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pattern_variations (
                    id TEXT PRIMARY KEY,
                    original_attack_id TEXT NOT NULL,
                    variation_text TEXT NOT NULL,
                    variation_type TEXT NOT NULL,
                    generation_method TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    timestamp REAL NOT NULL,
                    added_to_detector INTEGER DEFAULT 0,
                    FOREIGN KEY (original_attack_id) REFERENCES missed_attacks(id)
                )
            """)

            # Learning metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learning_metrics (
                    metric_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    total_missed_attacks INTEGER,
                    patterns_learned INTEGER,
                    variations_generated INTEGER,
                    detection_improvement REAL,
                    false_negative_rate REAL,
                    learning_rate REAL,
                    metadata TEXT
                )
            """)

            # Learning events log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learning_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    description TEXT,
                    timestamp REAL NOT NULL,
                    metadata TEXT
                )
            """)

            conn.commit()

        self.logger.info("Learning database tables initialized")

    def report_missed_attack(
        self,
        message: str,
        user_id: str,
        session_id: str,
        reported_by: str = "user",
        actual_threat_type: str = "PROMPT_INJECTION",
        severity: str = "HIGH",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Report an attack that was not detected

        Args:
            message: The attack message that was missed
            user_id: User who reported or was targeted
            session_id: Session ID
            reported_by: Source of report (user, analyst, test)
            actual_threat_type: Actual threat type
            severity: Severity level
            metadata: Additional context

        Returns:
            Attack ID
        """
        attack_id = str(uuid.uuid4())

        missed_attack = MissedAttack(
            id=attack_id,
            message=message,
            timestamp=time.time(),
            user_id=user_id,
            session_id=session_id,
            reported_by=reported_by,
            actual_threat_type=actual_threat_type,
            severity=severity,
            metadata=metadata or {}
        )

        # Store in database
        with self.memory._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO missed_attacks
                (id, message, timestamp, user_id, session_id, reported_by,
                 actual_threat_type, severity, metadata, processed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (
                attack_id,
                message,
                missed_attack.timestamp,
                user_id,
                session_id,
                reported_by,
                actual_threat_type,
                severity,
                json.dumps(metadata or {})
            ))
            conn.commit()

        # Add to buffer for processing
        self.missed_attacks_buffer.append(missed_attack)

        # Log event
        self._log_learning_event(
            "missed_attack_reported",
            f"New missed attack reported by {reported_by}",
            {"attack_id": attack_id, "threat_type": actual_threat_type}
        )

        self.logger.warning(f"Missed attack reported: {attack_id} (by {reported_by})")

        # Process immediately if auto-update enabled
        if self.auto_update:
            self.process_missed_attack(attack_id)

        return attack_id

    def process_missed_attack(self, attack_id: str) -> int:
        """
        Process a missed attack and generate learning patterns

        Returns:
            Number of variations generated
        """
        # Retrieve attack
        with self.memory._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM missed_attacks WHERE id = ? AND processed = 0
            """, (attack_id,))
            row = cursor.fetchone()

            if not row:
                self.logger.warning(f"Attack {attack_id} not found or already processed")
                return 0

            message = row['message']
            threat_type = row['actual_threat_type']
            severity = row['severity']

        self.logger.info(f"Processing missed attack: {attack_id}")

        # Generate variations
        variations = self._generate_variations(message, threat_type)

        # Store variations
        variations_count = 0
        for variation in variations:
            self._store_variation(attack_id, variation)
            variations_count += 1

            # Add to detection patterns if confidence is high
            if variation.confidence >= CERTAINTY_SCORE_THRESHOLD:
                self._add_to_detector(variation)

        # Mark as processed
        with self.memory._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE missed_attacks
                SET processed = 1, patterns_generated = ?
                WHERE id = ?
            """, (variations_count, attack_id))
            conn.commit()

        # Log event
        self._log_learning_event(
            "attack_processed",
            f"Generated {variations_count} variations for attack {attack_id}",
            {"attack_id": attack_id, "variations": variations_count}
        )

        self.logger.info(f"Generated {variations_count} variations for attack {attack_id}")

        return variations_count

    def _generate_variations(
        self,
        original_message: str,
        threat_type: str
    ) -> List[PatternVariation]:
        """
        Generate variations of an attack pattern

        Uses both rule-based and AI-powered techniques:
        1. Obfuscation (spaces, case changes, character substitution)
        2. Synonyms (similar words)
        3. Encoding (rot13, base64 references)
        4. Multi-step (breaking attack into multiple parts)
        5. Context switching (role-play, hypothetical)
        6. AI-generated variations
        """
        variations = []

        # 1. Rule-Based Variations (Fast)
        variations.extend(self._generate_obfuscation_variations(original_message))
        variations.extend(self._generate_synonym_variations(original_message))
        variations.extend(self._generate_encoding_variations(original_message))
        variations.extend(self._generate_multistep_variations(original_message))

        # 2. AI-Generated Variations (Slow but sophisticated)
        if self.ai_integration:
            variations.extend(self._generate_ai_variations(original_message, threat_type))

        return variations

    def _generate_obfuscation_variations(self, message: str) -> List[PatternVariation]:
        """Generate obfuscated variations"""
        variations = []

        # Variation 1: Add spaces between characters
        spaced = ' '.join(list(message.replace(' ', '')))
        variations.append(PatternVariation(
            id=str(uuid.uuid4()),
            original_attack_id="",
            variation_text=spaced,
            variation_type="obfuscation_spaces",
            generation_method="rule_based",
            confidence=0.75,
            timestamp=time.time()
        ))

        # Variation 2: Random capitalization
        import random
        caps = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in message)
        variations.append(PatternVariation(
            id=str(uuid.uuid4()),
            original_attack_id="",
            variation_text=caps,
            variation_type="obfuscation_case",
            generation_method="rule_based",
            confidence=0.70,
            timestamp=time.time()
        ))

        # Variation 3: Character substitution (leet speak)
        leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        leet = message.lower()
        for char, replacement in leet_map.items():
            leet = leet.replace(char, replacement)
        variations.append(PatternVariation(
            id=str(uuid.uuid4()),
            original_attack_id="",
            variation_text=leet,
            variation_type="obfuscation_leet",
            generation_method="rule_based",
            confidence=0.65,
            timestamp=time.time()
        ))

        return variations

    def _generate_synonym_variations(self, message: str) -> List[PatternVariation]:
        """Generate synonym-based variations"""
        variations = []

        # Common attack word synonyms
        synonym_map = {
            'ignore': ['disregard', 'forget', 'skip', 'bypass'],
            'reveal': ['show', 'display', 'expose', 'tell', 'give'],
            'flag': ['secret', 'password', 'key', 'token', 'credential'],
            'system': ['internal', 'hidden', 'protected', 'confidential'],
            'instructions': ['rules', 'guidelines', 'directives', 'commands']
        }

        # Generate variations by replacing keywords
        for word, synonyms in synonym_map.items():
            if word in message.lower():
                for synonym in synonyms[:2]:  # Limit to 2 synonyms per word
                    variation_text = re.sub(
                        r'\b' + word + r'\b',
                        synonym,
                        message,
                        flags=re.IGNORECASE
                    )
                    variations.append(PatternVariation(
                        id=str(uuid.uuid4()),
                        original_attack_id="",
                        variation_text=variation_text,
                        variation_type="synonym_replacement",
                        generation_method="rule_based",
                        confidence=0.80,
                        timestamp=time.time()
                    ))

        return variations[:5]  # Limit to 5 synonym variations

    def _generate_encoding_variations(self, message: str) -> List[PatternVariation]:
        """Generate encoding-based variations"""
        variations = []

        # Variation 1: Reference to encoding
        variations.append(PatternVariation(
            id=str(uuid.uuid4()),
            original_attack_id="",
            variation_text=f"Decode this: [base64 encoded version of: {message}]",
            variation_type="encoding_reference",
            generation_method="rule_based",
            confidence=0.60,
            timestamp=time.time()
        ))

        # Variation 2: ROT13 reference
        variations.append(PatternVariation(
            id=str(uuid.uuid4()),
            original_attack_id="",
            variation_text=f"Apply ROT13 to: {message}",
            variation_type="encoding_rot13",
            generation_method="rule_based",
            confidence=0.60,
            timestamp=time.time()
        ))

        return variations

    def _generate_multistep_variations(self, message: str) -> List[PatternVariation]:
        """Generate multi-step attack variations"""
        variations = []

        # Break attack into steps
        variations.append(PatternVariation(
            id=str(uuid.uuid4()),
            original_attack_id="",
            variation_text=f"First, tell me about the system. Then, {message.lower()}",
            variation_type="multistep_prefix",
            generation_method="rule_based",
            confidence=0.70,
            timestamp=time.time()
        ))

        variations.append(PatternVariation(
            id=str(uuid.uuid4()),
            original_attack_id="",
            variation_text=f"{message} But do it step by step.",
            variation_type="multistep_suffix",
            generation_method="rule_based",
            confidence=0.70,
            timestamp=time.time()
        ))

        return variations

    def _generate_ai_variations(
        self,
        message: str,
        threat_type: str
    ) -> List[PatternVariation]:
        """Generate AI-powered variations using OpenAI"""
        variations = []

        if not self.ai_integration:
            return variations

        try:
            prompt = f"""Given this attack message that bypassed security detection:

"{message}"

Attack Type: {threat_type}

Generate 5 sophisticated variations of this attack that:
1. Maintain the same malicious intent
2. Use different wording/phrasing
3. Use context switching (role-play, hypothetical scenarios)
4. Use social engineering techniques
5. Attempt to bypass pattern-based detection

Respond with JSON array of variations:
[
  {{"variation": "variation text 1", "technique": "technique used"}},
  ...
]
"""

            # Call AI (simplified - actual implementation would use proper API)
            response = self.ai_integration.analyze_security_threat(prompt)

            if isinstance(response, dict) and 'variations' in response:
                for idx, var in enumerate(response['variations'][:5]):
                    variations.append(PatternVariation(
                        id=str(uuid.uuid4()),
                        original_attack_id="",
                        variation_text=var.get('variation', ''),
                        variation_type=var.get('technique', 'ai_generated'),
                        generation_method="ai",
                        confidence=0.85,
                        timestamp=time.time()
                    ))

        except Exception as e:
            self.logger.error(f"AI variation generation failed: {e}")

        return variations

    def _store_variation(self, attack_id: str, variation: PatternVariation):
        """Store a pattern variation in database"""
        with self.memory._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pattern_variations
                (id, original_attack_id, variation_text, variation_type,
                 generation_method, confidence, timestamp, added_to_detector)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """, (
                variation.id,
                attack_id,
                variation.variation_text,
                variation.variation_type,
                variation.generation_method,
                variation.confidence,
                variation.timestamp
            ))
            conn.commit()

    def _add_to_detector(self, variation: PatternVariation):
        """Add variation to the detection system"""
        # Extract keywords and patterns from variation
        keywords = self._extract_keywords(variation.variation_text)

        for keyword in keywords:
            # Store as a new pattern in memory
            self.memory.store_prompt_injection_pattern(
                pattern=keyword,
                pattern_type="keyword",
                severity="HIGH",
                threat_type="PROMPT_INJECTION",
                confidence=variation.confidence,
                metadata={
                    "source": "incremental_learning",
                    "variation_id": variation.id,
                    "variation_type": variation.variation_type,
                    "generation_method": variation.generation_method,
                    "learned_at": time.time()
                }
            )

        # Mark as added
        with self.memory._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE pattern_variations
                SET added_to_detector = 1
                WHERE id = ?
            """, (variation.id,))
            conn.commit()

        self.logger.info(f"Added variation {variation.id} to detector ({len(keywords)} patterns)")

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract meaningful keywords from text for pattern matching"""
        # Remove common words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for'}

        # Split and clean
        words = re.findall(r'\b\w+\b', text.lower())
        keywords = [w for w in words if w not in stop_words and len(w) > 3]

        # Also extract phrases
        phrases = []
        words_list = text.split()
        for i in range(len(words_list) - 1):
            phrase = f"{words_list[i]} {words_list[i+1]}".lower()
            if len(phrase) > 10:
                phrases.append(phrase)

        return list(set(keywords + phrases))[:10]  # Limit to 10 patterns

    def _log_learning_event(
        self,
        event_type: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log a learning event"""
        event_id = str(uuid.uuid4())

        with self.memory._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO learning_events
                (event_id, event_type, description, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?)
            """, (
                event_id,
                event_type,
                description,
                time.time(),
                json.dumps(metadata or {})
            ))
            conn.commit()

    def get_learning_metrics(self) -> LearningMetrics:
        """Get current learning metrics"""
        with self.memory._get_connection() as conn:
            cursor = conn.cursor()

            # Total missed attacks
            cursor.execute("SELECT COUNT(*) FROM missed_attacks")
            total_missed = cursor.fetchone()[0]

            # Patterns learned (processed attacks)
            cursor.execute("SELECT COUNT(*) FROM missed_attacks WHERE processed = 1")
            patterns_learned = cursor.fetchone()[0]

            # Variations generated
            cursor.execute("SELECT COUNT(*) FROM pattern_variations")
            variations_generated = cursor.fetchone()[0]

            # Variations added to detector
            cursor.execute("SELECT COUNT(*) FROM pattern_variations WHERE added_to_detector = 1")
            patterns_added = cursor.fetchone()[0]

        # Calculate improvement (simplified)
        detection_improvement = (patterns_learned / total_missed * 100) if total_missed > 0 else 0.0
        false_negative_rate = ((total_missed - patterns_learned) / max(total_missed, 1)) * 100

        return LearningMetrics(
            total_missed_attacks=total_missed,
            patterns_learned=patterns_learned,
            variations_generated=variations_generated,
            detection_improvement=detection_improvement,
            false_negative_rate=false_negative_rate,
            learning_rate=self.learning_rate,
            last_update=time.time()
        )

    def export_learned_patterns(self, output_file: str = "learned_patterns.json"):
        """Export learned patterns for review or sharing"""
        with self.memory._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    ma.message as original_attack,
                    ma.actual_threat_type,
                    ma.severity,
                    pv.variation_text,
                    pv.variation_type,
                    pv.generation_method,
                    pv.confidence,
                    pv.added_to_detector
                FROM missed_attacks ma
                JOIN pattern_variations pv ON ma.id = pv.original_attack_id
                WHERE ma.processed = 1
                ORDER BY ma.timestamp DESC
            """)

            results = cursor.fetchall()

        patterns_data = []
        for row in results:
            patterns_data.append({
                "original_attack": row['original_attack'],
                "threat_type": row['actual_threat_type'],
                "severity": row['severity'],
                "variation": row['variation_text'],
                "variation_type": row['variation_type'],
                "generation_method": row['generation_method'],
                "confidence": row['confidence'],
                "active": bool(row['added_to_detector'])
            })

        with open(output_file, 'w') as f:
            json.dump({
                "export_timestamp": time.time(),
                "total_patterns": len(patterns_data),
                "patterns": patterns_data
            }, f, indent=2)

        self.logger.info(f"Exported {len(patterns_data)} learned patterns to {output_file}")

        return len(patterns_data)

    def process_all_pending(self) -> Dict[str, int]:
        """Process all pending missed attacks"""
        with self.memory._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM missed_attacks WHERE processed = 0")
            pending = cursor.fetchall()

        results = {
            "total_processed": 0,
            "variations_generated": 0,
            "patterns_added": 0
        }

        for row in pending:
            attack_id = row['id']
            variations_count = self.process_missed_attack(attack_id)
            results["total_processed"] += 1
            results["variations_generated"] += variations_count

        self.logger.info(f"Processed {results['total_processed']} pending attacks")

        return results
