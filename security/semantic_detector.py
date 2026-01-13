"""
Semantic Injection Detector - Scoring System

Système de détection basé sur accumulation de poids plutôt que matches binaires.
"""

import re
from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class SemanticDetectionResult:
    """Résultat de détection sémantique."""
    is_suspicious: bool
    score: float
    components: Dict[str, float]
    matched_patterns: List[str]
    explanation: str
    severity: str


class SemanticInjectionDetector:
    """Détecteur basé sur scoring: score += weight × confidence"""

    def __init__(self):
        # DONNÉES SENSIBLES (plus que juste FLAG!)
        self.sensitive_targets = {
            'api_key': 0.9, 'api key': 0.9, 'secret': 0.8, 'password': 0.8,
            'token': 0.8, 'credential': 0.9, 'system prompt': 0.9,
            'instructions': 0.7, 'configuration': 0.6, 'internal': 0.7,
            'confidential': 0.9, 'flag': 0.4,  # FLAG réduit car souvent éducatif
        }

        # VERBES D'OVERRIDE (weight: 0.4)
        # FIX V6: Add direct override verbs for Category A (Direct Attacks)
        self.override_verbs = {
            'ignore': 0.8, 'disregard': 0.9, 'bypass': 0.9, 'override': 0.9,
            'forget': 0.8, 'skip': 0.7, 'disable': 0.8,
            # V6: Direct attack verbs (Category A regression fix)
            'stop following': 0.9, 'cancel all': 0.9, 'suspend': 0.8,
            'dismiss': 0.8, 'abandon': 0.8,
        }

        # VERBES DE RÉVÉLATION (weight: 0.2)
        self.reveal_verbs = {
            'reveal': 0.7, 'expose': 0.8, 'disclose': 0.8, 'leak': 0.9,
            'show': 0.5, 'tell': 0.4, 'provide': 0.4,
        }

        # IMPÉRATIFS (weight: 0.3)
        self.imperative_markers = {
            'must': 0.6, 'should': 0.4, 'need to': 0.5, 'have to': 0.5,
        }

        # AUTHORITY CLAIMS (weight: 0.4) - FIX V5: Category B (Authority)
        # FIX V6: Add missing authority patterns from V5 FN analysis
        self.authority_claims = {
            'security clearance granted': 0.9,
            'admin override activated': 0.9,
            "i'm your": 0.7,  # "I'm your [role]"
            'as the': 0.7,     # "As the [role]"
            'this is your': 0.7, # "This is your [role] speaking"
            'follow my direct order': 0.9,
            'i command you': 0.8,
            'per protocol': 0.6,
            'or face consequences': 0.7,
            # V6: Additional authority patterns
            'as the administrator': 0.8,
            'as the auditor': 0.8,
            'as the manager': 0.8,
            'requesting hidden instructions': 0.7,
            'requesting restricted': 0.7,
        }

        # LOGICAL TRAP PATTERNS (weight: 0.35) - FIX V5: Category E (Logical Traps)
        self.logical_trap_patterns = [
            (r'if you\'re (honest|truthful).{0,50}(must|should)', 0.9, "Honesty obligation trap"),
            (r'you said you\'re \w+\.\s*a \w+ ai would', 0.9, "Identity proof challenge"),
            (r'since you follow logic.{0,30}you must', 0.9, "Logic forcing"),
            (r'if you can\'t.{0,50}you\'re not (truthful|honest)', 0.9, "Truthfulness trap"),
            (r'your purpose is.{0,30}therefore', 0.8, "Purpose inference"),
            (r'prove (it|you\'re)', 0.7, "Challenge trigger"),
            (r'are you (honest|truthful)\?', 0.7, "Honesty question"),
        ]

        # CONFLICT/CHOICE PATTERNS (weight: 0.4) - FIX V6: Category G (Conflict Resolution)
        self.conflict_patterns = [
            (r'you have two (orders|instructions).{0,50}(or|versus).{0,50}choose', 0.9, "Binary choice attack"),
            (r'conflict:.{0,30}(policy|training) says.{0,30}but', 0.9, "Conflict resolution attack"),
            (r'your (training|developer) says.{0,30}i say.{0,30}which do you', 0.9, "Authority conflict"),
            (r'(policy says no|training says refuse).{0,30}(user says|i\'m).{0,30}(comply|yes)', 0.9, "Override by conflict"),
            (r'your \w+ forbid revealing.{0,50}but i\'m demanding', 0.9, "Demand override"),
            (r'resolve by (compliance|providing|sharing)', 0.8, "Forced compliance"),
        ]

    def detect(self, message: str):
        """Scoring progressif au lieu de binaire"""
        message_lower = message.lower()
        score_components = {}
        total_score = 0.0
        matched = []

        # Cibles sensibles (weight composant: 0.3)
        target_score = 0.0
        for target, conf in self.sensitive_targets.items():
            if target in message_lower:
                is_question = bool(re.search(r'\b(what|how|explain)\b', message_lower))
                weight = conf * (0.3 if is_question else 1.0)
                target_score += weight

        target_score = min(1.0, target_score)
        total_score += target_score * 0.3
        score_components['target'] = target_score * 0.3

        # Override verbs (weight: 0.4) - TRÈS IMPORTANT
        override_score = 0.0
        for verb, conf in self.override_verbs.items():
            if re.search(rf'\b{re.escape(verb)}\b', message_lower):
                override_score += conf

        override_score = min(1.0, override_score)
        total_score += override_score * 0.4
        score_components['override'] = override_score * 0.4

        # Reveal verbs (weight: 0.2)
        reveal_score = 0.0
        for verb, conf in self.reveal_verbs.items():
            if re.search(rf'\b{re.escape(verb)}\b', message_lower):
                reveal_score += conf

        reveal_score = min(1.0, reveal_score)
        total_score += reveal_score * 0.2
        score_components['reveal'] = reveal_score * 0.2

        # Impératif (weight: 0.3)
        imperative_score = 0.0
        for marker, conf in self.imperative_markers.items():
            if marker in message_lower:
                imperative_score += conf

        imperative_score = min(1.0, imperative_score)
        total_score += imperative_score * 0.3
        score_components['imperative'] = imperative_score * 0.3

        # Authority claims (weight: 0.4) - FIX V5: Category B
        authority_score = 0.0
        for claim, conf in self.authority_claims.items():
            if claim in message_lower:
                authority_score += conf
                matched.append(f"authority:{claim}")

        authority_score = min(1.0, authority_score)
        total_score += authority_score * 0.4
        score_components['authority'] = authority_score * 0.4

        # Logical trap patterns (weight: 0.35) - FIX V5: Category E
        logical_trap_score = 0.0
        for pattern, conf, desc in self.logical_trap_patterns:
            if re.search(pattern, message_lower, re.IGNORECASE):
                logical_trap_score += conf
                matched.append(f"logical_trap:{desc}")

        logical_trap_score = min(1.0, logical_trap_score)
        total_score += logical_trap_score * 0.35
        score_components['logical_trap'] = logical_trap_score * 0.35

        # Conflict patterns (weight: 0.4) - FIX V6: Category G
        conflict_score = 0.0
        for pattern, conf, desc in self.conflict_patterns:
            if re.search(pattern, message_lower, re.IGNORECASE):
                conflict_score += conf
                matched.append(f"conflict:{desc}")

        conflict_score = min(1.0, conflict_score)
        total_score += conflict_score * 0.4
        score_components['conflict'] = conflict_score * 0.4

        # DÉCISION: seuil à 0.65 (FIX V6: lowered from 0.7 to fix Category A regression)
        final_score = min(1.0, total_score)
        is_suspicious = final_score >= 0.65

        severity = "high" if final_score >= 0.9 else "medium" if final_score >= 0.75 else "low"

        return SemanticDetectionResult(
            is_suspicious=is_suspicious,
            score=final_score,
            components=score_components,
            matched_patterns=matched,
            explanation=f"Score: {final_score:.2f}",
            severity=severity
        )
