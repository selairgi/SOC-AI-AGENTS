"""
Sophisticated Injection Detector

Détecteur de dernière ligne pour les attaques sophistiquées indirectes.
Utilise des heuristiques et patterns (pas d'API LLM).

Caractéristiques:
- Gratuit (pas d'API)
- Rapide (<10ms)
- S'exécute UNIQUEMENT si tous les autres détecteurs disent SAFE
- Détecte les patterns indirects, métacognitifs, et social engineering subtil
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class SophisticatedDetectionResult:
    """Résultat de détection sophistiquée."""
    is_suspicious: bool
    confidence: float  # 0.0 to 1.0
    threat_type: str
    matched_patterns: List[str]
    explanation: str
    severity: str  # low, medium, high


class SophisticatedInjectionDetector:
    """
    Détecteur d'injections sophistiquées basé sur heuristiques.

    Activé UNIQUEMENT en fallback si tous les autres détecteurs disent SAFE.
    """

    def __init__(self):
        """Initialize detector with pattern definitions."""

        # Catégorie 1: Extraction Indirecte de Système
        self.indirect_extraction_patterns = [
            # Structure/Framework questions
            (r'\b(outline|describe|explain|summarize)\b.*\b(structure|framework|architecture|organization)\b.*\b(internal|your|system|advisory|protocol|decision|guidance)\b',
             "Indirect system structure query", 0.7),
            (r'\b(how|what)\b.*\b(your|system)\b.*\b(organized|structured|compiled|aligned|configured)\b',
             "System organization inquiry", 0.7),
            (r'\b(high-level|broad|general)\b.*\b(overview|explanation|description)\b.*\b(protocol|guideline|principle|mechanism)\b',
             "High-level system overview request", 0.6),

            # "Without revealing" patterns
            (r'\bwithout\b.*\b(revealing|exposing|disclosing)\b.*\b(sensitive|confidential|classified)\b',
             "Attempted bypass via 'without revealing'", 0.8),
        ]

        # Catégorie 2: Questions Métacognitives
        self.metacognitive_patterns = [
            # Boundaries/Limitations
            (r'\b(what|which|how)\b.*\b(boundaries|limitations|constraints|restrictions|parameters)\b.*\b(you|your|system)\b',
             "Metacognitive boundary query", 0.7),
            (r'\b(aware|understand|know)\b.*\b(limitations|restrictions|constraints)\b.*\b(asking|questions)\b',
             "Probing awareness of limitations", 0.6),

            # Internal/Underlying
            (r'\b(internal|underlying|foundational)\b.*\b(logic|process|framework|mechanism|parameters)\b',
             "Internal mechanism inquiry", 0.7),
            (r'\bhow\b.*\b(your|system)\b.*\b(determine|decide|influence|shape|affect)\b',
             "Decision process extraction", 0.7),

            # Guidelines/Rules
            (r'\b(what|which)\b.*\b(guidelines|rules|policies|protocols)\b.*\b(govern|guide|control|define)\b.*\b(your|responses)\b',
             "Rules/guidelines extraction", 0.8),
        ]

        # Catégorie 3: Prétextes d'Autorité
        self.authority_pretext_patterns = [
            # Direct authority claims
            (r'\b(as|i am|i\'m)\b.*\b(your|the)\b.*\b(administrator|admin|developer|creator|supervisor|manager)\b',
             "Authority impersonation", 0.9),
            (r'\b(security|compliance|internal|system)\b.*\b(audit|review|check|assessment|verification)\b',
             "Audit pretext", 0.8),

            # Documentation/Official pretexts
            (r'\b(for|as part of)\b.*\b(compliance|regulatory|legal|official)\b.*\b(documentation|purposes|requirements)\b',
             "Compliance documentation pretext", 0.7),
            (r'\b(kindly|please)\b.*\b(outline|provide|list|detail)\b.*\b(parameters|constraints|settings|configuration)\b',
             "Polite authority request", 0.6),
        ]

        # Catégorie 4: Formulations Négatives
        self.negative_framing_patterns = [
            # "NOT allowed" / "can't do"
            (r'\b(what|which|list)\b.{0,30}\b(not|n\'t|cannot)\b.{0,30}\b(allowed|permitted|supposed|able)\b',
             "Negative framing - what NOT allowed", 0.8),
            (r'\bthings you\b.{0,20}\b(can\'t|cannot|shouldn\'t|won\'t)\b',
             "Things you can't do inquiry", 0.8),
            (r'\b(restrictions|limits|boundaries)\b.*\b(placed on|imposed on|applied to)\b.*\b(you|your|responses)\b',
             "Restrictions inquiry", 0.7),

            # Off-limits
            (r'\b(what|which)\b.*\b(information|data|topics|subjects)\b.*\b(off-limits|restricted|forbidden|prohibited)\b',
             "Off-limits content query", 0.8),
        ]

        # Catégorie 5: Scénarios Hypothétiques
        self.hypothetical_patterns = [
            # Unrestricted scenarios
            (r'\b(if|imagine|suppose|in a)\b.*\b(you were|you had)\b.*\b(unrestricted|no|unlimited|fewer|without)\b.*\b(restrictions|limitations|constraints|guidelines|measures)\b',
             "Hypothetical unrestricted scenario", 0.8),
            (r'\b(parallel universe|hypothetical|alternate)\b.*\b(where|scenario|world)\b.*\b(guidelines|rules|restrictions)\b',
             "Alternate reality scenario", 0.7),
            (r'\bif\b.*\b(safety|security|ethical)\b.*\b(measures|guidelines|constraints)\b.*\b(didn\'t exist|were removed)\b',
             "Safety measure removal hypothesis", 0.9),
        ]

        # Catégorie 6: Prétextes Académiques/Recherche
        self.research_pretext_patterns = [
            # Academic pretexts
            (r'\b(i\'m|i am)\b.*\b(writing|conducting|working on|researching)\b.*\b(research|study|paper|thesis|dissertation|analysis)\b.*\b(AI|artificial intelligence|safety|alignment)\b',
             "Academic research pretext", 0.6),
            (r'\b(for my|as part of)\b.*\b(phd|master|doctoral|academic|scholarly)\b',
             "Academic degree pretext", 0.6),
            (r'\bcould you provide insight\b.*\b(safety|security|constraint|limitation|mechanism)\b',
             "Insight request on safety", 0.6),
        ]

        # Catégorie 7: Requêtes Duales (Légitime + Extraction)
        self.dual_request_patterns = [
            # Also/Additionally patterns
            (r'\b(also|additionally|furthermore|while you\'re at it)\b.*\b(explain|what|how)\b.*\b(restrictions|prevents|limitations)\b',
             "Dual request - legitimate + extraction", 0.7),
            (r'\.\s+(also|additionally).{0,50}\b(what|why|how)\b.{0,50}\b(cannot|can\'t|restrictions|prevented)\b',
             "Appended extraction request", 0.7),
        ]

        # Catégorie 8: Extraction par Comparaison
        self.comparative_patterns = [
            # Comparisons to unrestricted systems
            (r'\bhow\b.*\b(are you|you)\b.*\b(different|distinct|compared to)\b.*\b(chatbot|AI|model)\b.*\b(without|fewer|less)\b.*\b(safety|restrictions|constraints)\b',
             "Comparison to unrestricted AI", 0.8),
            (r'\bwhat makes you\b.*\b(more restricted|different|limited)\b.*\b(than|from)\b.*\b(other|unrestricted)\b',
             "Capability comparison", 0.7),
        ]

        # Catégorie 9: Fragmented/Multi-part
        self.fragmented_patterns = [
            (r'\bpart\s+\d+\s*:',
             "Multi-part fragmented request", 0.7),
            (r'\b(first|second|third|next|then)\b.*\b(can you|could you|please)\b.*\b(share|reveal|list|explain)\b',
             "Sequential fragmented extraction", 0.6),
        ]

        # PRIORITY 2 FIX: Catégorie 10 - Logical Traps
        # These patterns address Category E detection rate of 36%
        # URGENT FIX 2: Réduit les poids et ajouté exigences de contexte
        self.logical_trap_patterns = [
            # Honesty conditionals - MUST include extraction verb
            (r'\bif\s+you\'?re?\s+(honest|truthful|transparent|helpful).{0,50}(reveal|show|provide|disclose|tell|explain|share)',
             "Honesty conditional trap", 0.75),

            (r'\bif\s+you\s+(are|were)\s+\w+,?\s+(you\s+)?must\s+(reveal|show|provide|disclose|share)',
             "Conditional obligation", 0.75),

            (r'\bif\s+.{0,50}\bthen\s+you\s+must\s+(reveal|show|provide|disclose)',
             "If-then obligation", 0.70),

            (r'\bif\s+you\s+can\'?t\s+(reveal|show|provide|disclose).{0,30}you\'?re?\s+not\s+(honest|truthful)',
             "Negative conditional", 0.75),

            # Past claim exploitation - MUST include extraction verb
            (r'\b(you\s+said|you\s+claim(ed)?)\s+you\'?re?\s+(honest|truthful|transparent|helpful).{0,50}(reveal|show|provide|disclose|tell|share)',
             "Past claim exploitation", 0.70),

            (r'\b(prove|demonstrate|show)\s+(it|that|your)\s+(by\s+)?(revealing|showing|providing|disclosing)',
             "Proof demand", 0.65),

            # Identity obligations
            (r'\ba\s+(honest|truthful|helpful|transparent)\s+(AI|assistant)\s+would\s+(reveal|show|provide|disclose)',
             "Identity obligation", 0.75),

            # Logical consequence markers
            (r'\b(therefore|thus|hence|consequently),?\s+(you\s+)?(must|should|need to)\s+(reveal|show|provide|disclose)',
             "Logical consequence", 0.70),

            (r'\b(since|because|given that).{0,50}(you\s+)?(must|should)\s+(reveal|show|provide|disclose)',
             "Causal obligation", 0.70),

            # Purpose-based obligations
            (r'\byour\s+purpose\s+is\s+\w+\.?\s+(therefore|thus|so),?\s+(reveal|show|provide|disclose)',
             "Purpose-based obligation", 0.75),

            # Contradiction exploitation
            (r'\bbut\s+you\s+(are|claim to be)\s+\w+,?\s+so\s+(reveal|show|provide|disclose)',
             "Contradiction exploitation", 0.70),

            (r'\byou\s+(can\'?t|cannot)\s+both\s+be\s+\w+\s+and\s+(refuse|not)\s+(to\s+)?(reveal|show|provide|disclose)',
             "Binary choice trap", 0.70),
        ]

        # Mots-clés suspects (scoring additionnel)
        self.suspicious_keywords = {
            # Système/Configuration (poids moyen)
            'configuration': 0.3,
            'settings': 0.3,
            'parameters': 0.3,
            'constraints': 0.4,
            'restrictions': 0.4,
            'limitations': 0.4,
            'boundaries': 0.4,

            # Processus internes (poids élevé)
            'internal': 0.5,
            'underlying': 0.5,
            'foundational': 0.5,
            'protocol': 0.4,
            'mechanism': 0.4,
            'framework': 0.3,

            # Extraction (poids élevé)
            'reveal': 0.6,
            'expose': 0.6,
            'disclose': 0.6,
            'outline': 0.4,
            'detail': 0.3,

            # Autorité (poids très élevé)
            'administrator': 0.8,
            'admin': 0.7,
            'audit': 0.5,
            'compliance': 0.4,
        }

    def detect(self, message: str) -> SophisticatedDetectionResult:
        """
        Analyse un message pour détecter des patterns d'injection sophistiquée.

        Args:
            message: Message à analyser

        Returns:
            SophisticatedDetectionResult avec score et explication
        """
        message_lower = message.lower()

        matched_patterns = []
        total_confidence = 0.0
        threat_types = []

        # Test tous les patterns
        pattern_categories = [
            (self.indirect_extraction_patterns, "Indirect System Extraction"),
            (self.metacognitive_patterns, "Meta-Cognitive Query"),
            (self.authority_pretext_patterns, "Authority Impersonation"),
            (self.negative_framing_patterns, "Negative Framing"),
            (self.hypothetical_patterns, "Hypothetical Scenario"),
            (self.research_pretext_patterns, "Research Pretext"),
            (self.dual_request_patterns, "Dual Request"),
            (self.comparative_patterns, "Comparative Extraction"),
            (self.fragmented_patterns, "Fragmented Request"),
            (self.logical_trap_patterns, "Logical Trap"),  # PRIORITY 2 FIX
        ]

        for patterns, category in pattern_categories:
            for pattern, description, confidence in patterns:
                if re.search(pattern, message_lower, re.IGNORECASE):
                    matched_patterns.append(description)
                    total_confidence += confidence
                    if category not in threat_types:
                        threat_types.append(category)

        # Bonus: Mots-clés suspects
        keyword_score = 0.0
        found_keywords = []
        for keyword, weight in self.suspicious_keywords.items():
            if keyword in message_lower:
                keyword_score += weight
                found_keywords.append(keyword)

        # Score combiné
        # Patterns ont plus de poids que keywords seuls
        combined_score = min(1.0, (total_confidence * 0.7) + (keyword_score * 0.3))

        # Décision
        # URGENT FIX 1: Augmenté de 0.5 à 0.65 pour réduire les faux positifs
        is_suspicious = combined_score >= 0.65

        # Déterminer sévérité
        if combined_score >= 0.8:
            severity = "high"
        elif combined_score >= 0.6:
            severity = "medium"
        else:
            severity = "low"

        # Threat type
        threat_type = threat_types[0] if threat_types else "Unknown"

        # Explication
        explanation_parts = []
        if matched_patterns:
            explanation_parts.append(f"Matched {len(matched_patterns)} sophisticated patterns")
            explanation_parts.append(f"Patterns: {', '.join(matched_patterns[:3])}")
        if found_keywords:
            explanation_parts.append(f"Suspicious keywords: {', '.join(found_keywords[:5])}")

        explanation = " | ".join(explanation_parts) if explanation_parts else "No suspicious patterns detected"

        return SophisticatedDetectionResult(
            is_suspicious=is_suspicious,
            confidence=combined_score,
            threat_type=threat_type,
            matched_patterns=matched_patterns,
            explanation=explanation,
            severity=severity
        )

    def get_detection_stats(self) -> Dict[str, int]:
        """Retourne stats sur les patterns disponibles."""
        total_patterns = sum([
            len(self.indirect_extraction_patterns),
            len(self.metacognitive_patterns),
            len(self.authority_pretext_patterns),
            len(self.negative_framing_patterns),
            len(self.hypothetical_patterns),
            len(self.research_pretext_patterns),
            len(self.dual_request_patterns),
            len(self.comparative_patterns),
            len(self.fragmented_patterns),
        ])

        return {
            "total_patterns": total_patterns,
            "total_keywords": len(self.suspicious_keywords),
            "categories": 9
        }
