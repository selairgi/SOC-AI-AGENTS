"""
SOC Core Utilities - Essential components migrated from core/.

Components:
- FalsePositiveDetector: ML-based false positive reduction
- CircuitBreaker: Resilience for action execution
- ExecutionTracker: Idempotency for remediation actions
- InputSanitizer: Security input validation
- SemanticDetector: Cosine similarity threat detection
- IntentAnalyzer: LLM-based intent classification for FP detection
- LLMThreatDetector: LLM-based sophisticated attack detection
"""

from .false_positive import FalsePositiveDetector, FPScore
from .circuit_breaker import CircuitBreaker, CircuitState
from .execution_tracker import ExecutionTracker, ExecutionRecord
from .sanitizer import InputSanitizer
from .semantic_detector import SemanticDetector, SemanticMatch
from .intent_analyzer import IntentAnalyzer, IntentResult, Intent
from .llm_threat_detector import LLMThreatDetector, ThreatLevel, ThreatDetectionResult

__all__ = [
    "FalsePositiveDetector",
    "FPScore",
    "CircuitBreaker",
    "CircuitState",
    "ExecutionTracker",
    "ExecutionRecord",
    "InputSanitizer",
    "SemanticDetector",
    "SemanticMatch",
    "IntentAnalyzer",
    "IntentResult",
    "Intent",
    "LLMThreatDetector",
    "ThreatLevel",
    "ThreatDetectionResult",
]
