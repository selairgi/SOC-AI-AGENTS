"""
SOC Agents - Event-driven security agents.

Main Agents:
- SOCDetector: Threat detection (RawLogEvent -> AlertDetected)
- SOCAnalyst: Threat analysis (AlertDetected -> AnalysisCompleted)
- SOCRemediator: Remediation execution (RemediationDecision -> RemediationExecuted)

These agents use the EventBus for communication and support:
- Synchronous event-driven architecture
- correlation_id propagation for tracing
- Incremental learning data collection
- dry_run mode for safe testing
"""

# Main agents (the 3 core agents)
from .soc_detector import SOCDetector
from .soc_analyst import SOCAnalyst
from .soc_remediator import SOCRemediator

# Legacy adapters for backward compatibility
from .unified_adapters import (
    UnifiedDetectorAdapter,
    UnifiedAnalystAdapter,
    UnifiedRemediatorAdapter,
    IncrementalStorage,
)

# Re-export from governance (for convenience)
from ..governance import PolicyAgent, ConsensusAgent, HumanApprovalAgent

__all__ = [
    # Main agents
    "SOCDetector",
    "SOCAnalyst",
    "SOCRemediator",
    # Governance (re-exported)
    "PolicyAgent",
    "ConsensusAgent",
    "HumanApprovalAgent",
    # Legacy adapters
    "UnifiedDetectorAdapter",
    "UnifiedAnalystAdapter",
    "UnifiedRemediatorAdapter",
    "IncrementalStorage",
]
