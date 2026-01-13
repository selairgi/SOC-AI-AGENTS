"""
SOC Core - Event-driven SOC agent infrastructure.

Architecture:
    Events -> SOCDetector -> SOCAnalyst -> Governance -> SOCRemediator -> Actions

Main Components:
- agents/: Core agents (SOCDetector, SOCAnalyst, SOCRemediator)
- events/: EventBus for pub/sub communication
- governance/: PolicyAgent, ConsensusAgent, HumanApprovalAgent
- learning/: IncrementalStorage, OfflineTrainer, ModelRegistry
- state/: IncidentStateManager for tracking
- pipeline/: SOCPipelineOrchestrator
- utils/: FalsePositiveDetector, CircuitBreaker, ExecutionTracker, InputSanitizer

Usage:
    from soc_core.pipeline import SOCPipelineOrchestrator

    with SOCPipelineOrchestrator(dry_run=True) as pipeline:
        result = pipeline.submit_log({
            "message": "Failed login from 192.168.1.100",
            "source": "auth_service",
            "source_ip": "192.168.1.100"
        })
        incident = pipeline.get_incident(result["correlation_id"])
"""

# Events
from .events import EventBus

# Main agents
from .agents import (
    SOCDetector,
    SOCAnalyst,
    SOCRemediator,
)

# Governance
from .governance import (
    PolicyAgent,
    ConsensusAgent,
    HumanApprovalAgent,
)

# State management
from .state import IncidentStateManager

# Learning
from .learning import (
    IncrementalStorage,
    OfflineTrainer,
    ModelRegistry,
)

# Utilities (migrated from core/)
from .utils import (
    FalsePositiveDetector,
    CircuitBreaker,
    ExecutionTracker,
    InputSanitizer,
)

# Pipeline
from .pipeline import SOCPipelineOrchestrator

__all__ = [
    # Events
    "EventBus",
    # Main agents
    "SOCDetector",
    "SOCAnalyst",
    "SOCRemediator",
    # Governance
    "PolicyAgent",
    "ConsensusAgent",
    "HumanApprovalAgent",
    # State
    "IncidentStateManager",
    # Learning
    "IncrementalStorage",
    "OfflineTrainer",
    "ModelRegistry",
    # Utils
    "FalsePositiveDetector",
    "CircuitBreaker",
    "ExecutionTracker",
    "InputSanitizer",
    # Pipeline
    "SOCPipelineOrchestrator",
]
