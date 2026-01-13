"""
SOC Pipeline - Orchestrates the complete threat detection and response workflow.

The pipeline connects:
    RawLogEvent
        -> SOCDetector (AlertDetected)
        -> SOCAnalyst (AnalysisCompleted)
        -> PolicyAgent (PolicyDecision)
        -> ConsensusAgent (RemediationDecision)
        -> [HumanApproval if required]
        -> SOCRemediator (RemediationExecuted)

All events are tracked in IncidentStateManager by correlation_id.
"""

from .orchestrator import SOCPipelineOrchestrator

__all__ = ["SOCPipelineOrchestrator"]
