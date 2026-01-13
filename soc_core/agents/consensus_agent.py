"""
Consensus Agent.

This agent aggregates inputs from multiple agents (RiskAssessment, PolicyDecision,
AnalysisCompleted) and applies a weighted voting strategy to produce a final
RemediationDecision.

Each agent's contribution is logged for explainability.

Usage:
    from soc_core.events import EventBus
    from soc_core.agents import ConsensusAgent

    bus = EventBus()
    consensus_agent = ConsensusAgent(bus)
    consensus_agent.start()

    # Final decisions will be published
    bus.subscribe("RemediationDecision", my_handler)
"""

import uuid
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from collections import OrderedDict


@dataclass
class AgentVote:
    """Represents a single agent's vote in the consensus process."""
    agent_name: str
    vote: str  # execute, require_human, block, monitor, ignore
    weight: float
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""


@dataclass
class PendingDecision:
    """Tracks pending inputs for a correlation_id."""
    correlation_id: str
    alert_id: Optional[str] = None
    created_at: str = ""
    risk_assessment: Optional[Dict] = None
    policy_decision: Optional[Dict] = None
    analysis_completed: Optional[Dict] = None

    def inputs_received(self) -> int:
        """Count how many inputs have been received."""
        count = 0
        if self.risk_assessment:
            count += 1
        if self.policy_decision:
            count += 1
        if self.analysis_completed:
            count += 1
        return count

    def is_complete(self) -> bool:
        """Check if all expected inputs are received."""
        # We consider complete when we have at least 2 inputs
        # or when we have the analyst verdict (authoritative source)
        return self.inputs_received() >= 2 or self.analysis_completed is not None


class ConsensusAgent:
    """
    Consensus agent that aggregates multiple agent inputs using weighted voting.

    This agent:
    - Subscribes to RiskAssessment, PolicyDecision, and AnalysisCompleted events
    - Aggregates inputs by correlation_id
    - Applies a weighted voting strategy
    - Publishes RemediationDecision events with full explainability
    """

    # Event type constants
    EVENT_RISK_ASSESSMENT = "RiskAssessment"
    EVENT_POLICY_DECISION = "PolicyDecision"
    EVENT_ANALYSIS_COMPLETED = "AnalysisCompleted"
    EVENT_REMEDIATION_DECISION = "RemediationDecision"

    # Default weights for each agent type
    DEFAULT_WEIGHTS = {
        "analyst": 0.40,      # Human/AI analyst verdict is most trusted
        "risk_agent": 0.35,   # Risk assessment is important for severity
        "policy_agent": 0.25  # Policy provides guardrails
    }

    # Vote mappings from each event type
    RISK_LEVEL_TO_VOTE = {
        "critical": "block",
        "high": "require_human",
        "medium": "monitor",
        "low": "ignore"
    }

    POLICY_DECISION_TO_VOTE = {
        "allow": "execute",
        "deny": "block",
        "require_human": "require_human"
    }

    ANALYST_ACTION_TO_VOTE = {
        "block": "block",
        "escalate": "require_human",
        "investigate": "require_human",
        "monitor": "monitor",
        "ignore": "ignore"
    }

    ANALYST_VERDICT_TO_VOTE = {
        "true_positive": "block",
        "false_positive": "ignore",
        "requires_investigation": "require_human",
        "inconclusive": "monitor"
    }

    # Action priority for tie-breaking (higher = more urgent)
    ACTION_PRIORITY = {
        "block": 5,
        "require_human": 4,
        "execute": 3,
        "monitor": 2,
        "ignore": 1
    }

    def __init__(
        self,
        event_bus,
        weights: Dict[str, float] = None,
        decision_timeout_seconds: float = 30.0,
        max_pending: int = 1000,
        logger: logging.Logger = None
    ):
        """
        Initialize the consensus agent.

        Args:
            event_bus: The EventBus instance to use for pub/sub
            weights: Custom weights for each agent (must sum to 1.0)
            decision_timeout_seconds: Time to wait for all inputs before deciding
            max_pending: Maximum pending decisions to track (LRU eviction)
            logger: Optional logger instance
        """
        self.bus = event_bus
        self.logger = logger or logging.getLogger("ConsensusAgent")
        self.decision_timeout = decision_timeout_seconds
        self.max_pending = max_pending

        # Validate and set weights
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self._validate_weights()

        # Pending decisions tracked by correlation_id (LRU)
        self._pending: OrderedDict[str, PendingDecision] = OrderedDict()
        self._lock = threading.Lock()

        self._running = False
        self._subscribed_risk = False
        self._subscribed_policy = False
        self._subscribed_analysis = False

        # Statistics
        self.stats = {
            "risk_events_received": 0,
            "policy_events_received": 0,
            "analysis_events_received": 0,
            "decisions_published": 0,
            "decisions_by_action": {
                "execute": 0, "require_human": 0, "block": 0,
                "monitor": 0, "ignore": 0
            },
            "incomplete_decisions": 0,
            "evicted_pending": 0,
            "start_time": None,
            "stop_time": None
        }

    def _validate_weights(self) -> None:
        """Validate that weights sum to approximately 1.0."""
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            self.logger.warning(
                f"Weights sum to {total}, normalizing to 1.0"
            )
            for key in self.weights:
                self.weights[key] /= total

    def start(self) -> None:
        """Start the consensus agent and subscribe to events."""
        if self._running:
            self.logger.warning("ConsensusAgent is already running")
            return

        self.bus.subscribe(self.EVENT_RISK_ASSESSMENT, self._handle_risk_assessment)
        self._subscribed_risk = True

        self.bus.subscribe(self.EVENT_POLICY_DECISION, self._handle_policy_decision)
        self._subscribed_policy = True

        self.bus.subscribe(self.EVENT_ANALYSIS_COMPLETED, self._handle_analysis_completed)
        self._subscribed_analysis = True

        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.stats["stop_time"] = None

        self.logger.info(
            f"ConsensusAgent started with weights: "
            f"analyst={self.weights['analyst']:.0%}, "
            f"risk={self.weights['risk_agent']:.0%}, "
            f"policy={self.weights['policy_agent']:.0%}"
        )

    def stop(self) -> None:
        """Stop the consensus agent and unsubscribe from events."""
        if not self._running:
            self.logger.warning("ConsensusAgent is not running")
            return

        if self._subscribed_risk:
            self.bus.unsubscribe(self.EVENT_RISK_ASSESSMENT, self._handle_risk_assessment)
            self._subscribed_risk = False

        if self._subscribed_policy:
            self.bus.unsubscribe(self.EVENT_POLICY_DECISION, self._handle_policy_decision)
            self._subscribed_policy = False

        if self._subscribed_analysis:
            self.bus.unsubscribe(self.EVENT_ANALYSIS_COMPLETED, self._handle_analysis_completed)
            self._subscribed_analysis = False

        self._running = False
        self.stats["stop_time"] = datetime.now(timezone.utc).isoformat()

        self.logger.info("ConsensusAgent stopped")
        self._log_statistics()

    def is_running(self) -> bool:
        """Check if the agent is currently running."""
        return self._running

    def _get_or_create_pending(self, correlation_id: str) -> PendingDecision:
        """Get or create a pending decision for a correlation_id."""
        with self._lock:
            if correlation_id in self._pending:
                # Move to end (LRU)
                self._pending.move_to_end(correlation_id)
                return self._pending[correlation_id]

            # Evict oldest if at capacity
            while len(self._pending) >= self.max_pending:
                oldest_id, _ = self._pending.popitem(last=False)
                self.stats["evicted_pending"] += 1
                self.logger.debug(f"Evicted pending decision: {oldest_id}")

            # Create new pending decision
            pending = PendingDecision(
                correlation_id=correlation_id,
                created_at=datetime.now(timezone.utc).isoformat()
            )
            self._pending[correlation_id] = pending
            return pending

    def _handle_risk_assessment(self, event: dict) -> None:
        """Handle incoming RiskAssessment event."""
        self.stats["risk_events_received"] += 1
        correlation_id = event.get("correlation_id")

        if not correlation_id:
            self.logger.warning("RiskAssessment missing correlation_id")
            return

        try:
            pending = self._get_or_create_pending(correlation_id)
            pending.risk_assessment = event

            payload = event.get("payload", {})
            if not pending.alert_id:
                pending.alert_id = payload.get("alert_id")

            self._log_contribution(
                "risk_agent",
                correlation_id,
                payload.get("overall_risk_level"),
                payload.get("risk_score_numeric", 0)
            )

            self._try_reach_consensus(correlation_id)

        except Exception as e:
            self.logger.error(f"Error processing RiskAssessment: {e}")

    def _handle_policy_decision(self, event: dict) -> None:
        """Handle incoming PolicyDecision event."""
        self.stats["policy_events_received"] += 1
        correlation_id = event.get("correlation_id")

        if not correlation_id:
            self.logger.warning("PolicyDecision missing correlation_id")
            return

        try:
            pending = self._get_or_create_pending(correlation_id)
            pending.policy_decision = event

            payload = event.get("payload", {})
            if not pending.alert_id:
                pending.alert_id = payload.get("alert_id")

            self._log_contribution(
                "policy_agent",
                correlation_id,
                payload.get("decision"),
                1.0 if payload.get("decision") == "allow" else 0.5
            )

            self._try_reach_consensus(correlation_id)

        except Exception as e:
            self.logger.error(f"Error processing PolicyDecision: {e}")

    def _handle_analysis_completed(self, event: dict) -> None:
        """Handle incoming AnalysisCompleted event."""
        self.stats["analysis_events_received"] += 1
        correlation_id = event.get("correlation_id")

        if not correlation_id:
            self.logger.warning("AnalysisCompleted missing correlation_id")
            return

        try:
            pending = self._get_or_create_pending(correlation_id)
            pending.analysis_completed = event

            payload = event.get("payload", {})
            if not pending.alert_id:
                pending.alert_id = payload.get("alert_id")

            self._log_contribution(
                "analyst",
                correlation_id,
                payload.get("verdict"),
                payload.get("certainty_score", 0.5)
            )

            self._try_reach_consensus(correlation_id)

        except Exception as e:
            self.logger.error(f"Error processing AnalysisCompleted: {e}")

    def _log_contribution(
        self,
        agent_name: str,
        correlation_id: str,
        value: Any,
        confidence: float
    ) -> None:
        """Log an agent's contribution for explainability."""
        self.logger.info(
            f"[CONTRIBUTION] {agent_name} for {correlation_id[:8]}... "
            f"value={value}, confidence={confidence:.2f}"
        )

    def _try_reach_consensus(self, correlation_id: str) -> None:
        """Check if we can reach consensus and publish decision if so."""
        with self._lock:
            if correlation_id not in self._pending:
                return
            pending = self._pending[correlation_id]

        # Check if we have enough inputs
        if not pending.is_complete():
            self.logger.debug(
                f"Waiting for more inputs: {pending.inputs_received()}/3 received"
            )
            return

        # We have enough to decide
        self._publish_consensus(pending)

        # Clean up
        with self._lock:
            self._pending.pop(correlation_id, None)

    def _collect_votes(self, pending: PendingDecision) -> List[AgentVote]:
        """Collect votes from all available inputs."""
        votes = []

        # Risk Assessment vote
        if pending.risk_assessment:
            payload = pending.risk_assessment.get("payload", {})
            risk_level = payload.get("overall_risk_level", "medium")
            vote = self.RISK_LEVEL_TO_VOTE.get(risk_level, "monitor")

            # Adjust confidence based on risk score
            risk_score = payload.get("risk_score_numeric", 50)
            confidence = min(1.0, risk_score / 100 + 0.3)

            votes.append(AgentVote(
                agent_name="risk_agent",
                vote=vote,
                weight=self.weights["risk_agent"],
                confidence=confidence,
                timestamp=pending.risk_assessment.get("timestamp", ""),
                details={
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                    "recommendations": payload.get("recommendations", [])
                }
            ))

        # Policy Decision vote
        if pending.policy_decision:
            payload = pending.policy_decision.get("payload", {})
            decision = payload.get("decision", "require_human")
            vote = self.POLICY_DECISION_TO_VOTE.get(decision, "require_human")

            votes.append(AgentVote(
                agent_name="policy_agent",
                vote=vote,
                weight=self.weights["policy_agent"],
                confidence=0.9,  # Policy is deterministic
                timestamp=pending.policy_decision.get("timestamp", ""),
                details={
                    "decision": decision,
                    "reason": payload.get("reason", ""),
                    "matched_rules": payload.get("matched_rules", [])
                }
            ))

        # Analysis Completed vote
        if pending.analysis_completed:
            payload = pending.analysis_completed.get("payload", {})

            # Prefer recommended_action, fall back to verdict
            recommended_action = payload.get("recommended_action")
            verdict = payload.get("verdict", "inconclusive")
            certainty = payload.get("certainty_score", 0.5)

            if recommended_action:
                vote = self.ANALYST_ACTION_TO_VOTE.get(recommended_action, "require_human")
            else:
                vote = self.ANALYST_VERDICT_TO_VOTE.get(verdict, "require_human")

            votes.append(AgentVote(
                agent_name="analyst",
                vote=vote,
                weight=self.weights["analyst"],
                confidence=certainty,
                timestamp=pending.analysis_completed.get("timestamp", ""),
                details={
                    "verdict": verdict,
                    "certainty": certainty,
                    "recommended_action": recommended_action
                }
            ))

        return votes

    def _weighted_vote(self, votes: List[AgentVote]) -> tuple:
        """
        Apply weighted voting to determine the final action.

        Returns:
            Tuple of (action, confidence, vote_breakdown)
        """
        if not votes:
            return "require_human", 0.0, {}

        # Aggregate weighted scores for each action
        action_scores: Dict[str, float] = {}
        total_weight = 0.0

        for vote in votes:
            weighted_score = vote.weight * vote.confidence
            action_scores[vote.vote] = action_scores.get(vote.vote, 0) + weighted_score
            total_weight += vote.weight

        # Normalize scores
        if total_weight > 0:
            for action in action_scores:
                action_scores[action] /= total_weight

        # Find winning action
        if not action_scores:
            return "require_human", 0.0, {}

        # Sort by score, then by priority for tie-breaking
        sorted_actions = sorted(
            action_scores.items(),
            key=lambda x: (x[1], self.ACTION_PRIORITY.get(x[0], 0)),
            reverse=True
        )

        winning_action = sorted_actions[0][0]
        confidence = sorted_actions[0][1]

        return winning_action, confidence, action_scores

    def _determine_urgency(self, action: str, votes: List[AgentVote]) -> str:
        """Determine urgency level based on action and inputs."""
        if action == "block":
            return "critical"
        if action == "require_human":
            # Check if any vote indicates high risk
            for vote in votes:
                if vote.details.get("risk_level") in ("critical", "high"):
                    return "high"
            return "medium"
        if action == "execute":
            return "medium"
        if action == "monitor":
            return "low"
        return "low"

    def _generate_reasoning(
        self,
        action: str,
        votes: List[AgentVote],
        vote_breakdown: Dict[str, float]
    ) -> str:
        """Generate human-readable reasoning for the decision."""
        parts = []

        # Describe the winning action
        action_descriptions = {
            "execute": "Proceeding with automatic execution",
            "require_human": "Requiring human approval before action",
            "block": "Blocking the activity immediately",
            "monitor": "Continuing with enhanced monitoring",
            "ignore": "No action required"
        }
        parts.append(action_descriptions.get(action, f"Action: {action}"))

        # Describe vote contributions
        for vote in votes:
            if vote.agent_name == "analyst":
                parts.append(
                    f"Analyst verdict: {vote.details.get('verdict')} "
                    f"(certainty: {vote.details.get('certainty', 0):.0%})"
                )
            elif vote.agent_name == "risk_agent":
                parts.append(
                    f"Risk level: {vote.details.get('risk_level')} "
                    f"(score: {vote.details.get('risk_score', 0):.0f})"
                )
            elif vote.agent_name == "policy_agent":
                parts.append(
                    f"Policy decision: {vote.details.get('decision')}"
                )

        return ". ".join(parts) + "."

    def _publish_consensus(self, pending: PendingDecision) -> None:
        """Create and publish a RemediationDecision event."""
        votes = self._collect_votes(pending)
        action, confidence, vote_breakdown = self._weighted_vote(votes)
        urgency = self._determine_urgency(action, votes)
        reasoning = self._generate_reasoning(action, votes, vote_breakdown)

        # Build contributors dict for explainability
        contributors = {}
        for vote in votes:
            contributors[vote.agent_name] = {
                "received": True,
                "weight": vote.weight,
                "vote": vote.vote,
                "weighted_score": vote.weight * vote.confidence,
                "details": vote.details
            }

        # Mark missing contributors
        for agent in ["risk_agent", "policy_agent", "analyst"]:
            if agent not in contributors:
                contributors[agent] = {
                    "received": False,
                    "weight": self.weights.get(agent, 0),
                    "vote": None,
                    "weighted_score": 0,
                    "details": {}
                }

        # Log detailed contribution summary
        self.logger.info(
            f"[CONSENSUS] {pending.correlation_id[:8]}... -> {action} "
            f"(confidence: {confidence:.0%})"
        )
        for vote in votes:
            self.logger.info(
                f"  - {vote.agent_name}: vote={vote.vote}, "
                f"weight={vote.weight:.0%}, confidence={vote.confidence:.0%}, "
                f"weighted_score={vote.weight * vote.confidence:.2f}"
            )

        # Build event
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        is_incomplete = pending.inputs_received() < 3
        if is_incomplete:
            self.stats["incomplete_decisions"] += 1

        decision_event = {
            "event_id": event_id,
            "correlation_id": pending.correlation_id,
            "timestamp": timestamp,
            "producer": "consensus_agent",
            "payload": {
                "decision_id": f"consensus-{event_id[:8]}",
                "alert_id": pending.alert_id,
                "action": action,
                "confidence": round(confidence, 3),
                "urgency": urgency,
                "reasoning": reasoning,
                "contributors": contributors,
                "voting_summary": {
                    "total_weight": sum(v.weight for v in votes),
                    "votes_received": len(votes),
                    "votes_expected": 3,
                    "consensus_threshold": 0.5,
                    "consensus_reached": confidence >= 0.5,
                    "vote_breakdown": {k: round(v, 3) for k, v in vote_breakdown.items()}
                }
            }
        }

        if is_incomplete:
            missing = []
            if not pending.risk_assessment:
                missing.append("risk_agent")
            if not pending.policy_decision:
                missing.append("policy_agent")
            if not pending.analysis_completed:
                missing.append("analyst")
            decision_event["payload"]["incomplete_reason"] = (
                f"Missing inputs from: {', '.join(missing)}"
            )

        self.bus.publish(self.EVENT_REMEDIATION_DECISION, decision_event)
        self.stats["decisions_published"] += 1
        self.stats["decisions_by_action"][action] += 1

        self.logger.debug(f"RemediationDecision published: {action}")

    def force_decision(self, correlation_id: str) -> bool:
        """
        Force a decision for a pending correlation_id with available inputs.

        Returns:
            True if a decision was published, False if no pending found.
        """
        with self._lock:
            if correlation_id not in self._pending:
                return False
            pending = self._pending[correlation_id]

        if pending.inputs_received() == 0:
            self.logger.warning(f"No inputs received for {correlation_id}")
            return False

        self._publish_consensus(pending)

        with self._lock:
            self._pending.pop(correlation_id, None)

        return True

    def _log_statistics(self) -> None:
        """Log agent statistics."""
        self.logger.info("=== ConsensusAgent Statistics ===")
        self.logger.info(f"RiskAssessment received: {self.stats['risk_events_received']}")
        self.logger.info(f"PolicyDecision received: {self.stats['policy_events_received']}")
        self.logger.info(f"AnalysisCompleted received: {self.stats['analysis_events_received']}")
        self.logger.info(f"Decisions published: {self.stats['decisions_published']}")
        self.logger.info(f"Actions breakdown: {self.stats['decisions_by_action']}")
        self.logger.info(f"Incomplete decisions: {self.stats['incomplete_decisions']}")

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        return self.stats.copy()

    def get_pending_count(self) -> int:
        """Get count of pending decisions."""
        with self._lock:
            return len(self._pending)
