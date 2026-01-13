"""
Policy Agent.

This agent subscribes to RemediationProposed events, evaluates them
against a JSON policy file, and publishes PolicyDecision events.

Policies are reloadable without restarting - the agent checks file
modification time before each evaluation.

Usage:
    from soc_core.events import EventBus
    from soc_core.agents import PolicyAgent

    bus = EventBus()
    policy_agent = PolicyAgent(bus, policy_path="path/to/policy.json")
    policy_agent.start()

    # Policy decisions will be published for incoming remediation proposals
    bus.subscribe("PolicyDecision", my_handler)
"""

import os
import json
import uuid
import fnmatch
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class PolicyRule:
    """Represents a single policy rule."""
    id: str
    name: str
    conditions: Dict[str, Any]
    decision: str  # allow | deny | require_human
    priority: int = 50
    description: str = ""
    reason: str = ""


@dataclass
class Policy:
    """Loaded policy configuration."""
    version: str
    description: str
    default_decision: str
    rules: List[PolicyRule] = field(default_factory=list)


class PolicyAgent:
    """
    Policy evaluation agent for remediation proposals.

    This agent:
    - Subscribes to RemediationProposed events
    - Evaluates proposed actions against a JSON policy file
    - Publishes PolicyDecision events with allow/deny/require_human decisions
    - Supports hot-reloading of policies without restart
    """

    # Event type constants
    EVENT_REMEDIATION_PROPOSED = "RemediationProposed"
    EVENT_POLICY_DECISION = "PolicyDecision"

    # Valid decisions
    VALID_DECISIONS = {"allow", "deny", "require_human"}

    def __init__(
        self,
        event_bus,
        policy_path: str = None,
        logger: logging.Logger = None
    ):
        """
        Initialize the policy agent.

        Args:
            event_bus: The EventBus instance to use for pub/sub
            policy_path: Path to the JSON policy file
            logger: Optional logger instance
        """
        self.bus = event_bus
        self.logger = logger or logging.getLogger("PolicyAgent")

        # Default policy path
        if policy_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            policy_path = os.path.join(base_dir, "policies", "remediation_policy.json")

        self.policy_path = policy_path
        self._policy: Optional[Policy] = None
        self._policy_mtime: float = 0

        self._running = False
        self._subscribed = False

        # Statistics
        self.stats = {
            "events_received": 0,
            "decisions_published": 0,
            "decisions": {"allow": 0, "deny": 0, "require_human": 0},
            "policy_reloads": 0,
            "evaluation_errors": 0,
            "start_time": None,
            "stop_time": None
        }

    def start(self) -> None:
        """
        Start the policy agent.

        Subscribes to RemediationProposed events and loads the policy file.
        """
        if self._running:
            self.logger.warning("PolicyAgent is already running")
            return

        # Load policy on start
        self._reload_policy_if_changed()

        self.bus.subscribe(self.EVENT_REMEDIATION_PROPOSED, self._handle_remediation_proposed)
        self._subscribed = True

        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self.stats["stop_time"] = None

        self.logger.info(f"PolicyAgent started with policy: {self.policy_path}")

    def stop(self) -> None:
        """
        Stop the policy agent.

        Unsubscribes from all events.
        """
        if not self._running:
            self.logger.warning("PolicyAgent is not running")
            return

        if self._subscribed:
            self.bus.unsubscribe(self.EVENT_REMEDIATION_PROPOSED, self._handle_remediation_proposed)
            self._subscribed = False

        self._running = False
        self.stats["stop_time"] = datetime.now(timezone.utc).isoformat()

        self.logger.info("PolicyAgent stopped")
        self._log_statistics()

    def is_running(self) -> bool:
        """Check if the agent is currently running."""
        return self._running

    def reload_policy(self) -> bool:
        """
        Force reload the policy file.

        Returns:
            True if policy was loaded successfully, False otherwise.
        """
        return self._load_policy()

    def _reload_policy_if_changed(self) -> None:
        """Check if policy file has changed and reload if needed."""
        try:
            if not os.path.exists(self.policy_path):
                self.logger.warning(f"Policy file not found: {self.policy_path}")
                return

            current_mtime = os.path.getmtime(self.policy_path)
            if current_mtime > self._policy_mtime:
                self._load_policy()
        except OSError as e:
            self.logger.error(f"Error checking policy file: {e}")

    def _load_policy(self) -> bool:
        """
        Load the policy file from disk.

        Returns:
            True if successful, False otherwise.
        """
        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Parse rules
            rules = []
            for rule_data in data.get("rules", []):
                rule = PolicyRule(
                    id=rule_data.get("id", str(uuid.uuid4())),
                    name=rule_data.get("name", "Unnamed Rule"),
                    conditions=rule_data.get("conditions", {}),
                    decision=rule_data.get("decision", "require_human"),
                    priority=rule_data.get("priority", 50),
                    description=rule_data.get("description", ""),
                    reason=rule_data.get("reason", "")
                )

                # Validate decision
                if rule.decision not in self.VALID_DECISIONS:
                    self.logger.warning(
                        f"Invalid decision '{rule.decision}' in rule {rule.id}, "
                        f"defaulting to 'require_human'"
                    )
                    rule.decision = "require_human"

                rules.append(rule)

            # Sort rules by priority (lower = higher priority)
            rules.sort(key=lambda r: r.priority)

            self._policy = Policy(
                version=data.get("version", "unknown"),
                description=data.get("description", ""),
                default_decision=data.get("default_decision", "require_human"),
                rules=rules
            )

            self._policy_mtime = os.path.getmtime(self.policy_path)
            self.stats["policy_reloads"] += 1

            self.logger.info(
                f"Loaded policy v{self._policy.version} with {len(rules)} rules"
            )
            return True

        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in policy file: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error loading policy: {e}")
            return False

    def _handle_remediation_proposed(self, event: dict) -> None:
        """Handle incoming RemediationProposed event."""
        self.stats["events_received"] += 1

        try:
            # Check for policy updates before evaluation
            self._reload_policy_if_changed()

            if self._policy is None:
                self.logger.error("No policy loaded, defaulting to require_human")
                decision = "require_human"
                reason = "No policy file loaded"
                matched_rules = []
                evaluated_actions = []
            else:
                decision, reason, matched_rules, evaluated_actions = self._evaluate_event(event)

            self._publish_decision(event, decision, reason, matched_rules, evaluated_actions)

        except Exception as e:
            self.logger.error(f"Error processing RemediationProposed: {e}")
            self.stats["evaluation_errors"] += 1
            # Publish a safe default on error
            self._publish_decision(
                event,
                "require_human",
                f"Evaluation error: {str(e)}",
                [],
                []
            )

    def _evaluate_event(self, event: dict) -> tuple:
        """
        Evaluate a RemediationProposed event against the policy.

        Returns:
            Tuple of (decision, reason, matched_rules, evaluated_actions)
        """
        payload = event.get("payload", {})
        proposed_actions = payload.get("proposed_actions", [])
        threat_type = payload.get("threat_type")
        requires_approval = payload.get("requires_approval", True)

        matched_rules = []
        evaluated_actions = []
        action_decisions = []

        # Evaluate each proposed action
        for action in proposed_actions:
            action_id = action.get("action_id", "unknown")
            action_type = action.get("action_type")
            target = action.get("target", {})

            # Find matching rule for this action
            rule_match = self._find_matching_rule(
                action_type=action_type,
                threat_type=threat_type,
                target=target,
                requires_approval=requires_approval
            )

            if rule_match:
                action_decision = rule_match.decision
                action_reason = rule_match.reason or f"Matched rule: {rule_match.name}"
                matched_rules.append({
                    "rule_id": rule_match.id,
                    "rule_name": rule_match.name,
                    "decision": rule_match.decision
                })
            else:
                action_decision = self._policy.default_decision
                action_reason = "No matching rule, using default policy"

            evaluated_actions.append({
                "action_id": action_id,
                "action_type": action_type,
                "decision": action_decision,
                "reason": action_reason
            })
            action_decisions.append(action_decision)

        # Determine overall decision (most restrictive wins)
        if "deny" in action_decisions:
            overall_decision = "deny"
            denied_actions = [
                ea for ea in evaluated_actions if ea["decision"] == "deny"
            ]
            overall_reason = f"Denied due to: {denied_actions[0]['reason']}"
        elif "require_human" in action_decisions:
            overall_decision = "require_human"
            human_actions = [
                ea for ea in evaluated_actions if ea["decision"] == "require_human"
            ]
            action_types = [ea["action_type"] for ea in human_actions]
            overall_reason = f"Human approval required for: {', '.join(action_types)}"
        elif action_decisions:
            overall_decision = "allow"
            overall_reason = "All proposed actions are allowed by policy"
        else:
            overall_decision = self._policy.default_decision
            overall_reason = "No actions to evaluate"

        return overall_decision, overall_reason, matched_rules, evaluated_actions

    def _find_matching_rule(
        self,
        action_type: str,
        threat_type: Optional[str],
        target: Dict[str, Any],
        requires_approval: bool
    ) -> Optional[PolicyRule]:
        """
        Find the highest priority rule that matches the given criteria.

        Args:
            action_type: The type of remediation action
            threat_type: The threat type being remediated
            target: The target of the action (ip, user, etc.)
            requires_approval: Whether the original proposal requires approval

        Returns:
            The matching PolicyRule or None
        """
        for rule in self._policy.rules:
            if self._rule_matches(rule, action_type, threat_type, target, requires_approval):
                return rule
        return None

    def _rule_matches(
        self,
        rule: PolicyRule,
        action_type: str,
        threat_type: Optional[str],
        target: Dict[str, Any],
        requires_approval: bool
    ) -> bool:
        """Check if a rule matches the given criteria."""
        conditions = rule.conditions

        # Check action_types condition
        allowed_actions = conditions.get("action_types", ["*"])
        if "*" not in allowed_actions and action_type not in allowed_actions:
            return False

        # Check threat_types condition
        allowed_threats = conditions.get("threat_types", ["*"])
        if "*" not in allowed_threats:
            if threat_type is None or threat_type not in allowed_threats:
                return False

        # Check requires_approval condition
        if "requires_approval" in conditions:
            if conditions["requires_approval"] != requires_approval:
                return False

        # Check target_patterns condition
        target_patterns = conditions.get("target_patterns", {})
        for field, patterns in target_patterns.items():
            target_value = target.get(field, "")
            if target_value:
                # Check if any pattern matches
                matched = False
                for pattern in patterns:
                    if fnmatch.fnmatch(target_value, pattern):
                        matched = True
                        break
                if not matched:
                    return False

        return True

    def _publish_decision(
        self,
        source_event: dict,
        decision: str,
        reason: str,
        matched_rules: List[Dict],
        evaluated_actions: List[Dict]
    ) -> None:
        """Create and publish a PolicyDecision event."""
        event_id = str(uuid.uuid4())
        correlation_id = source_event.get("correlation_id", str(uuid.uuid4()))
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = source_event.get("payload", {})

        decision_event = {
            "event_id": event_id,
            "correlation_id": correlation_id,
            "timestamp": timestamp,
            "producer": "policy_agent",
            "payload": {
                "decision_id": f"policy-{event_id[:8]}",
                "remediation_id": payload.get("playbook_id"),
                "alert_id": payload.get("alert_id"),
                "decision": decision,
                "reason": reason,
                "matched_rules": matched_rules,
                "evaluated_actions": evaluated_actions,
                "policy_version": self._policy.version if self._policy else "unknown"
            }
        }

        self.bus.publish(self.EVENT_POLICY_DECISION, decision_event)
        self.stats["decisions_published"] += 1
        self.stats["decisions"][decision] += 1

        self.logger.debug(
            f"Policy decision published: {decision} - {reason}"
        )

    def _log_statistics(self) -> None:
        """Log agent statistics."""
        self.logger.info("=== PolicyAgent Statistics ===")
        self.logger.info(f"Events received: {self.stats['events_received']}")
        self.logger.info(f"Decisions published: {self.stats['decisions_published']}")
        self.logger.info(f"Decision breakdown: {self.stats['decisions']}")
        self.logger.info(f"Policy reloads: {self.stats['policy_reloads']}")
        self.logger.info(f"Evaluation errors: {self.stats['evaluation_errors']}")

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        return self.stats.copy()

    def get_policy_info(self) -> Dict[str, Any]:
        """Get information about the currently loaded policy."""
        if self._policy is None:
            return {"loaded": False}

        return {
            "loaded": True,
            "version": self._policy.version,
            "description": self._policy.description,
            "default_decision": self._policy.default_decision,
            "rule_count": len(self._policy.rules),
            "policy_path": self.policy_path
        }
