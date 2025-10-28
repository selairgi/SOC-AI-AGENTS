"""
Policy-as-Code Engine for SOC AI Agents
Replaces brittle validation with robust libraries and testable policies.
Uses ipaddress library for IP/CIDR validation and implements OPA-style policy evaluation.
"""

import ipaddress
import re
import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("PolicyEngine")


class PolicyDecision(Enum):
    """Policy evaluation decision"""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    DRY_RUN_ONLY = "dry_run_only"


@dataclass
class PolicyResult:
    """Result of policy evaluation"""
    decision: PolicyDecision
    reasons: List[str]
    matched_policies: List[str]
    metadata: Dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.decision == PolicyDecision.ALLOW

    @property
    def requires_approval(self) -> bool:
        return self.decision == PolicyDecision.REQUIRE_APPROVAL


class ValidationError(Exception):
    """Validation error"""
    pass


class IPValidator:
    """Robust IP address and CIDR validation using ipaddress library"""

    @staticmethod
    def validate_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
        """
        Validate IP address (IPv4 or IPv6).

        Returns:
            Tuple of (valid, error_message)
        """
        try:
            ipaddress.ip_address(ip_str)
            return True, None
        except ValueError as e:
            return False, f"Invalid IP address: {e}"

    @staticmethod
    def validate_cidr(cidr_str: str) -> Tuple[bool, Optional[str]]:
        """
        Validate CIDR notation.

        Returns:
            Tuple of (valid, error_message)
        """
        try:
            ipaddress.ip_network(cidr_str, strict=False)
            return True, None
        except ValueError as e:
            return False, f"Invalid CIDR: {e}"

    @staticmethod
    def ip_in_network(ip_str: str, cidr_str: str) -> bool:
        """Check if IP is in network"""
        try:
            ip = ipaddress.ip_address(ip_str)
            network = ipaddress.ip_network(cidr_str, strict=False)
            return ip in network
        except ValueError:
            return False

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP is private (RFC1918, etc.)"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    @staticmethod
    def is_reserved_ip(ip_str: str) -> bool:
        """Check if IP is reserved"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_reserved or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False


class TargetValidator:
    """Validate remediation targets"""

    @staticmethod
    def validate_ip_target(target: str) -> Tuple[bool, Optional[str]]:
        """Validate IP address target"""
        return IPValidator.validate_ip(target)

    @staticmethod
    def validate_user_target(target: str) -> Tuple[bool, Optional[str]]:
        """Validate user ID target"""
        if not target or len(target) > 256:
            return False, "User ID must be 1-256 characters"

        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9_\-@.]+$', target):
            return False, "User ID contains invalid characters"

        return True, None

    @staticmethod
    def validate_session_target(target: str) -> Tuple[bool, Optional[str]]:
        """Validate session ID target"""
        if not target or len(target) > 256:
            return False, "Session ID must be 1-256 characters"

        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9_\-]+$', target):
            return False, "Session ID contains invalid characters"

        return True, None

    @staticmethod
    def validate_agent_target(target: str) -> Tuple[bool, Optional[str]]:
        """Validate agent ID target"""
        if not target or len(target) > 256:
            return False, "Agent ID must be 1-256 characters"

        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9_\-]+$', target):
            return False, "Agent ID contains invalid characters"

        return True, None


class PolicyRule:
    """Base class for policy rules"""

    def __init__(self, rule_id: str, description: str, priority: int = 100):
        self.rule_id = rule_id
        self.description = description
        self.priority = priority  # Lower = higher priority

    def evaluate(self, context: Dict[str, Any]) -> Optional[PolicyResult]:
        """
        Evaluate rule against context.

        Returns:
            PolicyResult if rule matches, None otherwise
        """
        raise NotImplementedError


class BlockReservedIPRule(PolicyRule):
    """Deny blocking of reserved/loopback IPs"""

    def __init__(self):
        super().__init__(
            "block_reserved_ip",
            "Prevent blocking of reserved, loopback, or link-local IPs",
            priority=10  # High priority
        )

    def evaluate(self, context: Dict[str, Any]) -> Optional[PolicyResult]:
        action = context.get('action', '')
        target = context.get('target', '')

        if action == 'block_ip':
            if IPValidator.is_reserved_ip(target):
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reasons=[f"Cannot block reserved/loopback IP: {target}"],
                    matched_policies=[self.rule_id],
                    metadata={'reserved_ip': target}
                )

        return None


class PrivateIPApprovalRule(PolicyRule):
    """Require approval for blocking private IPs"""

    def __init__(self):
        super().__init__(
            "private_ip_approval",
            "Require approval for blocking private IPs",
            priority=20
        )

    def evaluate(self, context: Dict[str, Any]) -> Optional[PolicyResult]:
        action = context.get('action', '')
        target = context.get('target', '')

        if action == 'block_ip':
            if IPValidator.is_private_ip(target):
                return PolicyResult(
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    reasons=[f"Blocking private IP requires approval: {target}"],
                    matched_policies=[self.rule_id],
                    metadata={'private_ip': target}
                )

        return None


class ProductionApprovalRule(PolicyRule):
    """Require approval for actions in production"""

    def __init__(self):
        super().__init__(
            "production_approval",
            "Require approval for all remediation in production",
            priority=30
        )

    def evaluate(self, context: Dict[str, Any]) -> Optional[PolicyResult]:
        environment = context.get('environment', 'development')

        if environment == 'production':
            action = context.get('action', '')
            if action in ['block_ip', 'suspend_user', 'terminate_session', 'isolate_agent']:
                return PolicyResult(
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    reasons=[f"Action '{action}' in production requires approval"],
                    matched_policies=[self.rule_id],
                    metadata={'environment': environment}
                )

        return None


class WhitelistIPRule(PolicyRule):
    """Never block whitelisted IPs"""

    def __init__(self, whitelist: List[str]):
        super().__init__(
            "whitelist_ip",
            "Prevent blocking of whitelisted IPs",
            priority=5  # Very high priority
        )
        self.whitelist = set(whitelist)

    def evaluate(self, context: Dict[str, Any]) -> Optional[PolicyResult]:
        action = context.get('action', '')
        target = context.get('target', '')

        if action == 'block_ip':
            if target in self.whitelist:
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reasons=[f"Cannot block whitelisted IP: {target}"],
                    matched_policies=[self.rule_id],
                    metadata={'whitelisted_ip': target}
                )

            # Check if target is in whitelisted network
            for whitelisted in self.whitelist:
                if '/' in whitelisted:  # CIDR notation
                    if IPValidator.ip_in_network(target, whitelisted):
                        return PolicyResult(
                            decision=PolicyDecision.DENY,
                            reasons=[f"Cannot block IP in whitelisted network: {target} in {whitelisted}"],
                            matched_policies=[self.rule_id],
                            metadata={'whitelisted_network': whitelisted}
                        )

        return None


class HighRiskApprovalRule(PolicyRule):
    """Require approval for high-risk actions"""

    def __init__(self, high_risk_actions: Optional[List[str]] = None):
        super().__init__(
            "high_risk_approval",
            "Require approval for high-risk actions",
            priority=25
        )
        self.high_risk_actions = set(high_risk_actions or [
            'suspend_user',
            'isolate_agent',
            'wipe_data',
            'shutdown_system'
        ])

    def evaluate(self, context: Dict[str, Any]) -> Optional[PolicyResult]:
        action = context.get('action', '')

        if action in self.high_risk_actions:
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reasons=[f"High-risk action '{action}' requires approval"],
                matched_policies=[self.rule_id],
                metadata={'risk_level': 'high', 'action': action}
            )

        return None


class DryRunDefaultRule(PolicyRule):
    """Default to dry-run for new playbooks"""

    def __init__(self):
        super().__init__(
            "dry_run_default",
            "New playbooks default to dry-run mode",
            priority=1000  # Low priority (catch-all)
        )

    def evaluate(self, context: Dict[str, Any]) -> Optional[PolicyResult]:
        is_new = context.get('is_new_playbook', True)
        has_approval = context.get('has_approval', False)

        if is_new and not has_approval:
            return PolicyResult(
                decision=PolicyDecision.DRY_RUN_ONLY,
                reasons=["New playbooks require dry-run before execution"],
                matched_policies=[self.rule_id],
                metadata={'requires_dry_run': True}
            )

        return None


class PolicyEngine:
    """OPA-style policy engine for evaluating remediation actions"""

    def __init__(self):
        self.rules: List[PolicyRule] = []
        self._load_default_policies()
        logger.info("Policy engine initialized with default policies")

    def _load_default_policies(self):
        """Load default security policies"""
        # High priority rules (blocking)
        self.add_rule(WhitelistIPRule(['127.0.0.1', '::1', '10.0.0.0/8']))
        self.add_rule(BlockReservedIPRule())

        # Medium priority rules (approval required)
        self.add_rule(PrivateIPApprovalRule())
        self.add_rule(HighRiskApprovalRule())
        self.add_rule(ProductionApprovalRule())

        # Low priority rules (defaults)
        self.add_rule(DryRunDefaultRule())

    def add_rule(self, rule: PolicyRule):
        """Add a policy rule"""
        self.rules.append(rule)
        # Sort by priority (lower number = higher priority)
        self.rules.sort(key=lambda r: r.priority)
        logger.debug(f"Added policy rule: {rule.rule_id}")

    def evaluate(self, context: Dict[str, Any]) -> PolicyResult:
        """
        Evaluate all policies against context.

        Args:
            context: Context containing:
                - action: Action to perform
                - target: Target of action
                - environment: Environment (production, development, etc.)
                - severity: Alert severity
                - is_new_playbook: Whether this is a new playbook
                - has_approval: Whether playbook is approved
                - created_by: User who created playbook
                - metadata: Additional context

        Returns:
            PolicyResult with final decision
        """
        logger.debug(f"Evaluating policies for action: {context.get('action')}")

        # Validate target first
        action = context.get('action', '')
        target = context.get('target', '')

        validation_result = self._validate_target(action, target)
        if not validation_result[0]:
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reasons=[f"Target validation failed: {validation_result[1]}"],
                matched_policies=['target_validation'],
                metadata={'validation_error': validation_result[1]}
            )

        # Evaluate rules in priority order
        matched_results = []
        for rule in self.rules:
            result = rule.evaluate(context)
            if result:
                matched_results.append(result)

                # DENY rules are final
                if result.decision == PolicyDecision.DENY:
                    logger.info(f"Policy DENY: {result.reasons}")
                    return result

        # If no results matched, default to ALLOW
        if not matched_results:
            return PolicyResult(
                decision=PolicyDecision.ALLOW,
                reasons=["No policies matched, default allow"],
                matched_policies=[],
                metadata={}
            )

        # Merge results based on priority
        # REQUIRE_APPROVAL > DRY_RUN_ONLY > ALLOW
        final_decision = PolicyDecision.ALLOW
        all_reasons = []
        all_policies = []
        all_metadata = {}

        for result in matched_results:
            all_reasons.extend(result.reasons)
            all_policies.extend(result.matched_policies)
            all_metadata.update(result.metadata)

            if result.decision == PolicyDecision.REQUIRE_APPROVAL:
                final_decision = PolicyDecision.REQUIRE_APPROVAL
            elif result.decision == PolicyDecision.DRY_RUN_ONLY and final_decision == PolicyDecision.ALLOW:
                final_decision = PolicyDecision.DRY_RUN_ONLY

        logger.info(f"Policy decision: {final_decision.value}, matched {len(all_policies)} policies")

        return PolicyResult(
            decision=final_decision,
            reasons=all_reasons,
            matched_policies=all_policies,
            metadata=all_metadata
        )

    def _validate_target(self, action: str, target: str) -> Tuple[bool, Optional[str]]:
        """Validate target based on action type"""
        if action == 'block_ip':
            return TargetValidator.validate_ip_target(target)
        elif action in ['suspend_user', 'flag_user']:
            return TargetValidator.validate_user_target(target)
        elif action == 'terminate_session':
            return TargetValidator.validate_session_target(target)
        elif action == 'isolate_agent':
            return TargetValidator.validate_agent_target(target)
        else:
            # Generic validation for other actions
            if not target or len(target) > 512:
                return False, "Target must be 1-512 characters"
            return True, None


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = PolicyEngine()

    # Test 1: Block reserved IP (should be denied)
    context = {
        'action': 'block_ip',
        'target': '127.0.0.1',
        'environment': 'production',
        'severity': 'critical',
        'created_by': 'analyst_john'
    }
    result = engine.evaluate(context)
    print(f"\nTest 1 - Block localhost: {result.decision.value}")
    print(f"Reasons: {result.reasons}")

    # Test 2: Block private IP (should require approval)
    context = {
        'action': 'block_ip',
        'target': '192.168.1.100',
        'environment': 'production',
        'severity': 'high',
        'created_by': 'analyst_john'
    }
    result = engine.evaluate(context)
    print(f"\nTest 2 - Block private IP: {result.decision.value}")
    print(f"Reasons: {result.reasons}")

    # Test 3: Block public IP in development (should allow)
    context = {
        'action': 'block_ip',
        'target': '8.8.8.8',
        'environment': 'development',
        'severity': 'medium',
        'created_by': 'analyst_john',
        'has_approval': True
    }
    result = engine.evaluate(context)
    print(f"\nTest 3 - Block public IP (dev): {result.decision.value}")
    print(f"Reasons: {result.reasons}")

    # Test 4: New playbook (should be dry-run only)
    context = {
        'action': 'block_ip',
        'target': '8.8.8.8',
        'environment': 'development',
        'severity': 'medium',
        'created_by': 'analyst_john',
        'is_new_playbook': True,
        'has_approval': False
    }
    result = engine.evaluate(context)
    print(f"\nTest 4 - New playbook: {result.decision.value}")
    print(f"Reasons: {result.reasons}")

    # Test 5: Invalid IP (should be denied)
    context = {
        'action': 'block_ip',
        'target': 'not_an_ip',
        'environment': 'production',
        'severity': 'critical',
        'created_by': 'analyst_john'
    }
    result = engine.evaluate(context)
    print(f"\nTest 5 - Invalid IP: {result.decision.value}")
    print(f"Reasons: {result.reasons}")
