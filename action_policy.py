"""
Action policy enforcement for SOC AI Agents.
Enforces parameter policies and requires approval for sensitive operations.
"""

import re
import time
import logging
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import json


class PolicyAction(Enum):
    """Actions that can be taken based on policy evaluation."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    ESCALATE = "escalate"


class ApprovalStatus(Enum):
    """Status of approval requests."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class PolicyRule:
    """A policy rule for action enforcement."""
    rule_id: str
    name: str
    description: str
    action_name: str
    conditions: Dict[str, Any]  # Conditions that must be met
    policy_action: PolicyAction
    approval_required: bool = False
    approval_ttl: int = 3600  # 1 hour default
    priority: int = 100  # Lower number = higher priority
    enabled: bool = True


@dataclass
class ApprovalRequest:
    """Request for approval of a sensitive action."""
    request_id: str
    action_name: str
    target: str
    playbook_id: str
    requester: str
    justification: str
    policy_rule_id: str
    created_time: float
    ttl: int
    status: ApprovalStatus = ApprovalStatus.PENDING
    approver: Optional[str] = None
    approved_time: Optional[float] = None
    rejection_reason: Optional[str] = None


@dataclass
class PolicyEvaluation:
    """Result of policy evaluation."""
    allowed: bool
    action: PolicyAction
    rule_id: Optional[str] = None
    message: str = ""
    approval_required: bool = False
    approval_request_id: Optional[str] = None


class ActionPolicyEngine:
    """Enforces action policies and manages approval workflows."""
    
    def __init__(self):
        self.logger = logging.getLogger("ActionPolicyEngine")
        self.rules: Dict[str, PolicyRule] = {}
        self.approval_requests: Dict[str, ApprovalRequest] = {}
        
        # Statistics
        self.stats = {
            "total_evaluations": 0,
            "allowed_actions": 0,
            "denied_actions": 0,
            "approval_required": 0,
            "approvals_granted": 0,
            "approvals_rejected": 0,
            "approvals_expired": 0
        }
        
        # Load default policies
        self._load_default_policies()
    
    def _load_default_policies(self):
        """Load default policy rules."""
        default_rules = [
            # IP blocking policies
            PolicyRule(
                rule_id="ip_block_private",
                name="Block Private IPs",
                description="Require approval for blocking private IP ranges",
                action_name="block_ip",
                conditions={
                    "ip_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                    "auto_approve": False
                },
                policy_action=PolicyAction.REQUIRE_APPROVAL,
                approval_required=True,
                priority=10
            ),
            PolicyRule(
                rule_id="ip_block_public",
                name="Block Public IPs",
                description="Allow blocking public IPs automatically",
                action_name="block_ip",
                conditions={
                    "ip_ranges": ["0.0.0.0/0"],
                    "exclude_private": True,
                    "auto_approve": True
                },
                policy_action=PolicyAction.ALLOW,
                priority=20
            ),
            
            # User suspension policies
            PolicyRule(
                rule_id="user_suspend_admin",
                name="Suspend Admin Users",
                description="Require approval for suspending admin users",
                action_name="suspend_user",
                conditions={
                    "user_patterns": [r"admin.*", r"root.*", r".*admin.*"],
                    "auto_approve": False
                },
                policy_action=PolicyAction.REQUIRE_APPROVAL,
                approval_required=True,
                priority=5
            ),
            PolicyRule(
                rule_id="user_suspend_regular",
                name="Suspend Regular Users",
                description="Allow suspending regular users automatically",
                action_name="suspend_user",
                conditions={
                    "user_patterns": [r"user.*", r"test.*"],
                    "auto_approve": True
                },
                policy_action=PolicyAction.ALLOW,
                priority=30
            ),
            
            # Agent isolation policies
            PolicyRule(
                rule_id="agent_isolate_critical",
                name="Isolate Critical Agents",
                description="Require approval for isolating critical agents",
                action_name="isolate_agent",
                conditions={
                    "agent_patterns": [r".*critical.*", r".*production.*", r".*main.*"],
                    "auto_approve": False
                },
                policy_action=PolicyAction.REQUIRE_APPROVAL,
                approval_required=True,
                priority=5
            ),
            PolicyRule(
                rule_id="agent_isolate_test",
                name="Isolate Test Agents",
                description="Allow isolating test agents automatically",
                action_name="isolate_agent",
                conditions={
                    "agent_patterns": [r".*test.*", r".*dev.*", r".*staging.*"],
                    "auto_approve": True
                },
                policy_action=PolicyAction.ALLOW,
                priority=40
            )
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
    
    def add_rule(self, rule: PolicyRule):
        """Add a policy rule."""
        self.rules[rule.rule_id] = rule
        self.logger.info(f"Added policy rule: {rule.name}")
    
    def remove_rule(self, rule_id: str):
        """Remove a policy rule."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            self.logger.info(f"Removed policy rule: {rule_id}")
    
    def evaluate_action(self, action_name: str, target: str, playbook_id: str, 
                       requester: str, context: Dict[str, Any] = None) -> PolicyEvaluation:
        """Evaluate an action against all applicable policies."""
        self.stats["total_evaluations"] += 1
        
        # Get applicable rules (sorted by priority)
        applicable_rules = [
            rule for rule in self.rules.values()
            if rule.enabled and rule.action_name == action_name
        ]
        applicable_rules.sort(key=lambda r: r.priority)
        
        for rule in applicable_rules:
            if self._matches_conditions(rule, target, context or {}):
                return self._apply_rule(rule, action_name, target, playbook_id, requester)
        
        # Default: allow if no rules match
        self.stats["allowed_actions"] += 1
        return PolicyEvaluation(
            allowed=True,
            action=PolicyAction.ALLOW,
            message="No applicable policy rules"
        )
    
    def _matches_conditions(self, rule: PolicyRule, target: str, context: Dict[str, Any]) -> bool:
        """Check if target matches rule conditions."""
        conditions = rule.conditions
        
        # Check IP range conditions
        if "ip_ranges" in conditions:
            if not self._is_ip_in_ranges(target, conditions["ip_ranges"]):
                return False
        
        # Check user pattern conditions
        if "user_patterns" in conditions:
            if not self._matches_patterns(target, conditions["user_patterns"]):
                return False
        
        # Check agent pattern conditions
        if "agent_patterns" in conditions:
            if not self._matches_patterns(target, conditions["agent_patterns"]):
                return False
        
        # Check exclude private condition
        if conditions.get("exclude_private", False):
            if self._is_private_ip(target):
                return False
        
        return True
    
    def _is_ip_in_ranges(self, ip: str, ranges: List[str]) -> bool:
        """Check if IP is in any of the specified ranges."""
        # Simple implementation - in production, use ipaddress module
        for ip_range in ranges:
            if "/" in ip_range:
                # CIDR notation (simplified)
                network, prefix_len = ip_range.split("/")
                prefix_len = int(prefix_len)
                if self._ip_in_cidr(ip, network, prefix_len):
                    return True
            else:
                # Exact match
                if ip == ip_range:
                    return True
        return False
    
    def _ip_in_cidr(self, ip: str, network: str, prefix_len: int) -> bool:
        """Check if IP is in CIDR range (simplified implementation)."""
        # This is a simplified implementation
        # In production, use the ipaddress module
        return True  # Placeholder
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range."""
        private_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        return self._is_ip_in_ranges(ip, private_ranges)
    
    def _matches_patterns(self, target: str, patterns: List[str]) -> bool:
        """Check if target matches any of the patterns."""
        for pattern in patterns:
            if re.search(pattern, target, re.IGNORECASE):
                return True
        return False
    
    def _apply_rule(self, rule: PolicyRule, action_name: str, target: str, 
                   playbook_id: str, requester: str) -> PolicyEvaluation:
        """Apply a policy rule and return evaluation result."""
        if rule.policy_action == PolicyAction.ALLOW:
            self.stats["allowed_actions"] += 1
            return PolicyEvaluation(
                allowed=True,
                action=PolicyAction.ALLOW,
                rule_id=rule.rule_id,
                message=f"Action allowed by rule: {rule.name}"
            )
        
        elif rule.policy_action == PolicyAction.DENY:
            self.stats["denied_actions"] += 1
            return PolicyEvaluation(
                allowed=False,
                action=PolicyAction.DENY,
                rule_id=rule.rule_id,
                message=f"Action denied by rule: {rule.name}"
            )
        
        elif rule.policy_action == PolicyAction.REQUIRE_APPROVAL:
            if rule.approval_required:
                approval_request_id = self._create_approval_request(
                    action_name, target, playbook_id, requester, rule
                )
                self.stats["approval_required"] += 1
                return PolicyEvaluation(
                    allowed=False,
                    action=PolicyAction.REQUIRE_APPROVAL,
                    rule_id=rule.rule_id,
                    message=f"Approval required by rule: {rule.name}",
                    approval_required=True,
                    approval_request_id=approval_request_id
                )
            else:
                # Auto-approve
                self.stats["allowed_actions"] += 1
                return PolicyEvaluation(
                    allowed=True,
                    action=PolicyAction.ALLOW,
                    rule_id=rule.rule_id,
                    message=f"Action auto-approved by rule: {rule.name}"
                )
        
        else:  # ESCALATE
            self.stats["approval_required"] += 1
            return PolicyEvaluation(
                allowed=False,
                action=PolicyAction.ESCALATE,
                rule_id=rule.rule_id,
                message=f"Action escalated by rule: {rule.name}",
                approval_required=True
            )
    
    def _create_approval_request(self, action_name: str, target: str, playbook_id: str,
                               requester: str, rule: PolicyRule) -> str:
        """Create an approval request."""
        request_id = f"approval_{int(time.time() * 1000)}_{hash(target) % 10000}"
        
        approval_request = ApprovalRequest(
            request_id=request_id,
            action_name=action_name,
            target=target,
            playbook_id=playbook_id,
            requester=requester,
            justification=f"Policy rule: {rule.name}",
            policy_rule_id=rule.rule_id,
            created_time=time.time(),
            ttl=rule.approval_ttl
        )
        
        self.approval_requests[request_id] = approval_request
        self.logger.info(f"Created approval request: {request_id} for {action_name}:{target}")
        return request_id
    
    def approve_action(self, request_id: str, approver: str) -> bool:
        """Approve a pending action."""
        if request_id not in self.approval_requests:
            return False
        
        request = self.approval_requests[request_id]
        if request.status != ApprovalStatus.PENDING:
            return False
        
        # Check if expired
        if time.time() - request.created_time > request.ttl:
            request.status = ApprovalStatus.EXPIRED
            self.stats["approvals_expired"] += 1
            return False
        
        request.status = ApprovalStatus.APPROVED
        request.approver = approver
        request.approved_time = time.time()
        
        self.stats["approvals_granted"] += 1
        self.logger.info(f"Approved action: {request_id} by {approver}")
        return True
    
    def reject_action(self, request_id: str, approver: str, reason: str) -> bool:
        """Reject a pending action."""
        if request_id not in self.approval_requests:
            return False
        
        request = self.approval_requests[request_id]
        if request.status != ApprovalStatus.PENDING:
            return False
        
        request.status = ApprovalStatus.REJECTED
        request.approver = approver
        request.rejection_reason = reason
        
        self.stats["approvals_rejected"] += 1
        self.logger.info(f"Rejected action: {request_id} by {approver}, reason: {reason}")
        return True
    
    def get_pending_approvals(self) -> List[ApprovalRequest]:
        """Get all pending approval requests."""
        return [
            request for request in self.approval_requests.values()
            if request.status == ApprovalStatus.PENDING
        ]
    
    def get_approval_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get a specific approval request."""
        return self.approval_requests.get(request_id)
    
    def cleanup_expired_approvals(self):
        """Remove expired approval requests."""
        current_time = time.time()
        expired_requests = [
            request_id for request_id, request in self.approval_requests.items()
            if (request.status == ApprovalStatus.PENDING and 
                current_time - request.created_time > request.ttl)
        ]
        
        for request_id in expired_requests:
            request = self.approval_requests[request_id]
            request.status = ApprovalStatus.EXPIRED
            self.stats["approvals_expired"] += 1
            self.logger.info(f"Approval request expired: {request_id}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get policy engine statistics."""
        return {
            **self.stats,
            "total_rules": len(self.rules),
            "pending_approvals": len(self.get_pending_approvals()),
            "approval_rate": (
                self.stats["approvals_granted"] / 
                max(self.stats["approval_required"], 1)
            ) * 100
        }
    
    def export_policies(self) -> List[Dict[str, Any]]:
        """Export all policies as JSON-serializable format."""
        return [
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "action_name": rule.action_name,
                "conditions": rule.conditions,
                "policy_action": rule.policy_action.value,
                "approval_required": rule.approval_required,
                "approval_ttl": rule.approval_ttl,
                "priority": rule.priority,
                "enabled": rule.enabled
            }
            for rule in self.rules.values()
        ]
