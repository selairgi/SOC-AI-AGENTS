"""
Security configuration for SOC AI Agents.
Defines action whitelist, validation rules, and security policies.
"""

import re
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from enum import Enum


class ActionRiskLevel(Enum):
    """Risk levels for actions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ActionDefinition:
    """Definition of an allowed action."""
    name: str
    description: str
    risk_level: ActionRiskLevel
    requires_real_mode: bool
    parameter_validators: Dict[str, callable]
    example_usage: str


class SecurityConfig:
    """Security configuration and validation for SOC agents."""
    
    # High-risk actions that require REAL_MODE=True
    HIGH_RISK_ACTIONS = {
        "block_ip", "suspend_user", "isolate_agent", "iptables", 
        "terminate_session", "disable_account", "quarantine_system"
    }
    
    @staticmethod
    def _validate_ip_address(ip: str) -> bool:
        """Validate IP address format."""
        if not ip:
            return False
        
        # IPv4 validation
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ipv4_pattern, ip):
            return True
        
        # IPv6 validation (basic)
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if re.match(ipv6_pattern, ip):
            return True
        
        return False
    
    @staticmethod
    def _validate_user_id(user_id: str) -> bool:
        """Validate user ID format."""
        if not user_id:
            return False
        
        # Allow alphanumeric, underscore, hyphen, dot
        user_id_pattern = r'^[a-zA-Z0-9._-]+$'
        return bool(re.match(user_id_pattern, user_id)) and len(user_id) <= 100
    
    @staticmethod
    def _validate_agent_id(agent_id: str) -> bool:
        """Validate agent ID format."""
        if not agent_id:
            return False
        
        # Allow alphanumeric, underscore, hyphen, dot
        agent_id_pattern = r'^[a-zA-Z0-9._-]+$'
        return bool(re.match(agent_id_pattern, agent_id)) and len(agent_id) <= 100
    
    # Allowed actions whitelist
    ALLOWED_ACTIONS = {
        # Network actions
        "block_ip": ActionDefinition(
            name="block_ip",
            description="Block an IP address",
            risk_level=ActionRiskLevel.HIGH,
            requires_real_mode=True,
            parameter_validators={"target": _validate_ip_address.__func__},
            example_usage="block_ip:192.168.1.100"
        ),
        "rate_limit_ip": ActionDefinition(
            name="rate_limit_ip",
            description="Apply rate limiting to an IP address",
            risk_level=ActionRiskLevel.MEDIUM,
            requires_real_mode=True,
            parameter_validators={"target": _validate_ip_address.__func__},
            example_usage="rate_limit_ip:192.168.1.100"
        ),
        
        # User actions
        "suspend_user": ActionDefinition(
            name="suspend_user",
            description="Suspend a user account",
            risk_level=ActionRiskLevel.HIGH,
            requires_real_mode=True,
            parameter_validators={"target": _validate_user_id.__func__},
            example_usage="suspend_user:user123"
        ),
        "flag_user": ActionDefinition(
            name="flag_user",
            description="Flag a user for review",
            risk_level=ActionRiskLevel.MEDIUM,
            requires_real_mode=False,
            parameter_validators={"target": _validate_user_id.__func__},
            example_usage="flag_user:user123"
        ),
        "rate_limit_user": ActionDefinition(
            name="rate_limit_user",
            description="Apply rate limiting to a user",
            risk_level=ActionRiskLevel.MEDIUM,
            requires_real_mode=True,
            parameter_validators={"target": _validate_user_id.__func__},
            example_usage="rate_limit_user:user123"
        ),
        
        # Agent actions
        "isolate_agent": ActionDefinition(
            name="isolate_agent",
            description="Isolate an AI agent",
            risk_level=ActionRiskLevel.CRITICAL,
            requires_real_mode=True,
            parameter_validators={"target": _validate_agent_id.__func__},
            example_usage="isolate_agent:agent_123"
        ),
        
        # Investigation actions
        "initiate_forensics": ActionDefinition(
            name="initiate_forensics",
            description="Start forensic investigation",
            risk_level=ActionRiskLevel.MEDIUM,
            requires_real_mode=True,
            parameter_validators={},
            example_usage="initiate_forensics"
        ),
        "enable_enhanced_monitoring": ActionDefinition(
            name="enable_enhanced_monitoring",
            description="Enable enhanced monitoring",
            risk_level=ActionRiskLevel.LOW,
            requires_real_mode=True,
            parameter_validators={},
            example_usage="enable_enhanced_monitoring"
        ),
        
        # Notification actions
        "notify_compliance_team": ActionDefinition(
            name="notify_compliance_team",
            description="Notify compliance team",
            risk_level=ActionRiskLevel.LOW,
            requires_real_mode=False,
            parameter_validators={},
            example_usage="notify_compliance_team"
        ),
        "require_human_review": ActionDefinition(
            name="require_human_review",
            description="Require human review",
            risk_level=ActionRiskLevel.LOW,
            requires_real_mode=False,
            parameter_validators={},
            example_usage="require_human_review"
        ),
        
        # Multi-action support
        "multi_action": ActionDefinition(
            name="multi_action",
            description="Execute multiple actions",
            risk_level=ActionRiskLevel.MEDIUM,
            requires_real_mode=False,
            parameter_validators={},
            example_usage="multi_action:action1,action2"
        )
    }
    
    @classmethod
    def is_action_allowed(cls, action_name: str) -> bool:
        """Check if an action is in the whitelist."""
        return action_name in cls.ALLOWED_ACTIONS
    
    @classmethod
    def get_action_definition(cls, action_name: str) -> Optional[ActionDefinition]:
        """Get action definition if it exists."""
        return cls.ALLOWED_ACTIONS.get(action_name)
    
    @classmethod
    def is_high_risk_action(cls, action_name: str) -> bool:
        """Check if an action is high-risk and requires REAL_MODE."""
        action_def = cls.get_action_definition(action_name)
        return action_def and action_def.requires_real_mode
    
    @classmethod
    def validate_action_parameters(cls, action_name: str, parameters: Dict[str, str]) -> tuple[bool, List[str]]:
        """Validate action parameters.
        
        Returns:
            (is_valid, error_messages)
        """
        action_def = cls.get_action_definition(action_name)
        if not action_def:
            return False, [f"Unknown action: {action_name}"]
        
        errors = []
        
        for param_name, validator in action_def.parameter_validators.items():
            if param_name in parameters:
                if not validator(parameters[param_name]):
                    errors.append(f"Invalid {param_name}: {parameters[param_name]}")
            else:
                errors.append(f"Missing required parameter: {param_name}")
        
        return len(errors) == 0, errors
    
    @classmethod
    def get_actions_by_risk_level(cls, risk_level: ActionRiskLevel) -> List[str]:
        """Get all actions for a specific risk level."""
        return [
            name for name, definition in cls.ALLOWED_ACTIONS.items()
            if definition.risk_level == risk_level
        ]