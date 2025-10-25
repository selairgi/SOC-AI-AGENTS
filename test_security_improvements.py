"""
Comprehensive tests for SOC AI Agents security improvements.
Tests structured actions, action whitelist, dry-run gating, schema validation, and input sanitization.
"""

import asyncio
import json
import logging
import time
from typing import Dict, Any

from models import Alert, Playbook, ThreatType
from remediator import Remediator
from soc_analyst import SOCAnalyst
from schema_validator import SchemaValidator
from security_config import SecurityConfig, ActionRiskLevel
from message_bus import MessageBus
from config import REAL_MODE, DRY_RUN, ENABLE_SCHEMA_VALIDATION, ENABLE_ACTION_WHITELIST, ENABLE_INPUT_SANITIZATION


class TestSecurityImprovements:
    """Test suite for security improvements."""
    
    def __init__(self):
        self.logger = logging.getLogger("TestSecurityImprovements")
        self.setup_logging()
        
        # Test components
        self.bus = MessageBus()
        self.remediator_queue = asyncio.Queue()
        self.remediator = Remediator()
        self.analyst = SOCAnalyst(self.bus, self.remediator_queue)
        self.schema_validator = SchemaValidator()
        self.security_config = SecurityConfig()
    
    def setup_logging(self):
        """Setup logging for tests."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def test_structured_actions(self):
        """Test structured actions with metadata["actions"] and legacy support."""
        self.logger.info("=== Testing Structured Actions ===")
        
        # Test 1: New structured actions format
        playbook_new = Playbook(
            action="multi_action",
            target="",  # Legacy field empty
            justification="Test structured actions",
            owner="test",
            metadata={
                "actions": ["block_ip:192.168.1.100", "suspend_user:user123", "initiate_forensics"]
            }
        )
        
        actions_new = playbook_new.get_actions()
        assert len(actions_new) == 3
        assert "block_ip:192.168.1.100" in actions_new
        assert "suspend_user:user123" in actions_new
        assert "initiate_forensics" in actions_new
        self.logger.info("✓ New structured actions format works")
        
        # Test 2: Legacy target format (fallback)
        playbook_legacy = Playbook(
            action="multi_action",
            target="block_ip:192.168.1.100,suspend_user:user123",
            justification="Test legacy format",
            owner="test"
        )
        
        actions_legacy = playbook_legacy.get_actions()
        assert len(actions_legacy) == 2
        assert "block_ip:192.168.1.100" in actions_legacy
        assert "suspend_user:user123" in actions_legacy
        self.logger.info("✓ Legacy target format fallback works")
        
        # Test 3: Set actions method
        playbook_test = Playbook(
            action="test",
            target="",
            justification="Test set actions",
            owner="test"
        )
        
        playbook_test.set_actions(["action1", "action2"])
        assert playbook_test.get_actions() == ["action1", "action2"]
        self.logger.info("✓ Set actions method works")
        
        self.logger.info("✅ Structured actions tests passed")
    
    def test_action_whitelist_validation(self):
        """Test action whitelist and parameter validation."""
        self.logger.info("=== Testing Action Whitelist ===")
        
        # Test 1: Valid actions
        valid_actions = ["block_ip", "suspend_user", "isolate_agent", "initiate_forensics"]
        for action in valid_actions:
            assert self.security_config.is_action_allowed(action), f"Action {action} should be allowed"
        self.logger.info("✓ Valid actions are whitelisted")
        
        # Test 2: Invalid actions
        invalid_actions = ["unknown_action", "malicious_command", "rm -rf /"]
        for action in invalid_actions:
            assert not self.security_config.is_action_allowed(action), f"Action {action} should be blocked"
        self.logger.info("✓ Invalid actions are blocked")
        
        # Test 3: Parameter validation
        # Valid IP
        is_valid, errors = self.security_config.validate_action_parameters("block_ip", {"target": "192.168.1.100"})
        assert is_valid, f"Valid IP should pass: {errors}"
        
        # Invalid IP
        is_valid, errors = self.security_config.validate_action_parameters("block_ip", {"target": "invalid_ip"})
        assert not is_valid, "Invalid IP should fail"
        
        # Valid user ID
        is_valid, errors = self.security_config.validate_action_parameters("suspend_user", {"target": "user123"})
        assert is_valid, f"Valid user ID should pass: {errors}"
        
        # Invalid user ID (with dangerous characters)
        is_valid, errors = self.security_config.validate_action_parameters("suspend_user", {"target": "user;rm -rf /"})
        assert not is_valid, "Invalid user ID should fail"
        
        self.logger.info("✅ Action whitelist tests passed")
    
    def test_dry_run_gating(self):
        """Test dry-run gating for high-risk actions."""
        self.logger.info("=== Testing Dry-Run Gating ===")
        
        # Test high-risk actions
        high_risk_actions = ["block_ip", "suspend_user", "isolate_agent"]
        for action in high_risk_actions:
            assert self.security_config.is_high_risk_action(action), f"Action {action} should be high-risk"
        
        # Test low-risk actions (actions that don't require real mode)
        low_risk_actions = ["notify_compliance_team", "require_human_review"]
        for action in low_risk_actions:
            assert not self.security_config.is_high_risk_action(action), f"Action {action} should not be high-risk"
        
        self.logger.info("✅ Dry-run gating tests passed")
    
    def test_schema_validation(self):
        """Test JSON schema validation for alerts and playbooks."""
        self.logger.info("=== Testing Schema Validation ===")
        
        # Test 1: Valid alert
        valid_alert = {
            "id": "alert_123",
            "timestamp": time.time(),
            "severity": "high",
            "title": "Test Alert",
            "description": "Test alert description",
            "threat_type": "prompt_injection",
            "agent_id": "agent_123",
            "rule_id": "rule_123",
            "evidence": {"confidence": 0.8},
            "correlated": False,
            "false_positive_probability": 0.1
        }
        
        result = self.schema_validator.validate_alert(valid_alert)
        assert result.is_valid, f"Valid alert should pass: {result.errors}"
        self.logger.info("✓ Valid alert passes validation")
        
        # Test 2: Invalid alert (missing required fields)
        invalid_alert = {
            "id": "alert_123",
            "severity": "high"
            # Missing required fields
        }
        
        result = self.schema_validator.validate_alert(invalid_alert)
        assert not result.is_valid, "Invalid alert should fail validation"
        self.logger.info("✓ Invalid alert fails validation")
        
        # Test 3: Valid playbook
        valid_playbook = {
            "action": "block_ip",
            "target": "192.168.1.100",
            "justification": "Test playbook",
            "owner": "test_user",
            "threat_type": "prompt_injection",
            "agent_id": "agent_123",
            "metadata": {
                "actions": ["block_ip:192.168.1.100"],
                "alert_id": "alert_123"
            }
        }
        
        result = self.schema_validator.validate_playbook(valid_playbook)
        assert result.is_valid, f"Valid playbook should pass: {result.errors}"
        self.logger.info("✓ Valid playbook passes validation")
        
        # Test 4: Invalid playbook (invalid action)
        invalid_playbook = {
            "action": "",  # Empty action
            "target": "192.168.1.100",
            "justification": "Test playbook",
            "owner": "test_user"
        }
        
        result = self.schema_validator.validate_playbook(invalid_playbook)
        assert not result.is_valid, "Invalid playbook should fail validation"
        self.logger.info("✓ Invalid playbook fails validation")
        
        self.logger.info("✅ Schema validation tests passed")
    
    def test_input_sanitization(self):
        """Test input sanitization to prevent shell injection."""
        self.logger.info("=== Testing Input Sanitization ===")
        
        # Test dangerous inputs
        dangerous_inputs = [
            "192.168.1.100; rm -rf /",
            "user123 & cat /etc/passwd",
            "agent_456 | nc -l 8080",
            "target`whoami`",
            "input$(id)",
            "test<file.txt",
            "data>output.txt",
            "cmd\"injection\"",
            "test'quotes'",
            "path\\with\\backslashes"
        ]
        
        for dangerous_input in dangerous_inputs:
            sanitized = self.remediator._sanitize_input(dangerous_input)
            
            # Check that dangerous characters are removed
            dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\']
            for char in dangerous_chars:
                assert char not in sanitized, f"Dangerous character '{char}' should be removed from '{dangerous_input}'"
            
            # Check length limit
            assert len(sanitized) <= 1000, f"Sanitized input should be limited to 1000 characters"
        
        self.logger.info("✓ Dangerous characters are sanitized")
        
        # Test normal inputs (should pass through mostly unchanged)
        normal_inputs = [
            "192.168.1.100",
            "user123",
            "agent_456",
            "normal_text"
        ]
        
        for normal_input in normal_inputs:
            sanitized = self.remediator._sanitize_input(normal_input)
            assert sanitized == normal_input, f"Normal input should pass through unchanged: '{normal_input}' -> '{sanitized}'"
        
        self.logger.info("✓ Normal inputs pass through unchanged")
        self.logger.info("✅ Input sanitization tests passed")
    
    async def test_integration_scenario(self):
        """Test complete integration scenario with all security features."""
        self.logger.info("=== Testing Integration Scenario ===")
        
        # Create a test alert
        alert = Alert(
            id="test_alert_123",
            timestamp=time.time(),
            severity="high",
            title="Test Prompt Injection",
            description="Test prompt injection attempt detected",
            threat_type=ThreatType.PROMPT_INJECTION,
            agent_id="test_agent",
            rule_id="prompt_injection_rule",
            evidence={
                "log": {
                    "src_ip": "192.168.1.100",
                    "user_id": "user123",
                    "confidence": 0.9
                }
            }
        )
        
        # Test alert processing with schema validation
        try:
            playbook = self.analyst.analyze_alert(alert)
            assert playbook is not None, "Playbook should be created"
            
            # Check structured actions
            actions = playbook.get_actions()
            assert len(actions) > 0, "Actions should be present"
            self.logger.info(f"✓ Created playbook with {len(actions)} actions: {actions}")
            
            # Test action validation
            for action_str in actions:
                action_name, parameters = self.remediator._parse_action_string(action_str)
                
                # Validate action
                is_valid, errors = self.remediator._validate_action(action_name, parameters)
                if not is_valid:
                    self.logger.warning(f"Action validation failed for '{action_str}': {errors}")
                else:
                    self.logger.info(f"✓ Action '{action_str}' passed validation")
            
            # Test dry-run restrictions
            for action_str in actions:
                action_name, _ = self.remediator._parse_action_string(action_str)
                can_execute = self.remediator._check_dry_run_restrictions(action_name)
                if not can_execute:
                    self.logger.info(f"✓ Action '{action_str}' blocked in dry-run mode")
                else:
                    self.logger.info(f"✓ Action '{action_str}' allowed in dry-run mode")
            
        except Exception as e:
            self.logger.error(f"Integration test failed: {e}")
            raise
        
        self.logger.info("✅ Integration scenario test passed")
    
    def test_unknown_action_rejection(self):
        """Test that unknown actions are rejected and logged."""
        self.logger.info("=== Testing Unknown Action Rejection ===")
        
        # Create playbook with unknown action
        playbook = Playbook(
            action="multi_action",
            target="",
            justification="Test unknown action",
            owner="test",
            metadata={
                "actions": ["unknown_action:target", "malicious_command", "block_ip:192.168.1.100"]
            }
        )
        
        actions = playbook.get_actions()
        
        # Test each action
        for action_str in actions:
            action_name, parameters = self.remediator._parse_action_string(action_str)
            is_valid, errors = self.remediator._validate_action(action_name, parameters)
            
            if action_name in ["unknown_action", "malicious_command"]:
                assert not is_valid, f"Unknown action '{action_name}' should be rejected"
                self.logger.info(f"✓ Unknown action '{action_name}' correctly rejected: {errors}")
            else:
                assert is_valid, f"Known action '{action_name}' should be allowed"
                self.logger.info(f"✓ Known action '{action_name}' correctly allowed")
        
        self.logger.info("✅ Unknown action rejection test passed")
    
    async def run_all_tests(self):
        """Run all security improvement tests."""
        self.logger.info("🚀 Starting Security Improvements Test Suite")
        
        try:
            # Run individual test suites
            self.test_structured_actions()
            self.test_action_whitelist_validation()
            self.test_dry_run_gating()
            self.test_schema_validation()
            self.test_input_sanitization()
            await self.test_integration_scenario()
            self.test_unknown_action_rejection()
            
            self.logger.info("🎉 All security improvement tests passed!")
            
        except Exception as e:
            self.logger.error(f"❌ Test suite failed: {e}")
            raise


async def main():
    """Main test runner."""
    test_suite = TestSecurityImprovements()
    await test_suite.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
