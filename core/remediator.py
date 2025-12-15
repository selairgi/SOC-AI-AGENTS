"""
Remediator agent - executes remediation actions based on playbooks.
"""

import asyncio
import subprocess
import logging
import re
from typing import List, Dict, Any, Optional
import ipaddress
import os

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import REAL_MODE, DRY_RUN, ENABLE_ACTION_WHITELIST, ENABLE_INPUT_SANITIZATION
from shared.models import Alert, Playbook
from security.security_config import SecurityConfig, ActionRiskLevel
from shared.execution_tracker import ExecutionTracker
from shared.retry_circuit_breaker import RetryCircuitBreaker, RetryConfig, CircuitBreakerConfig
from shared.bounded_queue import BoundedQueue, QueueConfig, QueueStrategy
from enterprise.action_policy import ActionPolicyEngine
from shared.agent_memory import AgentMemory


class Remediator:
    """Consume playbooks and execute remediation. Support dry-run and real mode.
    This component must be highly guarded & authenticated in production.
    """
    
    def __init__(self, queue_config: QueueConfig = None, memory: Optional[AgentMemory] = None):
        self._stopped = False
        self.logger = logging.getLogger("Remediator")
        self.security_config = SecurityConfig()
        
        # Initialize memory system
        self.memory = memory or AgentMemory()
        
        # Initialize new systems
        self.execution_tracker = ExecutionTracker()
        self.retry_circuit_breaker = RetryCircuitBreaker(
            retry_config=RetryConfig(max_attempts=3, base_delay=1.0),
            circuit_config=CircuitBreakerConfig(failure_threshold=5, recovery_timeout=60)
        )
        self.action_policy_engine = ActionPolicyEngine()
        
        # Initialize bounded queue
        queue_config = queue_config or QueueConfig(
            max_size=1000,
            strategy=QueueStrategy.BLOCK,
            timeout=30.0
        )
        self.action_queue = BoundedQueue(queue_config, "remediator_actions")
        
        # Lab/test environment detection
        self.lab_test_ips = {
            "127.0.0.1", "localhost", "::1", "0.0.0.0",
            "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"  # Private IP ranges
        }
        self.is_lab_environment = self._detect_lab_environment()
        
        # Legacy stats (kept for compatibility)
        self._execution_stats = {
            "actions_executed": 0,
            "actions_blocked": 0,
            "validation_errors": 0,
            "dry_run_skipped": 0,
            "lab_test_prevented": 0
        }
    
    def _detect_lab_environment(self) -> bool:
        """Detect if we're running in a lab/test environment"""
        # Check environment variables
        if os.getenv("ENVIRONMENT") in ["test", "development", "lab", "staging"]:
            return True
        if os.getenv("TEST_MODE") == "true":
            return True
        if os.getenv("LAB_MODE") == "true":
            return True
        
        # Check if running in Docker (common in test environments)
        if os.path.exists("/.dockerenv"):
            return True
        
        # Check hostname patterns
        import socket
        hostname = socket.gethostname().lower()
        if any(keyword in hostname for keyword in ["test", "dev", "lab", "staging", "local"]):
            return True
        
        return False
    
    def _is_lab_test_ip(self, ip: str) -> bool:
        """Check if an IP address is a lab/test IP (should not be blocked)"""
        if not ip:
            return False
        
        ip_lower = ip.lower().strip()
        
        # Direct matches
        if ip_lower in ["127.0.0.1", "localhost", "::1", "0.0.0.0"]:
            return True
        
        # Check private IP ranges
        try:
            ip_obj = ipaddress.ip_address(ip_lower)
            
            # Private IP ranges
            if ip_obj.is_private:
                return True
            
            # Loopback
            if ip_obj.is_loopback:
                return True
            
            # Link-local
            if ip_obj.is_link_local:
                return True
            
        except ValueError:
            # Invalid IP format
            pass
        
        return False
    
    def _sanitize_input(self, input_str: str) -> str:
        """Sanitize input to prevent shell injection."""
        if not ENABLE_INPUT_SANITIZATION:
            return input_str
        
        if not isinstance(input_str, str):
            return str(input_str)
        
        # Remove or escape dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\', '\n', '\r']
        sanitized = input_str
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Limit length
        return sanitized[:1000]
    
    def _validate_action(self, action_name: str, parameters: Dict[str, str]) -> tuple[bool, List[str]]:
        """Validate action name and parameters."""
        if not ENABLE_ACTION_WHITELIST:
            return True, []
        
        # Check if action is whitelisted
        if not self.security_config.is_action_allowed(action_name):
            self._execution_stats["validation_errors"] += 1
            return False, [f"Action '{action_name}' is not in the whitelist"]
        
        # Validate parameters
        is_valid, errors = self.security_config.validate_action_parameters(action_name, parameters)
        if not is_valid:
            self._execution_stats["validation_errors"] += 1
        
        return is_valid, errors
    
    def _check_dry_run_restrictions(self, action_name: str) -> bool:
        """Check if action should be blocked in dry-run mode."""
        if not DRY_RUN:
            return True  # Allow in real mode
        
        # Block high-risk actions in dry-run
        if self.security_config.is_high_risk_action(action_name):
            self._execution_stats["dry_run_skipped"] += 1
            self.logger.warning(f"[DRY-RUN] Blocked high-risk action '{action_name}' - requires REAL_MODE=True")
            return False
        
        return True
    
    def _parse_action_string(self, action_str: str) -> tuple[str, Dict[str, str]]:
        """Parse action string into action name and parameters."""
        if ":" in action_str:
            action_name, target = action_str.split(":", 1)
            parameters = {"target": self._sanitize_input(target)}
        else:
            action_name = action_str
            parameters = {}
        
        return action_name.strip(), parameters

    async def block_ip_iptables(self, ip: str) -> bool:
        """Example of a poster-child local remediation using iptables. Requires root.
        In production prefer orchestrating network devices (firewalls, WAF, cloud security groups) via their APIs.
        """
        if not REAL_MODE:
            self.logger.info(f"[DRY-RUN] Would block IP {ip} using iptables (skipped)")
            return True
        try:
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            # Use async subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self.logger.warning(f"iptables rule added for {ip} - IP BLOCKED")
                return True
            else:
                self.logger.error(f"iptables failed for {ip}: {stderr.decode()}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to block ip {ip}: {e}")
            return False

    async def block_ip_cloud_provider(self, ip: str) -> bool:
        # Placeholder: implement AWS/GCP/Azure SDK calls here
        self.logger.info(f"[DRY-RUN] Would call cloud provider API to block {ip}")
        return True

    async def handle_playbook(self, playbook: Playbook, alert: Alert):
        self.logger.info(f"Handling playbook {playbook.action} target {playbook.target} for alert {alert.id}")
        
        # Get structured actions from metadata, fallback to legacy target parsing
        actions = playbook.get_actions()
        
        if not actions:
            self.logger.warning(f"No actions found in playbook for alert {alert.id}")
            return
        
        # Start playbook execution tracking
        playbook_id = self.execution_tracker.start_playbook_execution(
            alert.id, playbook.action, actions
        )
        
        # Execute each action with idempotency and policy checks
        for action_str in actions:
            await self._execute_action_with_tracking(action_str, playbook, alert, playbook_id)
    
    async def _execute_action_with_tracking(self, action_str: str, playbook: Playbook, alert: Alert, playbook_id: str):
        """Execute action with full tracking, idempotency, and policy enforcement."""
        try:
            # Parse action string
            action_name, parameters = self._parse_action_string(action_str)
            target = parameters.get("target", "")
            
            # Check idempotency
            is_executed, existing_record = self.execution_tracker.is_action_executed(
                action_name, target, playbook_id
            )
            
            if is_executed:
                self.logger.info(f"Action already executed: {action_str} (skipping)")
                self.execution_tracker.record_action_execution(
                    action_name, target, playbook_id, "skipped", 
                    result="Already executed", error=None
                )
                self.execution_tracker.update_playbook_execution(playbook_id, existing_record.action_id, "executed")
                return
            
            # Check policy enforcement
            policy_evaluation = self.action_policy_engine.evaluate_action(
                action_name, target, playbook_id, playbook.owner, 
                context={"alert_id": alert.id, "threat_type": alert.threat_type.value}
            )
            
            if not policy_evaluation.allowed:
                if policy_evaluation.action.value == "require_approval":
                    self.logger.warning(f"Action requires approval: {action_str}")
                    self.execution_tracker.record_action_execution(
                        action_name, target, playbook_id, "pending_approval",
                        result=None, error=f"Requires approval: {policy_evaluation.message}"
                    )
                    return
                else:
                    self.logger.error(f"Action denied by policy: {action_str} - {policy_evaluation.message}")
                    self.execution_tracker.record_action_execution(
                        action_name, target, playbook_id, "denied",
                        result=None, error=f"Policy denied: {policy_evaluation.message}"
                    )
                    self.execution_tracker.update_playbook_execution(playbook_id, f"{action_name}:{target}", "failed")
                    return
            
            # Execute with retry and circuit breaker
            success, result, error = await self.retry_circuit_breaker.execute_with_retry(
                action_name, target, self._execute_action_async, action_str, playbook, alert
            )
            
            # Record execution result
            status = "executed" if success else "failed"
            execution_id = self.execution_tracker.record_action_execution(
                action_name, target, playbook_id, status, result, error
            )
            
            # Update playbook execution
            self.execution_tracker.update_playbook_execution(playbook_id, execution_id, status)
            
            if success:
                self._execution_stats["actions_executed"] += 1
                self.logger.info(f"Successfully executed action: {action_str}")
            else:
                self._execution_stats["actions_blocked"] += 1
                self.logger.error(f"Failed to execute action: {action_str} - {error}")
                
        except Exception as e:
            self.logger.error(f"Error executing action '{action_str}': {e}")
            self._execution_stats["actions_blocked"] += 1
    
    async def _execute_action_async(self, action_str: str, playbook: Playbook, alert: Alert):
        """Async wrapper for action execution."""
        return await self._execute_action(action_str, playbook, alert)
    
    async def _execute_action(self, action_str: str, playbook: Playbook, alert: Alert):
        """Execute a single action with validation and security checks."""
        try:
            # Parse action string
            action_name, parameters = self._parse_action_string(action_str)
            
            # Validate action
            is_valid, errors = self._validate_action(action_name, parameters)
            if not is_valid:
                self._execution_stats["actions_blocked"] += 1
                for error in errors:
                    self.logger.error(f"Action validation failed: {error}")
                return
            
            # Check dry-run restrictions
            if not self._check_dry_run_restrictions(action_name):
                return
            
            # Execute the action
            await self._dispatch_action(action_name, parameters, playbook, alert)
            self._execution_stats["actions_executed"] += 1
            
        except Exception as e:
            self.logger.error(f"Error executing action '{action_str}': {e}")
            self._execution_stats["actions_blocked"] += 1
    
    async def _dispatch_action(self, action_name: str, parameters: Dict[str, str], playbook: Playbook, alert: Alert):
        """Dispatch action to appropriate handler."""
        if action_name == "block_ip":
            await self._handle_block_ip(parameters.get("target", ""), playbook, alert)
        elif action_name == "suspend_user":
            await self._handle_suspend_user(parameters.get("target", ""), playbook, alert)
        elif action_name == "isolate_agent":
            await self._handle_isolate_agent(parameters.get("target", ""), playbook, alert)
        elif action_name == "rate_limit_ip":
            await self._handle_rate_limit_ip(parameters.get("target", ""), playbook, alert)
        elif action_name == "rate_limit_user":
            await self._handle_rate_limit_user(parameters.get("target", ""), playbook, alert)
        elif action_name == "flag_user":
            await self._handle_flag_user(parameters.get("target", ""), playbook, alert)
        elif action_name == "initiate_forensics":
            await self._handle_initiate_forensics(playbook, alert)
        elif action_name == "enable_enhanced_monitoring":
            await self._handle_enhanced_monitoring(playbook, alert)
        elif action_name == "notify_compliance_team":
            await self._handle_compliance_notification(playbook, alert)
        elif action_name == "require_human_review":
            await self._handle_human_review(playbook, alert)
        else:
            self.logger.warning(f"Unknown action {action_name}")
    
    async def _handle_block_ip(self, target: str, playbook: Playbook, alert: Alert):
        """Handle IP blocking. 
        Note: Contextual decisions (lab vs prod) should be made by SOC Analyst. 
        Remediator executes what is given, but maintains a hard safety guardrail for localhost.
        """
        ip = self._sanitize_input(target)
        
        # Hard Safety Check: Never block localhost/127.0.0.1 regardless of playbook
        # This is an invariant of the Remediator execution engine
        if ip in ["127.0.0.1", "localhost", "::1"]:
             self._execution_stats["lab_test_prevented"] += 1
             self.logger.warning(f"SAFETY GUARDRAIL: Prevented blocking localhost {ip} despite playbook instruction.")
             return

        # Proceed with blocking as instructed by Analyst
        ok = await self.block_ip_cloud_provider(ip)
        if not ok:
            ok = await self.block_ip_iptables(ip)
        
        if ok:
            self.logger.warning(f"Successfully blocked IP {ip} per playbook instruction.")
            
            # Store successful remediation
            self.memory.store_remediation_decision(
                alert_id=alert.id,
                action="block_ip",
                target=ip,
                is_lab_test=False, # Remediator assumes it's real if it got here, mostly
                was_blocked=True,
                certainty_score=playbook.metadata.get("certainty_score", 1.0),
                metadata={
                    "playbook_id": playbook.action,
                    "method": "cloud_provider" if ok else "iptables"
                }
            )
        else:
            self.logger.error(f"Failed to block IP {ip} (alert {alert.id})")
    
    async def _handle_suspend_user(self, target: str, playbook: Playbook, alert: Alert):
        """Handle user suspension."""
        user_id = self._sanitize_input(target)
        if not REAL_MODE:
            self.logger.info(f"[DRY-RUN] Would suspend user {user_id} (skipped)")
            return True
        try:
            # In a real implementation, you'd integrate with your user management system
            self.logger.warning(f"User {user_id} suspended for alert {alert.id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to suspend user {user_id}: {e}")
            return False
    
    async def _handle_isolate_agent(self, target: str, playbook: Playbook, alert: Alert):
        """Handle agent isolation."""
        agent_id = self._sanitize_input(target)
        if not REAL_MODE:
            self.logger.info(f"[DRY-RUN] Would isolate agent {agent_id} (skipped)")
            return True
        try:
            # In a real implementation, you'd stop/isolate the agent
            self.logger.warning(f"Agent {agent_id} isolated for alert {alert.id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to isolate agent {agent_id}: {e}")
            return False
    
    async def _handle_rate_limit_ip(self, target: str, playbook: Playbook, alert: Alert):
        """Handle IP rate limiting."""
        ip = self._sanitize_input(target)
        if not REAL_MODE:
            self.logger.info(f"[DRY-RUN] Would rate limit IP {ip} (skipped)")
            return True
        try:
            # In a real implementation, you'd configure rate limiting
            self.logger.warning(f"IP {ip} rate limited for alert {alert.id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to rate limit IP {ip}: {e}")
            return False
    
    async def _handle_rate_limit_user(self, target: str, playbook: Playbook, alert: Alert):
        """Handle user rate limiting."""
        user_id = self._sanitize_input(target)
        if not REAL_MODE:
            self.logger.info(f"[DRY-RUN] Would rate limit user {user_id} (skipped)")
            return True
        try:
            # In a real implementation, you'd configure user rate limiting
            self.logger.warning(f"User {user_id} rate limited for alert {alert.id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to rate limit user {user_id}: {e}")
            return False
    
    async def _handle_flag_user(self, target: str, playbook: Playbook, alert: Alert):
        """Handle user flagging."""
        user_id = self._sanitize_input(target)
        if not REAL_MODE:
            self.logger.info(f"[DRY-RUN] Would flag user {user_id} (skipped)")
            return True
        try:
            # In a real implementation, you'd flag the user in your system
            self.logger.warning(f"User {user_id} flagged for alert {alert.id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to flag user {user_id}: {e}")
            return False
    
    async def _handle_initiate_forensics(self, playbook: Playbook, alert: Alert):
        """Handle forensic investigation initiation."""
        if not REAL_MODE:
            self.logger.info(f"[DRY-RUN] Would initiate forensics for alert {alert.id} (skipped)")
            return True
        try:
            # In a real implementation, you'd start forensic data collection
            self.logger.warning(f"Forensics initiated for alert {alert.id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initiate forensics for alert {alert.id}: {e}")
            return False
    
    async def _handle_enhanced_monitoring(self, playbook: Playbook, alert: Alert):
        """Handle enhanced monitoring activation."""
        if not REAL_MODE:
            self.logger.info(f"[DRY-RUN] Would enable enhanced monitoring for alert {alert.id} (skipped)")
            return True
        try:
            # In a real implementation, you'd increase monitoring levels
            self.logger.warning(f"Enhanced monitoring enabled for alert {alert.id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to enable enhanced monitoring for alert {alert.id}: {e}")
            return False
    
    async def _handle_compliance_notification(self, playbook: Playbook, alert: Alert):
        """Handle compliance team notification."""
        if not REAL_MODE:
            self.logger.info(f"[DRY-RUN] Would notify compliance team for alert {alert.id} (skipped)")
            return True
        try:
            # In a real implementation, you'd send notifications to compliance team
            self.logger.warning(f"Compliance team notified for alert {alert.id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to notify compliance team for alert {alert.id}: {e}")
            return False
    
    async def _handle_human_review(self, playbook: Playbook, alert: Alert):
        """Handle human review requirement."""
        self.logger.info(f"Human review required for alert {alert.id}: {playbook.justification}")
        # In a real implementation, you'd create a ticket or notification for human review

    async def run(self, queue: asyncio.Queue):
        self.logger.info("Ready to execute playbooks")
        while not self._stopped:
            playbook, alert = await queue.get()
            try:
                await self.handle_playbook(playbook, alert)
            except Exception as e:
                self.logger.error(f"Exception executing playbook: {e}")

    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics."""
        return self._execution_stats.copy()
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics from all systems."""
        return {
            "remediator": self._execution_stats,
            "execution_tracker": self.execution_tracker.get_execution_stats(),
            "retry_circuit_breaker": self.retry_circuit_breaker.get_stats(),
            "action_policy": self.action_policy_engine.get_stats(),
            "queue_metrics": self.action_queue.get_metrics()
        }
    
    def log_execution_stats(self):
        """Log execution statistics."""
        stats = self.get_execution_stats()
        self.logger.info("=== Remediator Execution Statistics ===")
        self.logger.info(f"Actions executed: {stats['actions_executed']}")
        self.logger.info(f"Actions blocked: {stats['actions_blocked']}")
        self.logger.info(f"Validation errors: {stats['validation_errors']}")
        self.logger.info(f"Dry-run skipped: {stats['dry_run_skipped']}")
        
        # Log additional system stats
        exec_stats = self.execution_tracker.get_execution_stats()
        self.logger.info(f"Total executions tracked: {exec_stats['total_executions']}")
        self.logger.info(f"Duplicate actions skipped: {exec_stats['duplicate_skipped']}")
        self.logger.info(f"Duplicate rate: {exec_stats['duplicate_rate']:.1f}%")
        
        retry_stats = self.retry_circuit_breaker.get_stats()
        self.logger.info(f"Success rate: {retry_stats['success_rate']:.1f}%")
        self.logger.info(f"Retry rate: {retry_stats['retry_rate']:.1f}%")
        
        policy_stats = self.action_policy_engine.get_stats()
        self.logger.info(f"Policy evaluations: {policy_stats['total_evaluations']}")
        self.logger.info(f"Approval rate: {policy_stats['approval_rate']:.1f}%")
        
        queue_metrics = self.action_queue.get_metrics()
        self.logger.info(f"Queue utilization: {queue_metrics.utilization:.1f}%")

    async def stop(self):
        """Stop the remediator and all subsystems."""
        self._stopped = True
        
        # Stop all subsystems
        self.execution_tracker.stop()
        await self.action_queue.stop()
        
        self.log_execution_stats()
        self.logger.info("Remediator stopped")

