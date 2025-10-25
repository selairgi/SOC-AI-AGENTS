"""
Comprehensive tests for advanced SOC AI Agents features.
Tests idempotency, retries, circuit breaker, bounded queues, and action policies.
"""

import asyncio
import time
import logging
from typing import Dict, Any

from models import Alert, Playbook, ThreatType
from remediator import Remediator
from execution_tracker import ExecutionTracker
from retry_circuit_breaker import RetryCircuitBreaker, RetryConfig, CircuitBreakerConfig
from bounded_queue import BoundedQueue, QueueConfig, QueueStrategy
from action_policy import ActionPolicyEngine, PolicyRule, PolicyAction
from message_bus import MessageBus


class TestAdvancedFeatures:
    """Test suite for advanced SOC features."""
    
    def __init__(self):
        self.logger = logging.getLogger("TestAdvancedFeatures")
        self.setup_logging()
        
        # Test components
        self.bus = MessageBus()
        self.remediator = Remediator()
        self.execution_tracker = ExecutionTracker()
        self.retry_circuit_breaker = RetryCircuitBreaker()
        self.action_policy_engine = ActionPolicyEngine()
    
    def setup_logging(self):
        """Setup logging for tests."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def test_idempotency_and_deduplication(self):
        """Test idempotency and deduplication features."""
        self.logger.info("=== Testing Idempotency and Deduplication ===")
        
        # Test 1: Action execution tracking
        action_name = "block_ip"
        target = "192.168.1.100"
        playbook_id = "test_playbook_123"
        
        # First execution
        is_executed, record = self.execution_tracker.is_action_executed(action_name, target, playbook_id)
        assert not is_executed, "Action should not be executed yet"
        
        # Record execution
        execution_id = self.execution_tracker.record_action_execution(
            action_name, target, playbook_id, "executed", "Success", None
        )
        assert execution_id is not None, "Execution ID should be generated"
        
        # Second execution should be detected as duplicate
        is_executed, record = self.execution_tracker.is_action_executed(action_name, target, playbook_id)
        assert is_executed, "Action should be marked as executed"
        assert record.status == "executed", "Record status should be executed"
        
        self.logger.info("✓ Action execution tracking works")
        
        # Test 2: Playbook execution tracking
        playbook_id = self.execution_tracker.start_playbook_execution(
            "alert_123", "multi_action", ["block_ip:192.168.1.100", "suspend_user:user123"]
        )
        
        playbook = self.execution_tracker.get_playbook_execution(playbook_id)
        assert playbook is not None, "Playbook execution should be created"
        assert playbook.status == "pending", "Playbook should be pending"
        assert len(playbook.actions) == 2, "Should have 2 actions"
        
        # Update with action results
        self.execution_tracker.update_playbook_execution(playbook_id, "action1", "executed")
        self.execution_tracker.update_playbook_execution(playbook_id, "action2", "executed")
        
        playbook = self.execution_tracker.get_playbook_execution(playbook_id)
        assert playbook.status == "completed", "Playbook should be completed"
        
        self.logger.info("✓ Playbook execution tracking works")
        
        # Test 3: Statistics
        stats = self.execution_tracker.get_execution_stats()
        assert stats["total_executions"] > 0, "Should have recorded executions"
        assert stats["duplicate_skipped"] >= 0, "Should track duplicates"
        
        self.logger.info("✓ Statistics tracking works")
        self.logger.info("✅ Idempotency and deduplication tests passed")
    
    async def test_retry_and_circuit_breaker(self):
        """Test retry mechanism and circuit breaker."""
        self.logger.info("=== Testing Retry and Circuit Breaker ===")
        
        # Test 1: Successful execution
        async def successful_func():
            return "success"
        
        success, result, error = await self.retry_circuit_breaker.execute_with_retry(
            "test_action", "test_target", successful_func
        )
        
        assert success, "Should succeed on first try"
        assert result == "success", "Should return correct result"
        assert error is None, "Should have no error"
        
        self.logger.info("✓ Successful execution works")
        
        # Test 2: Retry on failure
        attempt_count = 0
        
        async def failing_func():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                raise Exception("Transient failure")
            return "success_after_retry"
        
        success, result, error = await self.retry_circuit_breaker.execute_with_retry(
            "test_action", "test_target", failing_func
        )
        
        assert success, "Should succeed after retries"
        assert result == "success_after_retry", "Should return correct result"
        assert attempt_count == 3, "Should have retried 3 times"
        
        self.logger.info("✓ Retry mechanism works")
        
        # Test 3: Circuit breaker
        async def always_failing_func():
            raise Exception("Permanent failure")
        
        # Execute multiple times to trigger circuit breaker
        for i in range(6):  # More than failure threshold
            success, result, error = await self.retry_circuit_breaker.execute_with_retry(
                "failing_action", "failing_target", always_failing_func
            )
            assert not success, f"Should fail on attempt {i+1}"
        
        # Check circuit breaker status
        status = self.retry_circuit_breaker.get_circuit_breaker_status()
        assert status["open_circuits"] > 0, "Should have open circuits"
        
        self.logger.info("✓ Circuit breaker works")
        
        # Test 4: Statistics
        stats = self.retry_circuit_breaker.get_stats()
        assert stats["total_requests"] > 0, "Should have recorded requests"
        assert stats["retries_attempted"] > 0, "Should have attempted retries"
        
        self.logger.info("✓ Statistics tracking works")
        self.logger.info("✅ Retry and circuit breaker tests passed")
    
    async def test_bounded_queue(self):
        """Test bounded queue with backpressure."""
        self.logger.info("=== Testing Bounded Queue ===")
        
        # Create a small queue for testing
        queue_config = QueueConfig(
            max_size=3,
            strategy=QueueStrategy.BLOCK,
            timeout=1.0
        )
        queue = BoundedQueue(queue_config, "test_queue")
        
        # Test 1: Basic put/get operations
        success = await queue.put("item1")
        assert success, "Should successfully put item"
        
        item = await queue.get()
        assert item == "item1", "Should retrieve correct item"
        
        self.logger.info("✓ Basic put/get operations work")
        
        # Test 2: Queue full behavior
        # Fill the queue
        await queue.put("item1")
        await queue.put("item2")
        await queue.put("item3")
        
        # Try to put one more (should timeout with BLOCK strategy)
        success = await queue.put("item4", timeout=0.5)
        assert not success, "Should fail to put when queue is full"
        
        self.logger.info("✓ Queue full behavior works")
        
        # Test 3: Metrics
        metrics = queue.get_metrics()
        assert metrics.current_size == 3, "Should have 3 items"
        assert metrics.utilization == 1.0, "Should be 100% utilized"
        assert metrics.total_puts >= 3, "Should have recorded puts"
        assert metrics.total_gets >= 1, "Should have recorded gets"
        
        self.logger.info("✓ Metrics tracking works")
        
        # Test 4: Different strategies
        drop_oldest_queue = BoundedQueue(
            QueueConfig(max_size=2, strategy=QueueStrategy.DROP_OLDEST),
            "drop_oldest_queue"
        )
        
        await drop_oldest_queue.put("item1")
        await drop_oldest_queue.put("item2")
        success = await drop_oldest_queue.put("item3")  # Should drop item1
        assert success, "Should succeed with DROP_OLDEST strategy"
        
        # item1 should be dropped, item2 and item3 should remain
        items = []
        while not drop_oldest_queue.empty():
            item = await drop_oldest_queue.get()
            if item:
                items.append(item)
        
        assert len(items) == 2, "Should have 2 items after dropping oldest"
        assert "item1" not in items, "Oldest item should be dropped"
        
        self.logger.info("✓ DROP_OLDEST strategy works")
        
        await queue.stop()
        self.logger.info("✅ Bounded queue tests passed")
    
    def test_action_policy_engine(self):
        """Test action policy enforcement."""
        self.logger.info("=== Testing Action Policy Engine ===")
        
        # Test 1: Default policies
        # Test blocking private IP (should require approval)
        evaluation = self.action_policy_engine.evaluate_action(
            "block_ip", "192.168.1.100", "playbook_123", "test_user"
        )
        
        assert not evaluation.allowed, "Blocking private IP should not be allowed"
        assert evaluation.action.value == "require_approval", "Should require approval"
        assert evaluation.approval_required, "Should require approval"
        
        self.logger.info("✓ Private IP blocking policy works")
        
        # Test 2: Approval workflow
        pending_approvals = self.action_policy_engine.get_pending_approvals()
        assert len(pending_approvals) > 0, "Should have pending approvals"
        
        approval_request = pending_approvals[0]
        request_id = approval_request.request_id
        
        # Approve the action
        success = self.action_policy_engine.approve_action(request_id, "admin_user")
        assert success, "Should successfully approve action"
        
        approval_request = self.action_policy_engine.get_approval_request(request_id)
        assert approval_request.status.value == "approved", "Should be approved"
        
        self.logger.info("✓ Approval workflow works")
        
        # Test 3: Custom policy rule
        custom_rule = PolicyRule(
            rule_id="test_rule",
            name="Test Rule",
            description="Test custom rule",
            action_name="test_action",
            conditions={"target_patterns": [r"test.*"]},
            policy_action=PolicyAction.ALLOW,
            priority=50
        )
        
        self.action_policy_engine.add_rule(custom_rule)
        
        evaluation = self.action_policy_engine.evaluate_action(
            "test_action", "test_target", "playbook_456", "test_user"
        )
        
        assert evaluation.allowed, "Custom rule should allow action"
        assert evaluation.rule_id == "test_rule", "Should reference custom rule"
        
        self.logger.info("✓ Custom policy rules work")
        
        # Test 4: Statistics
        stats = self.action_policy_engine.get_stats()
        assert stats["total_evaluations"] > 0, "Should have evaluations"
        assert stats["approval_required"] > 0, "Should have required approvals"
        assert stats["approvals_granted"] > 0, "Should have granted approvals"
        
        self.logger.info("✓ Statistics tracking works")
        self.logger.info("✅ Action policy engine tests passed")
    
    async def test_integration_scenario(self):
        """Test complete integration scenario."""
        self.logger.info("=== Testing Integration Scenario ===")
        
        # Create test alert and playbook
        alert = Alert(
            id="integration_test_alert",
            timestamp=time.time(),
            severity="high",
            title="Integration Test Alert",
            description="Test alert for integration testing",
            threat_type=ThreatType.PROMPT_INJECTION,
            agent_id="test_agent",
            evidence={"src_ip": "192.168.1.100", "user_id": "test_user"}
        )
        
        playbook = Playbook(
            action="multi_action",
            target="",
            justification="Integration test",
            owner="test_user",
            threat_type=ThreatType.PROMPT_INJECTION,
            agent_id="test_agent",
            metadata={
                "actions": ["block_ip:192.168.1.100", "suspend_user:test_user"]
            }
        )
        
        # Test playbook processing
        try:
            await self.remediator.handle_playbook(playbook, alert)
            
            # Check execution tracking
            exec_stats = self.remediator.execution_tracker.get_execution_stats()
            assert exec_stats["total_executions"] > 0, "Should have tracked executions"
            
            # Check retry/circuit breaker stats
            retry_stats = self.remediator.retry_circuit_breaker.get_stats()
            assert retry_stats["total_requests"] > 0, "Should have processed requests"
            
            # Check policy stats
            policy_stats = self.remediator.action_policy_engine.get_stats()
            assert policy_stats["total_evaluations"] > 0, "Should have policy evaluations"
            
            # Check comprehensive stats
            comprehensive_stats = self.remediator.get_comprehensive_stats()
            assert "remediator" in comprehensive_stats, "Should have remediator stats"
            assert "execution_tracker" in comprehensive_stats, "Should have execution tracker stats"
            assert "retry_circuit_breaker" in comprehensive_stats, "Should have retry stats"
            assert "action_policy" in comprehensive_stats, "Should have policy stats"
            assert "queue_metrics" in comprehensive_stats, "Should have queue stats"
            
            self.logger.info("✓ Integration scenario completed successfully")
            
        except Exception as e:
            self.logger.error(f"Integration test failed: {e}")
            raise
        
        self.logger.info("✅ Integration scenario test passed")
    
    async def run_all_tests(self):
        """Run all advanced feature tests."""
        self.logger.info("🚀 Starting Advanced Features Test Suite")
        
        try:
            # Run individual test suites
            self.test_idempotency_and_deduplication()
            await self.test_retry_and_circuit_breaker()
            await self.test_bounded_queue()
            self.test_action_policy_engine()
            await self.test_integration_scenario()
            
            self.logger.info("🎉 All advanced feature tests passed!")
            
        except Exception as e:
            self.logger.error(f"❌ Test suite failed: {e}")
            raise
        finally:
            # Cleanup
            await self.remediator.stop()


async def main():
    """Main test runner."""
    test_suite = TestAdvancedFeatures()
    await test_suite.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
