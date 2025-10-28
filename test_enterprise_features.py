"""
Comprehensive Tests for Enterprise Features

Tests:
1. Database persistence and queries
2. Authentication and RBAC
3. Cryptographic signing and verification
4. Policy engine evaluation
5. Approval workflow end-to-end
6. Audit log hash chain integrity
"""

import sys
import logging
import tempfile
import os
from datetime import datetime, timedelta

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EnterpriseTests")


def test_database_operations():
    """Test 1: Database persistence and queries"""
    logger.info("=" * 70)
    logger.info("TEST 1: Database Operations")
    logger.info("=" * 70)

    try:
        from database import (
            DatabaseManager, DBPlaybook, DBUser, PlaybookStatus,
            create_playbook_record, UserRole
        )

        # Use in-memory SQLite for testing
        db = DatabaseManager("sqlite:///:memory:")
        db.create_all_tables()

        logger.info("✓ Database tables created")

        # Test creating playbook
        session = db.get_session()
        playbook = create_playbook_record(
            session=session,
            playbook_id="test_pb_001",
            action="block_ip",
            target="192.168.1.100",
            justification="Test playbook",
            created_by="test_user",
            threat_type="prompt_injection",
            severity="high"
        )
        session.commit()
        logger.info(f"✓ Created playbook: {playbook.id}")

        # Test querying
        retrieved = session.query(DBPlaybook).filter(
            DBPlaybook.id == "test_pb_001"
        ).first()

        assert retrieved is not None, "Playbook not found"
        assert retrieved.action == "block_ip", "Action mismatch"
        assert retrieved.target == "192.168.1.100", "Target mismatch"
        logger.info("✓ Playbook query successful")

        # Test updating status
        retrieved.status = PlaybookStatus.APPROVED
        session.commit()

        updated = session.query(DBPlaybook).filter(
            DBPlaybook.id == "test_pb_001"
        ).first()
        assert updated.status == PlaybookStatus.APPROVED, "Status not updated"
        logger.info("✓ Playbook status update successful")

        session.close()

        logger.info("✅ TEST 1 PASSED: Database operations working\n")
        return True

    except Exception as e:
        logger.error(f"❌ TEST 1 FAILED: {e}")
        return False


def test_authentication_rbac():
    """Test 2: Authentication and RBAC"""
    logger.info("=" * 70)
    logger.info("TEST 2: Authentication & RBAC")
    logger.info("=" * 70)

    try:
        from database import DatabaseManager, UserRole
        from auth_rbac import AuthManager, AuthenticationError, AuthorizationError

        # Use in-memory database
        db = DatabaseManager("sqlite:///:memory:")
        db.create_all_tables()
        auth = AuthManager(db)

        # Test user creation
        auth.create_user(
            username="test_analyst",
            email="analyst@test.com",
            role=UserRole.ANALYST,
            password="test_password_123"
        )
        logger.info("✓ User created: test_analyst (ANALYST)")

        # Test authentication
        auth_context = auth.authenticate_local("test_analyst", "test_password_123")
        assert auth_context.username == "test_analyst", "Username mismatch"
        assert auth_context.role == UserRole.ANALYST, "Role mismatch"
        logger.info(f"✓ Authentication successful: {auth_context.username}")

        # Test wrong password
        try:
            auth.authenticate_local("test_analyst", "wrong_password")
            logger.error("❌ Should have failed with wrong password")
            return False
        except AuthenticationError:
            logger.info("✓ Wrong password correctly rejected")

        # Test permissions
        can_create = auth.check_permission(auth_context, "playbook", "create")
        assert can_create, "Analyst should be able to create playbooks"
        logger.info("✓ Permission check: Analyst can create playbooks")

        can_approve = auth.check_permission(auth_context, "approval", "approve")
        assert not can_approve, "Analyst should NOT be able to approve"
        logger.info("✓ Permission check: Analyst cannot approve playbooks")

        # Create approver
        auth.create_user(
            username="test_approver",
            email="approver@test.com",
            role=UserRole.APPROVER,
            password="approver_pass"
        )

        approver_context = auth.authenticate_local("test_approver", "approver_pass")
        can_approve = auth.check_permission(approver_context, "approval", "approve")
        assert can_approve, "Approver should be able to approve"
        logger.info("✓ Permission check: Approver can approve playbooks")

        logger.info("✅ TEST 2 PASSED: Authentication & RBAC working\n")
        return True

    except Exception as e:
        logger.error(f"❌ TEST 2 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cryptographic_signing():
    """Test 3: Cryptographic signing and verification"""
    logger.info("=" * 70)
    logger.info("TEST 3: Cryptographic Signing")
    logger.info("=" * 70)

    try:
        from crypto_signing import (
            CryptoSigner, PlaybookSigner, ApprovalSigner,
            AuditLogChain
        )

        signer = CryptoSigner(master_key="test_key_12345", key_id="test_key")
        logger.info("✓ Crypto signer initialized")

        # Test playbook signing
        playbook_signer = PlaybookSigner(signer)
        sig_result = playbook_signer.sign_playbook(
            playbook_id="pb_001",
            action="block_ip",
            target="192.168.1.100",
            justification="Test signing",
            created_by="analyst_john"
        )
        logger.info(f"✓ Playbook signed: {sig_result.signature[:32]}...")

        # Test verification
        verification = playbook_signer.verify_playbook(
            playbook_id="pb_001",
            action="block_ip",
            target="192.168.1.100",
            justification="Test signing",
            threat_type=None,
            metadata={},
            signature=sig_result.signature,
            created_by="analyst_john",
            timestamp=sig_result.timestamp
        )
        assert verification.valid, "Signature verification failed"
        logger.info("✓ Signature verification successful")

        # Test tampering detection
        verification = playbook_signer.verify_playbook(
            playbook_id="pb_001",
            action="block_ip",
            target="192.168.1.200",  # Changed target!
            justification="Test signing",
            threat_type=None,
            metadata={},
            signature=sig_result.signature,
            created_by="analyst_john",
            timestamp=sig_result.timestamp
        )
        assert not verification.valid, "Should detect tampering"
        logger.info("✓ Tampering detection working")

        # Test audit log chain
        chain = AuditLogChain(signer)
        entries = []

        # Create 3 log entries
        for i in range(3):
            log_data, signature, prev_hash = chain.create_log_entry(
                event_type="test_event",
                action=f"action_{i}",
                user_id=f"user_{i}",
                user_role="analyst",
                success=True,
                playbook_id=f"pb_{i}"
            )
            entries.append((log_data, signature, prev_hash))

        logger.info(f"✓ Created audit log chain with {len(entries)} entries")

        # Verify chain integrity
        valid, error = chain.verify_chain_integrity(entries)
        assert valid, f"Chain verification failed: {error}"
        logger.info("✓ Chain integrity verified")

        # Test tampering in chain
        entries[1] = (
            {**entries[1][0], 'action': 'tampered'},  # Tamper with middle entry
            entries[1][1],
            entries[1][2]
        )
        valid, error = chain.verify_chain_integrity(entries)
        assert not valid, "Should detect chain tampering"
        logger.info("✓ Chain tampering detection working")

        logger.info("✅ TEST 3 PASSED: Cryptographic signing working\n")
        return True

    except Exception as e:
        logger.error(f"❌ TEST 3 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_policy_engine():
    """Test 4: Policy engine evaluation"""
    logger.info("=" * 70)
    logger.info("TEST 4: Policy Engine")
    logger.info("=" * 70)

    try:
        from policy_engine import (
            PolicyEngine, IPValidator, PolicyDecision
        )

        # Test IP validation
        valid, error = IPValidator.validate_ip("192.168.1.100")
        assert valid, f"Valid IP rejected: {error}"
        logger.info("✓ IP validation: 192.168.1.100 is valid")

        valid, error = IPValidator.validate_ip("999.999.999.999")
        assert not valid, "Invalid IP accepted"
        logger.info("✓ IP validation: 999.999.999.999 correctly rejected")

        valid, error = IPValidator.validate_cidr("10.0.0.0/8")
        assert valid, f"Valid CIDR rejected: {error}"
        logger.info("✓ CIDR validation: 10.0.0.0/8 is valid")

        # Test IP properties
        is_private = IPValidator.is_private_ip("192.168.1.1")
        assert is_private, "192.168.1.1 should be private"
        logger.info("✓ Private IP detection: 192.168.1.1 is private")

        is_reserved = IPValidator.is_reserved_ip("127.0.0.1")
        assert is_reserved, "127.0.0.1 should be reserved"
        logger.info("✓ Reserved IP detection: 127.0.0.1 is reserved")

        # Test policy engine
        engine = PolicyEngine()
        logger.info(f"✓ Policy engine initialized with {len(engine.rules)} rules")

        # Test blocking localhost (should be denied)
        result = engine.evaluate({
            'action': 'block_ip',
            'target': '127.0.0.1',
            'environment': 'production'
        })
        assert result.decision == PolicyDecision.DENY, "Should deny localhost"
        logger.info(f"✓ Policy: Blocking localhost denied - {result.reasons[0]}")

        # Test blocking private IP (should require approval)
        result = engine.evaluate({
            'action': 'block_ip',
            'target': '192.168.1.100',
            'environment': 'production'
        })
        assert result.decision == PolicyDecision.REQUIRE_APPROVAL, "Should require approval"
        logger.info(f"✓ Policy: Private IP requires approval - {result.reasons[0]}")

        # Test blocking public IP in dev (should allow with dry-run)
        result = engine.evaluate({
            'action': 'block_ip',
            'target': '8.8.8.8',
            'environment': 'development',
            'is_new_playbook': False,
            'has_approval': True
        })
        assert result.decision == PolicyDecision.ALLOW, "Should allow approved public IP"
        logger.info("✓ Policy: Public IP with approval allowed")

        # Test new playbook (should be dry-run only)
        result = engine.evaluate({
            'action': 'block_ip',
            'target': '8.8.8.8',
            'environment': 'development',
            'is_new_playbook': True,
            'has_approval': False
        })
        assert result.decision == PolicyDecision.DRY_RUN_ONLY, "New playbook should be dry-run"
        logger.info("✓ Policy: New playbook requires dry-run")

        logger.info("✅ TEST 4 PASSED: Policy engine working\n")
        return True

    except Exception as e:
        logger.error(f"❌ TEST 4 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_approval_workflow():
    """Test 5: End-to-end approval workflow"""
    logger.info("=" * 70)
    logger.info("TEST 5: Approval Workflow")
    logger.info("=" * 70)

    try:
        from database import DatabaseManager, UserRole
        from auth_rbac import AuthManager
        from crypto_signing import CryptoSigner
        from policy_engine import PolicyEngine
        from approval_workflow import ApprovalWorkflowManager

        # Initialize components
        db = DatabaseManager("sqlite:///:memory:")
        db.create_all_tables()
        auth = AuthManager(db)
        signer = CryptoSigner(master_key="test_key")
        policy = PolicyEngine()
        workflow = ApprovalWorkflowManager(db, auth, signer, policy)

        logger.info("✓ Workflow components initialized")

        # Create users
        auth.create_user("analyst", "analyst@test.com", UserRole.ANALYST, "pass123")
        auth.create_user("approver", "approver@test.com", UserRole.APPROVER, "pass123")
        auth.create_user("executor", "executor@test.com", UserRole.EXECUTOR, "pass123")

        # Authenticate
        analyst = auth.authenticate_local("analyst", "pass123")
        approver_ctx = auth.authenticate_local("approver", "pass123")
        executor_ctx = auth.authenticate_local("executor", "pass123")

        logger.info("✓ Test users created and authenticated")

        # 1. Analyst creates playbook
        playbook = workflow.create_playbook(
            auth_context=analyst,
            action="block_ip",
            target="192.168.1.100",
            justification="Malicious activity detected",
            threat_type="prompt_injection",
            severity="high",
            environment="production"
        )

        assert playbook is not None, "Playbook creation failed"
        assert playbook.signature is not None, "Playbook not signed"
        logger.info(f"✓ Playbook created: {playbook.id}")
        logger.info(f"  Status: {playbook.status.value}")
        logger.info(f"  Signature: {playbook.signature[:32]}...")

        # 2. Execute dry-run
        dry_run = workflow.execute_dry_run(analyst, playbook.id)
        assert dry_run.success, f"Dry-run failed: {dry_run.errors}"
        logger.info(f"✓ Dry-run executed: {len(dry_run.actions_validated)} actions validated")
        logger.info(f"  Estimated impact: {dry_run.estimated_impact}")

        # 3. Approve playbook
        approval = workflow.approve_playbook(
            auth_context=approver_ctx,
            playbook_id=playbook.id,
            decision_reason="Threat validated, action necessary"
        )

        assert approval is not None, "Approval failed"
        assert approval.signature is not None, "Approval not signed"
        logger.info(f"✓ Playbook approved by {approval.decided_by}")
        logger.info(f"  Approval signature: {approval.signature[:32]}...")

        # Verify playbook status changed
        session = db.get_session()
        from database import DBPlaybook, PlaybookStatus
        updated_playbook = session.query(DBPlaybook).filter(
            DBPlaybook.id == playbook.id
        ).first()
        assert updated_playbook.status == PlaybookStatus.APPROVED, "Status not updated"
        logger.info(f"✓ Playbook status: {updated_playbook.status.value}")
        session.close()

        # 4. Check audit logs
        session = db.get_session()
        from database import DBAuditLog
        logs = session.query(DBAuditLog).filter(
            DBAuditLog.playbook_id == playbook.id
        ).order_by(DBAuditLog.timestamp).all()

        logger.info(f"✓ Audit trail: {len(logs)} entries")
        for log in logs:
            logger.info(f"  - {log.event_type}: {log.action} by {log.user_id}")

        # Verify hash chain
        log_entries = []
        for log in logs:
            log_data = {
                'timestamp': log.timestamp.isoformat(),
                'event_type': log.event_type,
                'action': log.action,
                'target': log.target,
                'playbook_id': log.playbook_id,
                'alert_id': log.alert_id,
                'user_id': log.user_id,
                'user_role': log.user_role.value if log.user_role else None,
                'success': log.success,
                'error_message': log.error_message,
                'before_state': log.before_state,
                'after_state': log.after_state,
                'metadata': log.metadata,
                'previous_log_hash': log.previous_log_hash
            }
            log_entries.append((log_data, log.signature, log.previous_log_hash))

        from crypto_signing import AuditLogChain
        chain = AuditLogChain(signer)
        valid, error = chain.verify_chain_integrity(log_entries)
        assert valid, f"Audit chain broken: {error}"
        logger.info("✓ Audit log chain integrity verified")

        session.close()

        logger.info("✅ TEST 5 PASSED: Approval workflow working\n")
        return True

    except Exception as e:
        logger.error(f"❌ TEST 5 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all enterprise feature tests"""
    logger.info("\n" + "=" * 70)
    logger.info("ENTERPRISE FEATURES TEST SUITE")
    logger.info("=" * 70 + "\n")

    results = {
        "Database Operations": test_database_operations(),
        "Authentication & RBAC": test_authentication_rbac(),
        "Cryptographic Signing": test_cryptographic_signing(),
        "Policy Engine": test_policy_engine(),
        "Approval Workflow": test_approval_workflow(),
    }

    # Summary
    logger.info("=" * 70)
    logger.info("TEST SUMMARY")
    logger.info("=" * 70)

    passed = sum(1 for result in results.values() if result)
    total = len(results)

    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        logger.info(f"{test_name:<30} {status}")

    logger.info("=" * 70)
    logger.info(f"TOTAL: {passed}/{total} tests passed")
    logger.info("=" * 70)

    if passed == total:
        logger.info("\n🎉 ALL TESTS PASSED! Enterprise features working correctly.")
        return True
    else:
        logger.error(f"\n⚠️  {total - passed} test(s) failed. Please review the errors above.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
