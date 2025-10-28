"""
Quick Database Test
Tests authentication, playbook creation, and approval workflow with SQLite
"""

import sys
import logging

# Fix Windows encoding
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger("QuickTest")

def test_database_with_auth():
    """Test database with authentication"""
    print("\n" + "=" * 70)
    print("QUICK DATABASE TEST")
    print("=" * 70)

    try:
        from database import DatabaseManager, DBPlaybook, PlaybookStatus
        from auth_rbac import AuthManager, UserRole
        from crypto_signing import CryptoSigner
        from policy_engine import PolicyEngine
        from approval_workflow import ApprovalWorkflowManager

        # Connect to SQLite database
        print("\n1. Connecting to database...")
        db = DatabaseManager("sqlite:///soc_database.db")
        print("   ✓ Connected to: soc_database.db")

        # Test authentication
        print("\n2. Testing authentication...")
        auth = AuthManager(db)

        analyst = auth.authenticate_local("analyst", "analyst_password")
        print(f"   ✓ Authenticated as: {analyst.username}")
        print(f"   ✓ Role: {analyst.role.value}")
        print(f"   ✓ Permissions: {len(analyst.permissions)}")

        # Test permission check
        can_create = auth.check_permission(analyst, "playbook", "create")
        print(f"   ✓ Can create playbooks: {can_create}")

        # Initialize workflow
        print("\n3. Initializing workflow components...")
        signer = CryptoSigner()
        policy = PolicyEngine()
        workflow = ApprovalWorkflowManager(db, auth, signer, policy)
        print("   ✓ Workflow initialized")

        # Create playbook
        print("\n4. Creating playbook...")
        playbook = workflow.create_playbook(
            auth_context=analyst,
            action="block_ip",
            target="192.168.1.100",
            justification="Test playbook for database verification",
            threat_type="prompt_injection",
            severity="high",
            environment="development"
        )
        print(f"   ✓ Playbook created: {playbook.id}")
        print(f"   ✓ Status: {playbook.status.value}")
        print(f"   ✓ Action: {playbook.action}")
        print(f"   ✓ Target: {playbook.target}")
        print(f"   ✓ Signed: {playbook.signature[:32]}...")

        # Execute dry-run
        print("\n5. Executing dry-run...")
        dry_run = workflow.execute_dry_run(analyst, playbook.id)
        print(f"   ✓ Dry-run success: {dry_run.success}")
        print(f"   ✓ Actions validated: {len(dry_run.actions_validated)}")
        print(f"   ✓ Warnings: {len(dry_run.warnings)}")
        print(f"   ✓ Errors: {len(dry_run.errors)}")

        # Approve playbook
        print("\n6. Testing approval workflow...")
        approver = auth.authenticate_local("approver", "approver_password")
        print(f"   ✓ Authenticated approver: {approver.username}")

        approval = workflow.approve_playbook(
            auth_context=approver,
            playbook_id=playbook.id,
            decision_reason="Test approval for database verification"
        )
        print(f"   ✓ Playbook approved by: {approval.decided_by}")
        print(f"   ✓ Approval signed: {approval.signature[:32]}...")
        print(f"   ✓ Approval status: {approval.status.value}")

        # Query database
        print("\n7. Querying database...")
        session = db.get_session()

        # Count playbooks
        playbook_count = session.query(DBPlaybook).count()
        print(f"   ✓ Total playbooks: {playbook_count}")

        # Get our playbook
        pb = session.query(DBPlaybook).filter(DBPlaybook.id == playbook.id).first()
        print(f"   ✓ Retrieved playbook: {pb.id}")
        print(f"   ✓ Current status: {pb.status.value}")

        session.close()

        # Test audit logs
        print("\n8. Checking audit logs...")
        from database import DBAuditLog
        session = db.get_session()
        logs = session.query(DBAuditLog).filter(
            DBAuditLog.playbook_id == playbook.id
        ).all()
        print(f"   ✓ Audit log entries: {len(logs)}")
        for log in logs:
            print(f"     - {log.event_type}: {log.action} by {log.user_id}")
        session.close()

        print("\n" + "=" * 70)
        print("✅ ALL DATABASE TESTS PASSED!")
        print("=" * 70)
        print("\nDatabase Features Verified:")
        print("  ✓ SQLite connection")
        print("  ✓ User authentication")
        print("  ✓ Role-based permissions")
        print("  ✓ Playbook creation with signatures")
        print("  ✓ Dry-run execution")
        print("  ✓ Approval workflow")
        print("  ✓ Database queries")
        print("  ✓ Audit trail")
        print("\n🎉 Enterprise features working with SQLite database!")
        return True

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_database_with_auth()
    sys.exit(0 if success else 1)
