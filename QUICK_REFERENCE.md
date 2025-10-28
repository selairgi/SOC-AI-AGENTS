# Enterprise Features Quick Reference

## 1. Database Setup

```bash
# Install PostgreSQL
sudo apt-get install postgresql

# Create database
sudo -u postgres psql
CREATE DATABASE soc_db;
CREATE USER soc WITH PASSWORD 'soc_password';
GRANT ALL PRIVILEGES ON DATABASE soc_db TO soc;
\q

# Install dependencies
pip install -r requirements_enterprise.txt

# Initialize database
python setup_database.py setup --url "postgresql://soc:soc_password@localhost:5432/soc_db"
```

## 2. Authentication

```python
from database import DatabaseManager
from auth_rbac import AuthManager, UserRole

db = DatabaseManager("postgresql://soc:soc_password@localhost:5432/soc_db")
auth = AuthManager(db)

# Create user
auth.create_user(
    username="john.doe",
    email="john@company.com",
    role=UserRole.ANALYST,
    password="strong_password"
)

# Authenticate (local)
auth_context = auth.authenticate_local("john.doe", "strong_password")

# Authenticate (OIDC)
auth_context = auth.authenticate_oidc(
    oidc_subject="user@company.com",
    id_token={'sub': 'user@company.com', 'roles': ['soc-analyst']}
)

# Check permission
if auth.check_permission(auth_context, "playbook", "create"):
    # User can create playbooks
    pass
```

## 3. Policy Engine

```python
from policy_engine import PolicyEngine, IPValidator

# Validate IP
valid, error = IPValidator.validate_ip("192.168.1.100")

# Validate CIDR
valid, error = IPValidator.validate_cidr("10.0.0.0/8")

# Check IP in network
is_in = IPValidator.ip_in_network("192.168.1.50", "192.168.1.0/24")

# Evaluate policy
engine = PolicyEngine()
result = engine.evaluate({
    'action': 'block_ip',
    'target': '192.168.1.100',
    'environment': 'production',
    'severity': 'critical'
})

if result.decision == PolicyDecision.DENY:
    print(f"Denied: {result.reasons}")
elif result.requires_approval:
    print(f"Approval required: {result.reasons}")
```

## 4. Approval Workflow

```python
from approval_workflow import ApprovalWorkflowManager
from crypto_signing import CryptoSigner

signer = CryptoSigner()
workflow = ApprovalWorkflowManager(db, auth, signer, policy_engine)

# Create playbook (dry-run default)
playbook = workflow.create_playbook(
    auth_context=analyst_context,
    action="block_ip",
    target="192.168.1.100",
    justification="Suspicious activity",
    severity="high",
    environment="production"
)

# Execute dry-run
dry_run_result = workflow.execute_dry_run(analyst_context, playbook.id)

# Approve
approval = workflow.approve_playbook(
    auth_context=approver_context,
    playbook_id=playbook.id,
    decision_reason="Threat validated"
)

# Reject
approval = workflow.reject_playbook(
    auth_context=approver_context,
    playbook_id=playbook.id,
    decision_reason="False positive"
)
```

## 5. Cryptographic Signing

```python
from crypto_signing import CryptoSigner, PlaybookSigner, AuditLogChain

# Initialize signer
signer = CryptoSigner(master_key="your-secret-key", key_id="prod_key_v1")

# Sign playbook
playbook_signer = PlaybookSigner(signer)
sig_result = playbook_signer.sign_playbook(
    playbook_id="pb_12345",
    action="block_ip",
    target="192.168.1.100",
    justification="Critical threat",
    created_by="analyst_john"
)

# Verify playbook
verification = playbook_signer.verify_playbook(
    playbook_id="pb_12345",
    action="block_ip",
    target="192.168.1.100",
    justification="Critical threat",
    threat_type="prompt_injection",
    metadata={},
    signature=sig_result.signature,
    created_by="analyst_john",
    timestamp=sig_result.timestamp
)

if verification.valid:
    print("✓ Signature valid")
else:
    print(f"✗ Verification failed: {verification.error}")

# Audit log chain
chain = AuditLogChain(signer)
log_data, signature, prev_hash = chain.create_log_entry(
    event_type="playbook_executed",
    action="block_ip",
    user_id="executor_bot",
    user_role="executor",
    success=True,
    playbook_id="pb_12345"
)

# Verify chain integrity
valid, error = chain.verify_chain_integrity(log_entries)
if not valid:
    print(f"⚠️ TAMPERING DETECTED: {error}")
```

## 6. Database Queries

```python
from database import DatabaseManager, DBPlaybook, DBApproval, DBAuditLog, PlaybookStatus
from datetime import datetime, timedelta

db = DatabaseManager("postgresql://...")
session = db.get_session()

# Query pending playbooks
pending = session.query(DBPlaybook).filter(
    DBPlaybook.status == PlaybookStatus.PENDING
).all()

# Query playbooks by user
user_playbooks = session.query(DBPlaybook).filter(
    DBPlaybook.created_by == "analyst_john"
).order_by(DBPlaybook.created_at.desc()).limit(10).all()

# Query approvals needing action
pending_approvals = session.query(DBApproval).filter(
    DBApproval.status == ApprovalStatus.PENDING,
    DBApproval.expires_at > datetime.utcnow()
).all()

# Export audit logs
logs = db.export_audit_logs(
    session,
    start_date=datetime.utcnow() - timedelta(days=30),
    user_id="analyst_john",
    event_type="playbook_created"
)

# Cleanup expired records
db.cleanup_expired_records(session)

session.close()
```

## 7. Custom Policy Rules

```python
from policy_engine import PolicyRule, PolicyResult, PolicyDecision

class BusinessHoursOnlyRule(PolicyRule):
    def __init__(self):
        super().__init__(
            "business_hours_only",
            "Restrict actions to business hours",
            priority=50
        )

    def evaluate(self, context):
        from datetime import datetime
        hour = datetime.now().hour

        if hour < 9 or hour >= 17:
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reasons=["Actions outside business hours require approval"],
                matched_policies=[self.rule_id],
                metadata={'hour': hour}
            )
        return None

# Add to engine
engine = PolicyEngine()
engine.add_rule(BusinessHoursOnlyRule())
```

## 8. Permission Decorators

```python
from auth_rbac import AuthManager

auth = AuthManager(db)

@auth.require_permission("playbook", "create")
def create_playbook(auth_context, ...):
    # Only users with create permission can call this
    pass

@auth.require_permission("approval", "approve")
def approve_playbook(auth_context, ...):
    # Only approvers can call this
    pass
```

## 9. Default Users

After setup:

| Username | Password | Role |
|----------|----------|------|
| admin | admin_password_change_me | ADMIN |
| analyst | analyst_password | ANALYST |
| approver | approver_password | APPROVER |
| executor | executor_password | EXECUTOR |

⚠️ Change all passwords in production!

## 10. Common Operations

```python
# Complete workflow example
from database import DatabaseManager
from auth_rbac import AuthManager
from crypto_signing import CryptoSigner
from policy_engine import PolicyEngine
from approval_workflow import ApprovalWorkflowManager

# Initialize
db = DatabaseManager("postgresql://soc:soc_password@localhost:5432/soc_db")
auth = AuthManager(db)
signer = CryptoSigner()
policy = PolicyEngine()
workflow = ApprovalWorkflowManager(db, auth, signer, policy)

# 1. Analyst creates playbook
analyst = auth.authenticate_local("analyst", "analyst_password")
playbook = workflow.create_playbook(
    auth_context=analyst,
    action="block_ip",
    target="192.168.1.100",
    justification="Malicious activity detected",
    severity="high",
    environment="production"
)

# 2. Execute dry-run
dry_run = workflow.execute_dry_run(analyst, playbook.id)
print(f"Dry-run: {dry_run.success}, validated: {len(dry_run.actions_validated)}")

# 3. Approver reviews and approves
approver = auth.authenticate_local("approver", "approver_password")
approval = workflow.approve_playbook(
    approver,
    playbook.id,
    "Threat validated, blocking necessary"
)

# 4. Executor runs playbook
executor = auth.authenticate_local("executor", "executor_password")
# ... execute playbook logic ...

# 5. Query audit logs
session = db.get_session()
logs = db.export_audit_logs(session, playbook_id=playbook.id)
print(f"Audit trail: {len(logs)} entries")
session.close()
```

## Environment Variables

```bash
# .env file
DATABASE_URL=postgresql://soc:soc_password@localhost:5432/soc_db
CRYPTO_KEY=your-secret-key-here-change-in-production
OIDC_CLIENT_ID=your-oidc-client-id
OIDC_CLIENT_SECRET=your-oidc-secret
OIDC_DISCOVERY_URL=https://your-oidc-provider.com/.well-known/openid-configuration
ENVIRONMENT=production
```

## CLI Commands

```bash
# Database setup
python setup_database.py setup
python setup_database.py verify
python setup_database.py export-schema --output schema.sql

# Run tests
python -m pytest tests/
python database.py  # Test database
python auth_rbac.py  # Test auth
python crypto_signing.py  # Test signing
python policy_engine.py  # Test policies
```

## Documentation

- [ENTERPRISE_FEATURES.md](./ENTERPRISE_FEATURES.md) - Full documentation
- [ENTERPRISE_SETUP_GUIDE.md](./ENTERPRISE_SETUP_GUIDE.md) - Setup guide
- [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md) - Implementation details
- [README.md](./README.md) - Main readme

---

**Need help?** Check the full documentation or run modules with `python <module>.py` to see examples.
