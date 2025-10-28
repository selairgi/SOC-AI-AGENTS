# 🏢 Enterprise Features Documentation

## Overview

This document describes the enterprise-grade security and operational improvements added to the SOC AI Agents system, including:

1. **Persistent Storage** - PostgreSQL database for playbooks, approvals, and audit logs
2. **Authentication & RBAC** - OIDC/local auth with role-based access control
3. **Tamper-Evident Audit Trail** - Cryptographic signing and hash chains
4. **Policy-as-Code** - OPA-style policy engine with robust validation
5. **Approval Workflow** - Dry-run default with approval gating

---

## 1. Persistent Storage with PostgreSQL

### Features
✅ Durable storage that survives restarts
✅ Full query capabilities with indexes
✅ Retention policies and automatic cleanup
✅ Export capabilities for forensic analysis
✅ Transaction support for data integrity

### Database Schema

#### Tables

**playbooks** - Remediation playbooks
- `id` - Unique playbook identifier
- `created_at`, `updated_at` - Timestamps
- `action`, `target` - Remediation details
- `status` - pending, dry_run, approved, executing, completed, failed
- `created_by`, `approved_by`, `executed_by` - User tracking
- `signature` - Cryptographic signature
- `dry_run_result`, `execution_result` - JSON results
- `expires_at` - Retention policy

**approvals** - Approval decisions
- `id` - Approval identifier
- `playbook_id` - Associated playbook
- `status` - pending, approved, rejected, expired
- `requested_by`, `decided_by` - User tracking
- `decision_reason` - Justification
- `signature` - Cryptographic proof
- `expires_at` - Approval timeout

**audit_logs** - Immutable audit trail
- `id` - Sequential log ID
- `event_type` - Type of event
- `user_id`, `user_role` - Actor information
- `success` - Operation result
- `before_state`, `after_state` - State changes
- `signature` - Cryptographic signature
- `previous_log_hash` - Hash chain link

**users** - User authentication
- `id`, `username`, `email` - User identity
- `role` - RBAC role (viewer, analyst, approver, executor, admin)
- `password_hash` - Hashed password
- `oidc_subject` - OIDC identifier
- `active`, `locked` - Account status

**sessions** - Active sessions
- `id` - Session identifier
- `user_id` - Associated user
- `token_hash` - Hashed session token
- `expires_at` - Session expiration
- `revoked` - Revocation status

### Setup

```bash
# 1. Install PostgreSQL
# Ubuntu/Debian:
sudo apt-get install postgresql postgresql-contrib

# macOS:
brew install postgresql

# Windows:
# Download from https://www.postgresql.org/download/windows/

# 2. Create database and user
sudo -u postgres psql
CREATE DATABASE soc_db;
CREATE USER soc WITH PASSWORD 'soc_password';
GRANT ALL PRIVILEGES ON DATABASE soc_db TO soc;
\q

# 3. Install Python dependencies
pip install -r requirements_enterprise.txt

# 4. Run database setup
python setup_database.py setup --url "postgresql://soc:soc_password@localhost:5432/soc_db"
```

### Usage

```python
from database import DatabaseManager

# Initialize
db = DatabaseManager("postgresql://soc:soc_password@localhost:5432/soc_db")

# Query playbooks
session = db.get_session()
playbooks = session.query(DBPlaybook).filter(
    DBPlaybook.status == PlaybookStatus.PENDING
).all()

# Export audit logs for forensics
logs = db.export_audit_logs(
    session,
    start_date=datetime(2025, 1, 1),
    end_date=datetime(2025, 12, 31),
    user_id="analyst_john"
)

# Save to JSON
import json
with open('audit_export.json', 'w') as f:
    json.dump(logs, f, indent=2)

session.close()
```

### Retention Policies

Automatic cleanup runs periodically:
- **Playbooks**: Archived after expiration (default: 90 days)
- **Sessions**: Revoked after expiration (default: 8 hours)
- **Approvals**: Expired if not decided (default: 24 hours)

Configure retention in `database.py`:
```python
playbook = create_playbook_record(
    ...,
    expires_in_days=90  # Customize retention
)
```

---

## 2. Authentication & RBAC

### Roles

| Role | Permissions | Use Case |
|------|------------|----------|
| **VIEWER** | Read playbooks, approvals, audit logs | Security monitoring |
| **ANALYST** | Create playbooks, request approvals | SOC analysts |
| **APPROVER** | Approve/reject playbooks | Security managers |
| **EXECUTOR** | Execute approved playbooks | Automation systems |
| **ADMIN** | All permissions | System administrators |

### Authentication Methods

#### Local Authentication
```python
from auth_rbac import AuthManager

auth = AuthManager(db_manager)

# Create user
auth.create_user(
    username="john.doe",
    email="john@company.com",
    role=UserRole.ANALYST,
    password="strong_password_here"
)

# Authenticate
auth_context = auth.authenticate_local(
    username="john.doe",
    password="strong_password_here",
    ip_address="192.168.1.50"
)

print(f"Logged in as {auth_context.username} with role {auth_context.role.value}")
```

#### OIDC Authentication
```python
# After OIDC provider validates user
auth_context = auth.authenticate_oidc(
    oidc_subject="user@company.com",
    id_token={
        'sub': 'user@company.com',
        'email': 'user@company.com',
        'preferred_username': 'user',
        'roles': ['soc-analyst']  # Maps to UserRole.ANALYST
    },
    ip_address="192.168.1.50"
)
```

### Permission Checking

```python
# Check permission manually
if auth.check_permission(auth_context, "playbook", "create"):
    # User can create playbooks
    pass

# Use decorator
@auth.require_permission("playbook", "approve")
def approve_playbook(auth_context, playbook_id):
    # Only users with approve permission can call this
    pass
```

### Session Management

```python
# Sessions are created automatically during authentication
# Validate session token
auth_context = auth.validate_token(session_token)

# Revoke session (logout)
auth.revoke_session(session_id)
```

### Default Users

After setup, these test users are available:

- **admin** / admin_password_change_me (ADMIN)
- **analyst** / analyst_password (ANALYST)
- **approver** / approver_password (APPROVER)
- **executor** / executor_password (EXECUTOR)

⚠️ **CHANGE DEFAULT PASSWORDS IN PRODUCTION!**

---

## 3. Tamper-Evident Audit Trail

### Cryptographic Signing

All playbooks, approvals, and audit logs are cryptographically signed using HMAC-SHA256.

```python
from crypto_signing import CryptoSigner, PlaybookSigner

# Initialize signer
signer = CryptoSigner(master_key="your-secret-key-here")
playbook_signer = PlaybookSigner(signer)

# Sign playbook
sig_result = playbook_signer.sign_playbook(
    playbook_id="pb_12345",
    action="block_ip",
    target="192.168.1.100",
    justification="Critical threat",
    created_by="analyst_john"
)

# Signature is stored with playbook
print(f"Signature: {sig_result.signature}")
print(f"Timestamp: {sig_result.timestamp}")
```

### Audit Log Hash Chain

Audit logs form a blockchain-like hash chain for tamper detection:

```
Log 1 → Hash → Log 2 → Hash → Log 3 → Hash → ...
        ↓               ↓               ↓
    Stored in      Stored in       Stored in
    Log 2's        Log 3's         Log 4's
    prev_hash      prev_hash       prev_hash
```

```python
from crypto_signing import AuditLogChain

chain = AuditLogChain(signer)

# Create log entry
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

### Forensic Analysis

Generate tamper-proof reports:

```python
from database import DatabaseManager

db = DatabaseManager(...)

# Export audit logs
logs = db.export_audit_logs(
    session,
    start_date=datetime(2025, 1, 1),
    user_id="analyst_john",
    event_type="playbook_approved"
)

# Each log includes:
# - What was done (action)
# - Who did it (user_id, user_role)
# - When it was done (timestamp)
# - Cryptographic proof (signature)
# - Hash chain link (previous_log_hash)
```

---

## 4. Policy-as-Code Engine

### Robust IP Validation

Uses Python's `ipaddress` library for bulletproof validation:

```python
from policy_engine import IPValidator

# Validate IP
valid, error = IPValidator.validate_ip("192.168.1.100")
if not valid:
    print(f"Invalid IP: {error}")

# Validate CIDR
valid, error = IPValidator.validate_cidr("10.0.0.0/8")

# Check if IP is in network
is_in = IPValidator.ip_in_network("192.168.1.50", "192.168.1.0/24")

# Check IP properties
is_private = IPValidator.is_private_ip("192.168.1.1")  # True
is_reserved = IPValidator.is_reserved_ip("127.0.0.1")  # True
```

### Policy Rules

Built-in policies:

1. **BlockReservedIPRule** - Deny blocking of localhost, loopback
2. **WhitelistIPRule** - Never block whitelisted IPs/networks
3. **PrivateIPApprovalRule** - Require approval for private IPs
4. **ProductionApprovalRule** - Require approval in production
5. **HighRiskApprovalRule** - Require approval for destructive actions
6. **DryRunDefaultRule** - New playbooks default to dry-run

### Policy Evaluation

```python
from policy_engine import PolicyEngine

engine = PolicyEngine()

# Evaluate action
result = engine.evaluate({
    'action': 'block_ip',
    'target': '192.168.1.100',
    'environment': 'production',
    'severity': 'critical',
    'created_by': 'analyst_john'
})

if result.decision == PolicyDecision.DENY:
    print(f"Action denied: {result.reasons}")
elif result.decision == PolicyDecision.REQUIRE_APPROVAL:
    print(f"Approval required: {result.reasons}")
elif result.decision == PolicyDecision.ALLOW:
    print("Action allowed")
```

### Custom Policies

Create your own policy rules:

```python
from policy_engine import PolicyRule, PolicyResult, PolicyDecision

class BusinessHoursOnlyRule(PolicyRule):
    """Only allow actions during business hours"""

    def __init__(self):
        super().__init__(
            "business_hours_only",
            "Restrict actions to business hours (9am-5pm)",
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
engine.add_rule(BusinessHoursOnlyRule())
```

---

## 5. Approval Workflow with Dry-Run

### Dry-Run Mode (Default)

All new playbooks default to dry-run mode for safety:

```python
from approval_workflow import ApprovalWorkflowManager

workflow = ApprovalWorkflowManager(db, auth, signer, policy_engine)

# Create playbook (automatically in dry-run mode)
playbook = workflow.create_playbook(
    auth_context=analyst_context,
    action="block_ip",
    target="192.168.1.100",
    justification="Malicious activity detected",
    environment="production"
)

print(f"Playbook status: {playbook.status}")  # Output: DRY_RUN

# Execute dry-run (simulation)
dry_run_result = workflow.execute_dry_run(analyst_context, playbook.id)

if dry_run_result.success:
    print(f"✓ Dry-run successful: {len(dry_run_result.actions_validated)} actions validated")
    print(f"Estimated impact: {dry_run_result.estimated_impact}")
else:
    print(f"✗ Dry-run failed: {dry_run_result.errors}")
```

### Approval Process

```python
# If policy requires approval, request is auto-created
# Approver can then approve the playbook

approver_context = auth.authenticate_local("approver", "password")

# Approve playbook
approval = workflow.approve_playbook(
    auth_context=approver_context,
    playbook_id=playbook.id,
    decision_reason="Validated threat, blocking necessary"
)

print(f"Playbook approved by {approval.decided_by}")
print(f"Approval signature: {approval.signature[:32]}...")
```

### Execution

```python
# Only approved playbooks can be executed
# Must have EXECUTOR role

executor_context = auth.authenticate_local("executor", "password")

# Execute playbook
result = remediator.execute_playbook(
    auth_context=executor_context,
    playbook_id=playbook.id
)

if result.success:
    print(f"✓ Playbook executed: {len(result.actions_executed)} actions")
else:
    print(f"✗ Execution failed: {result.errors}")
```

### Approval Workflow Diagram

```
┌─────────────────────────────────────────────────────────┐
│ 1. ANALYST CREATES PLAYBOOK                             │
│    └─→ Default Status: DRY_RUN                          │
│    └─→ Policy Evaluation: REQUIRE_APPROVAL              │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ 2. DRY-RUN EXECUTION (Simulation)                       │
│    ├─→ Validate all actions                             │
│    ├─→ Check targets                                    │
│    ├─→ Estimate impact                                  │
│    └─→ Store results in playbook                        │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ 3. APPROVAL REQUEST                                     │
│    ├─→ Status: PENDING                                  │
│    ├─→ Expires in 24 hours                              │
│    └─→ Notify approvers                                 │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ 4. APPROVER DECISION                                    │
│    ├─→ Review dry-run results                           │
│    ├─→ Approve or Reject                                │
│    ├─→ Cryptographically sign decision                  │
│    └─→ Status: APPROVED                                 │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ 5. EXECUTOR RUNS PLAYBOOK                               │
│    ├─→ Verify approval signature                        │
│    ├─→ Execute actions                                  │
│    ├─→ Log all steps                                    │
│    └─→ Status: COMPLETED                                │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start Guide

### 1. Install PostgreSQL

```bash
# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib

# macOS
brew install postgresql
brew services start postgresql

# Windows
# Download installer from postgresql.org
```

### 2. Install Python Dependencies

```bash
pip install -r requirements_enterprise.txt
```

### 3. Set up Database

```bash
# Create database
createdb soc_db

# Run setup script
python setup_database.py setup \
  --url "postgresql://soc:soc_password@localhost:5432/soc_db"
```

### 4. Configure Environment

```bash
# .env file
DATABASE_URL=postgresql://soc:soc_password@localhost:5432/soc_db
CRYPTO_KEY=your-secret-key-here-change-me
ENVIRONMENT=production
```

### 5. Start the System

```python
# enhanced_soc_system.py
from database import DatabaseManager
from auth_rbac import AuthManager
from crypto_signing import CryptoSigner
from policy_engine import PolicyEngine
from approval_workflow import ApprovalWorkflowManager

# Initialize
db = DatabaseManager(os.getenv('DATABASE_URL'))
auth = AuthManager(db)
signer = CryptoSigner(os.getenv('CRYPTO_KEY'))
policy = PolicyEngine()
workflow = ApprovalWorkflowManager(db, auth, signer, policy)

# Ready to use!
```

---

## Security Best Practices

### Production Checklist

- [ ] Change all default passwords
- [ ] Use strong, random master key for signing
- [ ] Enable HTTPS/TLS for all connections
- [ ] Configure PostgreSQL with SSL
- [ ] Enable connection pooling
- [ ] Set up database backups
- [ ] Configure OIDC for authentication
- [ ] Implement rate limiting on API
- [ ] Enable database audit logging
- [ ] Set up monitoring and alerting
- [ ] Configure log retention policies
- [ ] Test disaster recovery procedures

### Key Rotation

```python
# Rotate signing keys periodically
old_signer = CryptoSigner(master_key=old_key, key_id="key_v1")
new_signer = CryptoSigner(master_key=new_key, key_id="key_v2")

# Sign new data with new key
# Keep old key for verifying historical signatures
```

### Backup Strategy

```bash
# Daily database backup
pg_dump -h localhost -U soc soc_db > backup_$(date +%Y%m%d).sql

# Export audit logs
python -c "
from database import DatabaseManager
db = DatabaseManager('postgresql://...')
session = db.get_session()
logs = db.export_audit_logs(session)
import json
with open('audit_backup.json', 'w') as f:
    json.dump(logs, f)
"
```

---

## API Integration

All features are accessible via REST API with authentication:

```http
### Authenticate
POST /api/auth/login
Content-Type: application/json

{
  "username": "analyst",
  "password": "password"
}

### Create Playbook
POST /api/playbooks
Authorization: Bearer <token>
Content-Type: application/json

{
  "action": "block_ip",
  "target": "192.168.1.100",
  "justification": "Malicious activity",
  "environment": "production"
}

### Execute Dry-Run
POST /api/playbooks/{id}/dry-run
Authorization: Bearer <token>

### Approve Playbook
POST /api/approvals/{playbook_id}/approve
Authorization: Bearer <token>
Content-Type: application/json

{
  "decision_reason": "Threat validated, action necessary"
}

### Export Audit Logs
GET /api/audit/export?start_date=2025-01-01&end_date=2025-12-31
Authorization: Bearer <token>
```

---

## Troubleshooting

### Database Connection Issues

```python
# Test connection
from database import DatabaseManager

db = DatabaseManager("postgresql://soc:password@localhost:5432/soc_db")
if db.health_check():
    print("✓ Connected")
else:
    print("✗ Connection failed")
```

### Permission Errors

```python
# Debug permissions
auth_context = auth.authenticate_local("user", "password")
print(f"Role: {auth_context.role.value}")
print(f"Permissions: {[f'{p.resource}:{p.action}' for p in auth_context.permissions]}")
```

### Signature Verification Failures

- Ensure master key is consistent
- Check timestamps are in UTC
- Verify data hasn't been modified

---

## Performance Considerations

- **Database Indexes**: All critical columns are indexed
- **Connection Pooling**: SQLAlchemy pool with 10-20 connections
- **Query Optimization**: Use eager loading for relationships
- **Caching**: Session tokens cached in memory
- **Async Operations**: All I/O is non-blocking

---

## Support

For issues or questions:
1. Check logs in `/var/log/soc/` or console output
2. Verify database connectivity
3. Check authentication configuration
4. Review policy evaluation results
5. Consult audit logs for detailed history
