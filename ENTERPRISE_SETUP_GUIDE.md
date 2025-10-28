# 🚀 Enterprise Setup Quick Guide

## What's New?

The SOC AI Agents system now includes **enterprise-grade security and operational features**:

✅ **PostgreSQL Database** - Persistent storage for playbooks, approvals, and audit logs
✅ **Authentication & RBAC** - Role-based access control with OIDC support
✅ **Cryptographic Signing** - Tamper-evident audit trail with hash chains
✅ **Policy Engine** - Robust validation and policy-as-code
✅ **Approval Workflow** - Dry-run default with approval gating for destructive actions

## Quick Setup (5 minutes)

### 1. Install PostgreSQL

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib
sudo systemctl start postgresql
```

**macOS:**
```bash
brew install postgresql
brew services start postgresql
```

**Windows:**
Download and install from [postgresql.org](https://www.postgresql.org/download/windows/)

### 2. Create Database

```bash
# Connect to PostgreSQL
sudo -u postgres psql

# Create database and user
CREATE DATABASE soc_db;
CREATE USER soc WITH PASSWORD 'soc_password';
GRANT ALL PRIVILEGES ON DATABASE soc_db TO soc;
\q
```

### 3. Install Python Dependencies

```bash
pip install -r requirements_enterprise.txt
```

### 4. Initialize Database

```bash
python setup_database.py setup --url "postgresql://soc:soc_password@localhost:5432/soc_db"
```

**Output:**
```
======================================================================
SOC AI AGENTS - DATABASE SETUP
======================================================================
✓ Database connection successful
✓ Database tables created successfully
✓ Authentication system initialized
✓ Default users created:
  - admin / admin_password_change_me (ADMIN)
  - analyst / analyst_password (ANALYST)
  - approver / approver_password (APPROVER)
  - executor / executor_password (EXECUTOR)
✓ Policy engine initialized with 6 default policies
✓ Cryptographic signer initialized
======================================================================
DATABASE SETUP COMPLETE!
======================================================================
```

### 5. Verify Setup

```bash
python setup_database.py verify --url "postgresql://soc:soc_password@localhost:5432/soc_db"
```

---

## Using Enterprise Features

### Example: Create Playbook with Approval Workflow

```python
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

# Authenticate as analyst
analyst = auth.authenticate_local("analyst", "analyst_password")

# Create playbook (defaults to dry-run)
playbook = workflow.create_playbook(
    auth_context=analyst,
    action="block_ip",
    target="192.168.1.100",
    justification="Suspicious activity detected",
    threat_type="prompt_injection",
    severity="high",
    environment="production"
)

print(f"✓ Playbook {playbook.id} created")
print(f"  Status: {playbook.status.value}")  # DRY_RUN or PENDING
print(f"  Signed: {playbook.signature[:32]}...")

# Execute dry-run
dry_run = workflow.execute_dry_run(analyst, playbook.id)
print(f"✓ Dry-run: {len(dry_run.actions_validated)} actions validated")
print(f"  Estimated impact: {dry_run.estimated_impact}")

# Authenticate as approver
approver = auth.authenticate_local("approver", "approver_password")

# Approve playbook
approval = workflow.approve_playbook(
    auth_context=approver,
    playbook_id=playbook.id,
    decision_reason="Threat validated, blocking necessary"
)

print(f"✓ Playbook approved by {approval.decided_by}")
print(f"  Approval signed: {approval.signature[:32]}...")

# Now playbook can be executed by executor role
```

### Example: Query Audit Logs

```python
from datetime import datetime

# Export audit logs for forensics
session = db.get_session()
logs = db.export_audit_logs(
    session,
    start_date=datetime(2025, 1, 1),
    user_id="analyst",
    event_type="playbook_created"
)

# Save to file
import json
with open('audit_export.json', 'w') as f:
    json.dump(logs, f, indent=2)

print(f"✓ Exported {len(logs)} audit log entries")
```

### Example: Policy Evaluation

```python
from policy_engine import PolicyEngine

engine = PolicyEngine()

# Test blocking localhost (should be denied)
result = engine.evaluate({
    'action': 'block_ip',
    'target': '127.0.0.1',
    'environment': 'production'
})

print(f"Decision: {result.decision.value}")
# Output: DENY

print(f"Reasons: {result.reasons}")
# Output: ["Cannot block reserved/loopback IP: 127.0.0.1"]

# Test blocking private IP (should require approval)
result = engine.evaluate({
    'action': 'block_ip',
    'target': '192.168.1.100',
    'environment': 'production'
})

print(f"Decision: {result.decision.value}")
# Output: REQUIRE_APPROVAL

print(f"Requires approval: {result.requires_approval}")
# Output: True
```

---

## Default Users & Roles

After setup, these users are available:

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| admin | admin_password_change_me | ADMIN | All permissions |
| analyst | analyst_password | ANALYST | Create playbooks, request approvals |
| approver | approver_password | APPROVER | Approve/reject playbooks |
| executor | executor_password | EXECUTOR | Execute approved playbooks |

⚠️ **SECURITY WARNING**: Change all default passwords immediately in production!

```python
# Change password
from auth_rbac import AuthManager

auth = AuthManager(db)
admin = auth.authenticate_local("admin", "admin_password_change_me")

# TODO: Implement password change method
# auth.change_password(admin, "new_secure_password")
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│              Application Layer                      │
│  (Flask API / Web Interface / CLI)                  │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│          Approval Workflow Manager                  │
│  ┌────────────┬──────────────┬──────────────────┐  │
│  │ Policy     │ Auth/RBAC    │ Crypto Signing   │  │
│  │ Engine     │ Manager      │ Module           │  │
│  └────────────┴──────────────┴──────────────────┘  │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│         PostgreSQL Database (Persistent)            │
│  ┌──────────────────────────────────────────────┐  │
│  │ Playbooks │ Approvals │ Audit Logs │ Users  │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Key Features Explained

### 1. Dry-Run Default

**All new playbooks start in dry-run mode**. This simulates the execution without actually performing actions.

- Validates all targets
- Checks policies
- Estimates impact
- Stores results for review

Only after successful dry-run and approval can playbooks be executed.

### 2. Approval Gating

**Destructive actions require explicit approval** from users with APPROVER role.

Policies automatically determine when approval is needed:
- Production environment actions
- Private IP blocking
- High-risk operations (user suspension, agent isolation)

### 3. Cryptographic Proof

**Every action is cryptographically signed**:
- Playbook creation signed by analyst
- Approval decision signed by approver
- Audit logs signed and chained

This creates an **immutable, tamper-evident trail** showing:
- **Who** performed the action
- **What** was done
- **When** it occurred
- **Cryptographic proof** it wasn't tampered with

### 4. Policy-as-Code

**Policies are code**, not configuration:

```python
class CustomPolicyRule(PolicyRule):
    def evaluate(self, context):
        # Your business logic here
        if should_deny:
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reasons=["Custom rule triggered"]
            )
        return None

engine.add_rule(CustomPolicyRule())
```

This makes policies:
- **Testable** - Unit test your security policies
- **Reviewable** - Code review for policy changes
- **Versioned** - Track policy changes in git

---

## File Structure

New enterprise files:

```
SOC ai agents/
├── database.py                    # PostgreSQL models & manager
├── auth_rbac.py                   # Authentication & RBAC
├── crypto_signing.py              # Cryptographic signing
├── policy_engine.py               # Policy-as-code engine
├── approval_workflow.py           # Approval workflow manager
├── setup_database.py              # Database setup script
├── requirements_enterprise.txt    # Enterprise dependencies
├── ENTERPRISE_FEATURES.md         # Full documentation
└── ENTERPRISE_SETUP_GUIDE.md      # This file
```

---

## Migration from Basic to Enterprise

If you have an existing SOC AI Agents installation:

1. **Backup your data** (if any)
2. **Install PostgreSQL** (see above)
3. **Install new dependencies**: `pip install -r requirements_enterprise.txt`
4. **Run database setup**: `python setup_database.py setup`
5. **Update your code** to use workflow manager instead of direct remediator

**Before (basic):**
```python
from remediator import Remediator

rem = Remediator()
rem.execute_action("block_ip", "192.168.1.100")
```

**After (enterprise):**
```python
from approval_workflow import ApprovalWorkflowManager

# Create playbook
playbook = workflow.create_playbook(
    auth_context=analyst,
    action="block_ip",
    target="192.168.1.100",
    ...
)

# Dry-run
workflow.execute_dry_run(analyst, playbook.id)

# Approve
workflow.approve_playbook(approver, playbook.id)

# Execute (after approval)
remediator.execute_playbook(executor, playbook.id)
```

---

## Production Deployment Checklist

- [ ] PostgreSQL installed and secured
- [ ] Database backups configured
- [ ] All default passwords changed
- [ ] HTTPS/TLS enabled
- [ ] Environment variables configured
- [ ] Log rotation set up
- [ ] Monitoring and alerting configured
- [ ] OIDC configured (if using)
- [ ] Policy rules reviewed and customized
- [ ] Approval workflow tested
- [ ] Disaster recovery plan documented
- [ ] Security audit performed

---

## Troubleshooting

### Database Connection Failed

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -h localhost -U soc -d soc_db

# Check logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

### Permission Denied Errors

```python
# Check user role
from auth_rbac import AuthManager

auth = AuthManager(db)
user = auth.authenticate_local("username", "password")
print(f"Role: {user.role.value}")
print(f"Permissions: {[f'{p.resource}:{p.action}' for p in user.permissions]}")
```

### Policy Denying Actions

```python
# Debug policy evaluation
from policy_engine import PolicyEngine

engine = PolicyEngine()
result = engine.evaluate(context)

print(f"Decision: {result.decision.value}")
print(f"Matched policies: {result.matched_policies}")
print(f"Reasons: {result.reasons}")
```

---

## Next Steps

1. **Read full documentation**: [ENTERPRISE_FEATURES.md](./ENTERPRISE_FEATURES.md)
2. **Customize policies**: Edit `policy_engine.py` or add custom rules
3. **Configure OIDC**: For enterprise SSO integration
4. **Set up monitoring**: Track playbook executions and approvals
5. **Create custom roles**: Add fine-grained permissions as needed

---

## Support & Questions

- **Documentation**: See [ENTERPRISE_FEATURES.md](./ENTERPRISE_FEATURES.md)
- **Examples**: Check examples in each module's `__main__` section
- **Logs**: Review application logs for detailed error messages
- **Audit Trail**: Query audit_logs table for complete history

---

**🎉 You're ready to run a production-grade SOC with enterprise security!**
