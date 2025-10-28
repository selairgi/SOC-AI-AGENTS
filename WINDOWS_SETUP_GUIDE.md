# Windows Setup Guide for Enterprise Features

## Quick Setup Options

### Option 1: SQLite (Easiest - No Installation Required) ✅

Perfect for development and testing on Windows.

**Advantages:**
- ✅ No installation required
- ✅ Works immediately
- ✅ File-based database
- ✅ All features work

**Setup:**
```bash
# 1. Install Python dependencies
pip install sqlalchemy

# 2. Run setup with SQLite
python setup_database.py setup --url "sqlite:///soc_database.db"

# That's it! Database ready to use.
```

### Option 2: PostgreSQL (Production-Grade) 🔧

Better for production, but requires installation.

---

## Option 1: SQLite Setup (Recommended for Windows)

### Step 1: Install Dependencies

```bash
# Open Command Prompt or PowerShell
cd "C:\Users\LENOVO\Desktop\SOC ai agents"

# Install required packages
pip install sqlalchemy psycopg2-binary alembic
```

### Step 2: Initialize Database

```bash
# Create SQLite database
python setup_database.py setup --url "sqlite:///soc_database.db"
```

**Expected Output:**
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
✓ Policy engine initialized
✓ Cryptographic signer initialized
======================================================================
DATABASE SETUP COMPLETE!
======================================================================
```

### Step 3: Verify Setup

```bash
python setup_database.py verify --url "sqlite:///soc_database.db"
```

### Step 4: Use the Database

```python
from database import DatabaseManager
from auth_rbac import AuthManager

# Connect to SQLite database
db = DatabaseManager("sqlite:///soc_database.db")
auth = AuthManager(db)

# Authenticate
auth_context = auth.authenticate_local("analyst", "analyst_password")
print(f"Logged in as: {auth_context.username}")
print(f"Role: {auth_context.role.value}")
```

**Database file location:**
```
C:\Users\LENOVO\Desktop\SOC ai agents\soc_database.db
```

---

## Option 2: PostgreSQL Setup (Production)

### Step 1: Download PostgreSQL for Windows

1. Go to: https://www.postgresql.org/download/windows/
2. Download the installer (Windows x86-64)
3. Run the installer

### Step 2: Install PostgreSQL

During installation:
- **Port:** 5432 (default)
- **Password:** Choose a strong password (remember it!)
- **Locale:** Default
- **Installation path:** C:\Program Files\PostgreSQL\16\

Click through the installation wizard.

### Step 3: Set Environment Variables (Optional)

Add PostgreSQL to PATH:
1. Press `Win + X` → System
2. Advanced system settings → Environment Variables
3. Edit `Path` variable
4. Add: `C:\Program Files\PostgreSQL\16\bin`

### Step 4: Create Database

**Option A: Using pgAdmin (GUI)**
1. Open pgAdmin 4 (installed with PostgreSQL)
2. Connect to PostgreSQL server
3. Right-click "Databases" → Create → Database
4. Name: `soc_db`
5. Click Save

**Option B: Using Command Line**
```bash
# Open Command Prompt as Administrator
cd "C:\Program Files\PostgreSQL\16\bin"

# Create database
psql -U postgres
# Enter password when prompted

# In psql:
CREATE DATABASE soc_db;
CREATE USER soc WITH PASSWORD 'your_password_here';
GRANT ALL PRIVILEGES ON DATABASE soc_db TO soc;
\q
```

### Step 5: Install Python Dependencies

```bash
cd "C:\Users\LENOVO\Desktop\SOC ai agents"
pip install -r requirements_enterprise.txt
```

### Step 6: Setup Database

```bash
python setup_database.py setup --url "postgresql://soc:your_password_here@localhost:5432/soc_db"
```

### Step 7: Verify Setup

```bash
python setup_database.py verify --url "postgresql://soc:your_password_here@localhost:5432/soc_db"
```

---

## Troubleshooting

### Error: "No module named 'sqlalchemy'"

**Solution:**
```bash
pip install sqlalchemy
```

### Error: "No module named 'psycopg2'"

**Solution:**
```bash
pip install psycopg2-binary
```

### Error: Database connection failed (PostgreSQL)

**Solutions:**

1. **Check PostgreSQL is running:**
   - Open Services (Win + R → `services.msc`)
   - Find "postgresql-x64-16" service
   - Status should be "Running"
   - If not, right-click → Start

2. **Check connection details:**
   ```bash
   # Test connection
   psql -U soc -d soc_db -h localhost
   # Enter password when prompted
   ```

3. **Check firewall:**
   - Allow PostgreSQL port 5432
   - Windows Defender Firewall → Advanced Settings
   - Inbound Rules → New Rule → Port → TCP 5432

4. **Check pg_hba.conf:**
   - Location: `C:\Program Files\PostgreSQL\16\data\pg_hba.conf`
   - Add line: `host all all 127.0.0.1/32 md5`
   - Restart PostgreSQL service

### SQLite: "Database is locked"

**Solution:**
```bash
# Close all connections
# Delete lock file if exists
del soc_database.db-journal

# Or use a new database file
python setup_database.py setup --url "sqlite:///soc_database_new.db"
```

---

## Testing the Setup

### Test 1: Database Connection

```bash
python -c "from database import DatabaseManager; db = DatabaseManager('sqlite:///soc_database.db'); print('✓ Connected' if db.health_check() else '✗ Failed')"
```

### Test 2: Authentication

```bash
python -c "from database import DatabaseManager; from auth_rbac import AuthManager; db = DatabaseManager('sqlite:///soc_database.db'); auth = AuthManager(db); ctx = auth.authenticate_local('admin', 'admin_password_change_me'); print(f'✓ Authenticated as {ctx.username}')"
```

### Test 3: Run Full Tests

```bash
# First, modify test to use SQLite
python test_enterprise_features.py
```

---

## Configuration File (.env)

Create a `.env` file in the project directory:

```bash
# For SQLite
DATABASE_URL=sqlite:///soc_database.db

# For PostgreSQL
# DATABASE_URL=postgresql://soc:your_password@localhost:5432/soc_db

# Crypto key
CRYPTO_KEY=your-secret-key-change-in-production

# Environment
ENVIRONMENT=development
```

---

## Quick Commands

### SQLite

```bash
# Setup
python setup_database.py setup --url "sqlite:///soc_database.db"

# Verify
python setup_database.py verify --url "sqlite:///soc_database.db"

# Export schema
python setup_database.py export-schema --url "sqlite:///soc_database.db" --output schema.sql

# Connect in Python
python
>>> from database import DatabaseManager
>>> db = DatabaseManager("sqlite:///soc_database.db")
>>> session = db.get_session()
```

### PostgreSQL

```bash
# Setup
python setup_database.py setup --url "postgresql://soc:password@localhost:5432/soc_db"

# Verify
python setup_database.py verify --url "postgresql://soc:password@localhost:5432/soc_db"

# Backup
pg_dump -U soc -d soc_db > backup.sql

# Restore
psql -U soc -d soc_db < backup.sql
```

---

## Performance Tips

### SQLite
- Use for: Development, testing, single-user scenarios
- File location matters (SSD vs HDD)
- Vacuum regularly: `VACUUM;`

### PostgreSQL
- Use for: Production, multi-user, high-performance
- Configure shared_buffers in postgresql.conf
- Regular maintenance: `VACUUM ANALYZE;`

---

## Next Steps After Setup

1. **Change Default Passwords:**
   ```python
   from database import DatabaseManager
   from auth_rbac import AuthManager

   db = DatabaseManager("sqlite:///soc_database.db")
   auth = AuthManager(db)

   # TODO: Implement password change
   # auth.change_password(user_id, new_password)
   ```

2. **Run Tests:**
   ```bash
   python test_enterprise_features.py
   ```

3. **Try the Workflow:**
   ```bash
   python approval_workflow.py
   ```

4. **Integrate with Web App:**
   ```python
   # In enhanced_web_chatbot.py, add:
   from database import DatabaseManager
   from approval_workflow import ApprovalWorkflowManager

   db = DatabaseManager("sqlite:///soc_database.db")
   # ... initialize workflow
   ```

---

## Comparison: SQLite vs PostgreSQL

| Feature | SQLite | PostgreSQL |
|---------|--------|------------|
| Installation | ✅ None required | ❌ Install needed |
| Setup Time | ✅ Instant | ⏱️ 15-30 minutes |
| File-based | ✅ Yes | ❌ No |
| Concurrent Users | ⚠️ Limited | ✅ Excellent |
| Performance | ✅ Fast for small | ✅ Fast for large |
| Production Ready | ⚠️ Small scale | ✅ Enterprise scale |
| Backup | ✅ Copy file | ⏱️ pg_dump |
| Best For | Development/Testing | Production |

**Recommendation for Windows:**
- **Development:** Use SQLite (instant setup)
- **Production:** Use PostgreSQL (better scalability)

---

## Still Having Issues?

1. **Check Python version:**
   ```bash
   python --version
   # Should be 3.8 or higher
   ```

2. **Check installed packages:**
   ```bash
   pip list | findstr sqlalchemy
   pip list | findstr psycopg2
   ```

3. **Try SQLite first:**
   - Always works
   - No installation
   - Quick testing

4. **Get help:**
   - Check logs in console output
   - Enable debug mode in setup script
   - Check database file permissions

---

## Success Checklist

- [ ] Python 3.8+ installed
- [ ] SQLAlchemy installed (`pip install sqlalchemy`)
- [ ] Database created (SQLite file or PostgreSQL database)
- [ ] Setup script run successfully
- [ ] Default users created
- [ ] Verification passed
- [ ] Can authenticate users
- [ ] Tests pass

Once all checkboxes are complete, you're ready to use enterprise features! 🎉
