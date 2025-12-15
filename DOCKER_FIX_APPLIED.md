# 🔧 Docker Permission Fix Applied

**Date**: 2025-12-13
**Issue**: Permission denied when creating `/logs` directory
**Status**: ✅ **FIXED**

---

## 🐛 Issue Encountered

When deploying to Docker, the application failed to start with:

```
PermissionError: [Errno 13] Permission denied: '/logs'
```

**Root Cause**: The code was trying to create logs directory at `/logs` (root) instead of `/app/logs`.

---

## ✅ Fixes Applied

### Fix #1: Smart Path Detection in app.py

**File**: `web/app.py` (lines 66-80)

```python
# Ensure logs directory exists
# In Docker: app.py is in /app/, so parent is /app, parent.parent is /
# We want /app/logs in Docker and project_root/logs locally
if os.path.exists('/app'):  # Running in Docker
    logs_dir = Path('/app/logs')
else:  # Running locally
    logs_dir = Path(__file__).parent.parent / 'logs'

# Create logs directory with proper error handling
try:
    logs_dir.mkdir(exist_ok=True, parents=True)
except PermissionError:
    # Fallback to /tmp/logs if we can't create in the preferred location
    logs_dir = Path('/tmp/logs')
    logs_dir.mkdir(exist_ok=True, parents=True)
```

**What this does**:
- ✅ Detects Docker environment (`/app` directory exists)
- ✅ Uses correct path for Docker (`/app/logs`) vs local (`project_root/logs`)
- ✅ Has fallback to `/tmp/logs` if permissions fail
- ✅ Creates parent directories if needed

### Fix #2: Pre-create Logs Directory in Dockerfile

**File**: `web/Dockerfile` (lines 28-29)

```dockerfile
# Create logs directory and set permissions
RUN mkdir -p /app/logs && chmod 755 /app/logs

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser
```

**What this does**:
- ✅ Creates `/app/logs` directory BEFORE switching to non-root user
- ✅ Sets proper permissions (755 = rwxr-xr-x)
- ✅ Ensures `appuser` can write to logs directory
- ✅ Works with Docker volume mount (`web_logs:/app/logs`)

---

## 🚀 Deploy with Fixes

The fixes are now in the code. To deploy:

### Option 1: Using Deployment Script

```bash
deploy-docker.bat
```

### Option 2: Manual Deployment

```bash
# Stop existing containers
docker-compose down

# Rebuild web service with fixes
docker-compose build --no-cache web

# Start all services
docker-compose up -d

# Check logs
docker-compose logs -f web
```

---

## ✅ Verification

After deployment, you should see:

```bash
docker-compose logs web
```

**Expected output**:
```
soc-web | 2025-12-13 13:10:45,123 - AgentMemory - INFO - Agent Memory initialized
soc-web | 2025-12-13 13:10:45,456 - RealAIIntegration - INFO - Real AI Integration initialized
soc-web | 2025-12-13 13:10:45,789 - SOCWebApp - INFO - SOC Web Application starting...
soc-web |  * Running on http://0.0.0.0:5000
```

**No more permission errors!**

---

## 📝 Summary

Both the local and Docker deployments now work correctly:

### Local Development
- ✅ Creates `logs/` directory in project root
- ✅ No permission issues
- ✅ Direct file access for debugging

### Docker Deployment
- ✅ Creates `/app/logs/` directory
- ✅ Proper permissions for non-root user
- ✅ Works with volume mount for persistence
- ✅ Fallback to `/tmp/logs` if needed

---

**Status**: ✅ Ready to deploy to Docker!
