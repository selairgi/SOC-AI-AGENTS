# Requirements Installation Guide

This project uses split requirements files to optimize installation size and deployment flexibility.

## 📦 Requirements Files Overview

### Production Deployment
- **`requirements-base.txt`** (~150MB)
  - Core dependencies for production deployment
  - Includes lightweight ML (numpy, scikit-learn) for intelligent detection
  - **Use for**: Docker production builds, cloud deployments
  - **Install**: `pip install -r requirements-base.txt`

### Development & Testing
- **`requirements-ml.txt`** (~2.3GB additional)
  - Heavy ML dependencies (torch, sentence-transformers)
  - Only needed for semantic detector testing
  - **Use for**: Local development, running full test suite
  - **Install**: `pip install -r requirements-base.txt -r requirements-ml.txt`

### Full Installation (Legacy)
- **`requirements.txt`**
  - Includes ALL dependencies (base + ML + cloud SDKs)
  - **Use for**: Quick local setup without optimization
  - **Install**: `pip install -r requirements.txt`

---

## 🚀 Installation Scenarios

### Scenario 1: Production Docker Deployment (Recommended)
```bash
# Smallest footprint - only essential dependencies
pip install -r requirements-base.txt
```
**Size**: ~150MB
**Use case**: Production web application

### Scenario 2: Development with ML Testing
```bash
# Base + ML dependencies for semantic detector testing
pip install -r requirements-base.txt -r requirements-ml.txt
```
**Size**: ~2.5GB
**Use case**: Local development, running semantic_detector tests

### Scenario 3: Full Installation (All Features)
```bash
# Everything including cloud provider SDKs
pip install -r requirements.txt
```
**Size**: ~3GB
**Use case**: Full feature development, cloud integration testing

---

## 🔍 What's Included Where?

### requirements-base.txt (Production)
✅ Web framework (Flask, SocketIO)
✅ AI integration (OpenAI client)
✅ Database (SQLAlchemy, psycopg2-binary)
✅ Caching (Redis)
✅ Lightweight ML (numpy, scikit-learn)
✅ Monitoring (prometheus-client)
✅ Intelligent prompt detection (no PyTorch required)

❌ PyTorch
❌ Sentence Transformers
❌ Semantic Detector

### requirements-ml.txt (Development/Testing)
✅ PyTorch (~2GB)
✅ Sentence Transformers (~300MB)
✅ Semantic detection capabilities

**Note**: These are ONLY used in `tests/test_semantic_detector.py` and `security/semantic_detector.py` (not in production)

### requirements.txt (Full)
✅ Everything from requirements-base.txt
✅ Everything from requirements-ml.txt
✅ Cloud provider SDKs (AWS, GCP, Azure)
✅ Advanced Redis clustering
✅ Alternative PostgreSQL drivers

---

## 🐳 Docker Configuration

### Current Setup
The web Dockerfile currently uses `web/requirements.txt` which is lightweight (no ML dependencies).

### Recommended Updates
For production optimization, update Dockerfiles to use requirements-base.txt:

```dockerfile
# web/Dockerfile
COPY requirements-base.txt .
RUN pip install --no-cache-dir -r requirements-base.txt
```

### Multi-stage Build (Advanced)
```dockerfile
# Development stage with ML
FROM python:3.11-slim AS development
COPY requirements-base.txt requirements-ml.txt ./
RUN pip install -r requirements-base.txt -r requirements-ml.txt

# Production stage (lightweight)
FROM python:3.11-slim AS production
COPY requirements-base.txt .
RUN pip install -r requirements-base.txt
```

---

## 📊 Size Comparison

| Installation Type | Size | Install Time | Use Case |
|-------------------|------|--------------|----------|
| **requirements-base.txt** | ~150MB | ~2 min | ✅ Production |
| **requirements-ml.txt** (additional) | ~2.3GB | ~15 min | Development/Testing |
| **requirements.txt** (full) | ~3GB | ~20 min | Full features |

---

## 🧪 Testing

### Running Tests Without ML Dependencies
```bash
# Install base requirements
pip install -r requirements-base.txt

# Run tests (excluding semantic detector tests)
pytest -v --ignore=tests/test_semantic_detector.py
```

### Running Full Test Suite
```bash
# Install base + ML requirements
pip install -r requirements-base.txt -r requirements-ml.txt

# Run all tests including semantic detector
pytest -v
```

---

## ❓ FAQ

**Q: Why split requirements?**
A: PyTorch and sentence-transformers add ~2.3GB but are only used in test files. Production deployments don't need them.

**Q: Will production intelligent detection still work?**
A: Yes! The production system uses `intelligent_prompt_detector.py` which only needs numpy and scikit-learn (included in requirements-base.txt).

**Q: When do I need requirements-ml.txt?**
A: Only when developing/testing the semantic detector module or running the full test suite.

**Q: Can I still use requirements.txt?**
A: Yes! It's maintained for backwards compatibility and local development convenience.

---

## 🔄 Migration Path

### For Existing Deployments
1. Current deployment using `requirements.txt` works fine
2. To optimize, switch to `requirements-base.txt` in next deployment
3. Update Dockerfile: `COPY requirements-base.txt .`
4. Rebuild Docker image: `docker-compose build`
5. Restart services: `docker-compose up -d`

### For New Deployments
Start with `requirements-base.txt` for optimal size and speed.

---

**Last Updated**: 2025-12-14
**Maintained By**: SOC AI Agents Team
