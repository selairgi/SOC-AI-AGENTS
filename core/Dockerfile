FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    ca-certificates \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY core/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (context is project root)
COPY core/ /app/core/
COPY shared/ /app/shared/
COPY security/ /app/security/
COPY enterprise/ /app/enterprise/

# Set PYTHONPATH
ENV PYTHONPATH=/app

# Create non-root user
# RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
# USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Run application as a module
CMD ["python", "-m", "core.main"]


