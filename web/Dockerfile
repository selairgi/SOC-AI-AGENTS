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
COPY web/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir redis>=4.0.0

# Copy web application
COPY web/ /app/

# Copy all required modules (context is project root)
COPY shared/ /app/shared/
COPY security/ /app/security/
COPY core/ /app/core/
COPY ai/ /app/ai/
COPY enterprise/ /app/enterprise/

# Set PYTHONPATH to include app directory
ENV PYTHONPATH=/app

# Create logs directory and set permissions
RUN mkdir -p /app/logs && chmod 755 /app/logs

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')" || exit 1

# Run application
CMD ["python", "app.py"]


