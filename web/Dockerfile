FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
# Added build-essential for ML libraries compilation
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    build-essential \
    ca-certificates \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (better Docker layer caching)
COPY web/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy web application
COPY web/ /app/

# Copy all required modules (context is project root)
COPY shared/ /app/shared/
COPY security/ /app/security/
COPY core/ /app/core/
COPY ai/ /app/ai/
COPY enterprise/ /app/enterprise/
COPY prompt_sleuth/ /app/prompt_sleuth/

# Set PYTHONPATH to include app directory
ENV PYTHONPATH=/app

# Create necessary directories
RUN mkdir -p /app/logs && chmod 755 /app/logs
RUN mkdir -p /app/security/.cache && chmod 755 /app/security/.cache

# V7.1: Copy pre-trained ML models (if they exist)
# These are optional - pipeline will work without them but with reduced accuracy
# To include models: build with `docker build --build-arg COPY_ML_MODELS=true`
ARG COPY_ML_MODELS=false
RUN if [ "$COPY_ML_MODELS" = "true" ] && [ -f security/.cache/xgb_model.pkl ]; then \
        echo "Copying ML models..."; \
    else \
        echo "ML models not found or COPY_ML_MODELS=false. Pipeline will train on first run."; \
    fi

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


