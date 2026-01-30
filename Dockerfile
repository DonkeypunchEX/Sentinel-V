FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY sentinel_v/ ./sentinel_v/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Create directories for logs and data
RUN mkdir -p /app/logs /app/data

# Create non-root user
RUN useradd -m -u 1000 sentinel && \
    chown -R sentinel:sentinel /app
USER sentinel

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(('localhost', 8080))" || exit 1

# Expose monitoring port
EXPOSE 8080

# Default command
CMD ["python", "-m", "sentinel_v.cli", "start", "--config", "/app/config/sentinel.default.yaml"]
