# TIGRESS Dockerfile
# Multi-stage build for optimized container size

# Build stage
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Runtime stage
FROM python:3.12-slim

WORKDIR /app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash tigress

# Copy installed packages from builder
COPY --from=builder /root/.local /home/tigress/.local

# Make sure scripts in .local are usable
ENV PATH=/home/tigress/.local/bin:$PATH

# Copy application code
COPY . .

# Set ownership
RUN chown -R tigress:tigress /app

# Switch to non-root user
USER tigress

# Create necessary directories
RUN mkdir -p /app/data /app/models /app/config /app/logs

# Set environment variables
ENV PYTHONPATH=/app
ENV TIGRESS_POSTURE=normal
ENV TIGRESS_API_TOKEN=""

# Expose dashboard port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health').raise_for_status()" || exit 1

# Default command (can be overridden)
CMD ["python", "-m", "src.dashboard.app"]

# Alternative: Run with uvicorn directly for better performance
# CMD ["uvicorn", "src.dashboard.app:app", "--host", "0.0.0.0", "--port", "8080"]
