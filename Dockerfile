# ============================================
# Stage 1: Builder - Install dependencies
# ============================================
FROM python:3.11-slim AS builder

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install -r requirements.txt && \
    rm -rf /root/.cache/pip


# ============================================
# Stage 2: Runtime - Production image
# ============================================
FROM python:3.11-slim

# Set timezone to UTC (CRITICAL)
ENV TZ=UTC

WORKDIR /app

# Install system dependencies: cron and timezone tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cron \
        tzdata && \
    ln -snf /usr/share/zoneinfo/UTC /etc/localtime && \
    echo "UTC" > /etc/timezone && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder stage
COPY --from=builder /install /usr/local
ENV PYTHONPATH=/usr/local

# Copy application code
COPY app ./app
COPY scripts ./scripts
COPY cron ./cron

# Copy cryptographic keys (required for decryption and signing)
COPY student_private.pem .
COPY student_public.pem .
COPY instructor_public.pem .

# Make cron script executable
RUN chmod +x scripts/log_2fa_cron.py

# Install cron job
RUN cp cron/2fa-cron /etc/cron.d/2fa-cron && \
    chmod 0644 /etc/cron.d/2fa-cron && \
    crontab /etc/cron.d/2fa-cron

# Create volume mount points
RUN mkdir -p /data /cron && \
    chmod 755 /data /cron

# Define volumes for persistent storage
VOLUME ["/data", "/cron"]

# Expose API port
EXPOSE 8080

# Start cron daemon and API server
CMD ["sh", "-c", "cron && uvicorn app.main:app --host 0.0.0.0 --port 8080"]
