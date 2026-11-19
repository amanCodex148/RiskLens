# ==============================================================================
# RiskLens Platform - Containerfile / Dockerfile
# Production-ready, secure, lightweight container for Continuous Cyber Risk
# Quantification & Investment Optimization Platform (PostgreSQL-backed)
# ==============================================================================

# Base image: Official Python 3.12 Debian slim
FROM python:3.12-slim AS runtime

# Set operational environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PORT=8000 \
    HOST=0.0.0.0 \
    WORKERS=2 \
    RISKLENS_ENV=production \
    RISKLENS_DATA_DIR=/app/data \
    DATABASE_URL=postgresql://risklens:risklens_password@postgres:5432/risklens \
    POSTGRES_HOST=postgres \
    POSTGRES_PORT=5432 \
    POSTGRES_DB=risklens \
    POSTGRES_USER=risklens \
    POSTGRES_PASSWORD=risklens_password

# Set container working directory
WORKDIR /app

# Install security updates, curl for health check, and postgresql-client for pg_isready
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root risklens system user and group
RUN groupadd --gid 10001 risklens \
    && useradd --uid 10001 --gid risklens --shell /bin/false --no-create-home risklens

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt /app/requirements.txt

# Install production Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# Copy application source directories
COPY backend /app/backend
COPY frontend /app/frontend
COPY tests /app/tests
COPY data /app/data
COPY scripts /app/scripts

# Ensure persistent data directory exists and assign ownership to risklens user
RUN mkdir -p /app/data \
    && chown -R risklens:risklens /app

# Switch to unprivileged non-root user
USER risklens

# Expose HTTP port
EXPOSE 8000

# Declare persistent volume mount point for telemetry data and exported reports
VOLUME ["/app/data"]

# Container healthcheck using liveness probe endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/health || exit 1

# Launch RiskLens application using Gunicorn process supervisor with Uvicorn workers
CMD ["sh", "-c", "exec gunicorn backend.main:app -w ${WORKERS:-2} -k uvicorn.workers.UvicornWorker --bind ${HOST:-0.0.0.0}:${PORT:-8000} --access-logfile - --error-logfile -"]
