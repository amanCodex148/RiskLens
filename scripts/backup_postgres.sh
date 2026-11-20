#!/usr/bin/env bash
# ==============================================================================
# RiskLens Platform - Automated PostgreSQL Backup & Disaster Recovery Script
# Performs compressed, timestamped database dumps and enforces retention policies.
#
# Usage:
#   ./scripts/backup_postgres.sh                  # Backs up to ./backups/
#   ./scripts/backup_postgres.sh /path/to/backups # Custom backup directory
# ==============================================================================
set -euo pipefail

BACKUP_DIR="${1:-./backups}"
RETENTION_DAYS=30
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/risklens_db_backup_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

POSTGRES_USER="${POSTGRES_USER:-risklens}"
POSTGRES_DB="${POSTGRES_DB:-risklens}"
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-risklens_password}"

echo "=========================================================="
echo " RiskLens PostgreSQL Backup"
echo " Timestamp: ${TIMESTAMP}"
echo " Destination: ${BACKUP_FILE}"
echo "=========================================================="

# 1. Check if running against a Docker container or native PostgreSQL
if docker ps --filter "name=risklens-postgres" --filter "status=running" -q | grep -q .; then
    echo "Backing up via active Docker container (risklens-postgres)..."
    docker exec -e PGPASSWORD="${POSTGRES_PASSWORD}" risklens-postgres \
        pg_dump -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" --clean --if-exists | gzip -9 > "${BACKUP_FILE}"
elif command -v pg_dump &> /dev/null; then
    echo "Backing up via native pg_dump client (${POSTGRES_HOST}:${POSTGRES_PORT})..."
    PGPASSWORD="${POSTGRES_PASSWORD}" pg_dump -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" --clean --if-exists | gzip -9 > "${BACKUP_FILE}"
else
    echo "Error: Neither active Docker container 'risklens-postgres' nor native 'pg_dump' was found."
    exit 1
fi

# 2. Verify backup file size and integrity
if [ -s "${BACKUP_FILE}" ]; then
    SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
    echo ">>> Backup completed successfully: ${BACKUP_FILE} (${SIZE})"
else
    echo "Error: Backup file was created but is empty."
    rm -f "${BACKUP_FILE}"
    exit 1
fi

# 3. Enforce backup retention policy (purge archives older than RETENTION_DAYS)
echo "Cleaning up backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "risklens_db_backup_*.sql.gz" -type f -mtime "+${RETENTION_DAYS}" -delete || true

echo "Backup operation finished successfully."
