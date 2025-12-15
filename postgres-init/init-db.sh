#!/bin/bash
set -e

# This script ensures the database exists
# It's called by PostgreSQL's docker-entrypoint-initdb.d mechanism

# The database should already be created by POSTGRES_DB, but this ensures it exists
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Database should already exist, but ensure it's ready
    SELECT 1;
EOSQL

echo "Database initialization complete"
