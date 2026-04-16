#!/usr/bin/env bash
# Provision a new per-tenant Postgres schema.
#
# Usage: scripts/tenant-provision.sh <tenant_id>
# Requires: DATABASE_URL env var (default: postgres://wick:wick@localhost:5432/wick)
#
# This script is the ops-level equivalent of the programmatic provisioning
# that wick-server performs automatically via the CreateTenant gRPC call.
# Use this for manual recovery or CI seed operations.
#
# The tenant schema name is derived as: tenant_<tenant_id>

set -euo pipefail

TENANT_ID="${1:-}"
DATABASE_URL="${DATABASE_URL:-postgres://wick:wick@localhost:5432/wick}"
TEMPLATE="migrations/tenant_template/0001_init.sql"

if [[ -z "$TENANT_ID" ]]; then
    echo "Usage: $0 <tenant_id>"
    exit 1
fi

# Validate: tenant_id must be pure digits.
if ! [[ "$TENANT_ID" =~ ^[0-9]+$ ]]; then
    echo "Error: tenant_id must be a positive integer, got: '$TENANT_ID'"
    exit 1
fi

SCHEMA="tenant_${TENANT_ID}"

echo "Provisioning schema '$SCHEMA' in ${DATABASE_URL%%@*}@..."

if [[ ! -f "$TEMPLATE" ]]; then
    echo "Error: migration template not found at $TEMPLATE"
    echo "Run this script from the wick-cloud workspace root."
    exit 1
fi

# Substitute the {{SCHEMA}} placeholder and execute.
SQL=$(sed "s/{{SCHEMA}}/${SCHEMA}/g" "$TEMPLATE")

psql "$DATABASE_URL" -c "CREATE SCHEMA IF NOT EXISTS \"${SCHEMA}\"" \
    && echo "$SQL" | psql "$DATABASE_URL" \
    && echo "Done: schema '$SCHEMA' provisioned."
