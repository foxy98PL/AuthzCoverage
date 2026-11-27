#!/usr/bin/env bash
# Records the scripted tenantshop session into testdata/raw/tenantshop.har (git-ignored).
# Usage: e2e/recorders/tenantshop.sh     (expects tenantshop on http://localhost:8090,
#        e.g. `docker compose -f e2e/apps/tenantshop/compose.yaml up -d`, or BASE=... for another address)
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO/e2e/apps/tenantshop"
go run ./cmd/record -base "${BASE:-http://localhost:8090}" -out "$REPO/testdata/raw/tenantshop.har"

echo "next: authzcov coverage --spec e2e/apps/tenantshop/shop/openapi.yaml --identities e2e/apps/tenantshop/identities.yaml --har testdata/raw/tenantshop.har"
