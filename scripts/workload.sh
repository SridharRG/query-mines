#!/usr/bin/env bash
# Generate a steady demo workload against the Docker Postgres so the dashboard
# and pg_stat_statements have data. Usage: scripts/workload.sh [seconds] [tps]
set -euo pipefail
SECONDS_TO_RUN="${1:-900}"
RATE="${2:-15}"
exec docker exec qm-postgres pgbench -n -U qm -d schooldb -c 4 -j 2 -R "$RATE" -T "$SECONDS_TO_RUN" -f /workload/workload.sql
