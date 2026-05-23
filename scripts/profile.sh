#!/usr/bin/env bash
# Profile the asm-rinha stack under cgroup limits (≈ Mac Mini Late 2014):
# starts docker-compose, runs k6 full test, dumps results + memory/cpu stats.
#
# Usage:  ./scripts/profile.sh           — single full run
#         ./scripts/profile.sh 5         — 5 back-to-back runs

set -euo pipefail
cd "$(dirname "$0")/.."

RUNS="${1:-1}"
K6="${K6:-/tmp/k6}"
TEST_DIR="${TEST_DIR:-../rinha-de-backend-2026/test}"

if ! command -v "$K6" >/dev/null 2>&1; then
    echo "error: k6 not found at $K6 (set K6 env var or run scripts/get-k6.sh)" >&2
    exit 1
fi
if [ ! -f "$TEST_DIR/test.js" ]; then
    echo "error: rinha test.js not found at $TEST_DIR/test.js" >&2
    exit 1
fi

echo "==> docker compose up -d"
docker compose down -v 2>/dev/null || true
docker compose up -d

# Wait until the LB responds on port 9999 (or fail after 30 s).
echo "==> waiting for LB on :9999 ..."
for i in $(seq 1 60); do
    if curl -fsS --max-time 1 http://localhost:9999/ready >/dev/null 2>&1; then
        echo "    ready after ${i} probe(s)"
        break
    fi
    sleep 0.5
done

# Cgroup snapshot — what the containers are actually consuming.
echo
echo "==> container stats (snapshot):"
docker stats --no-stream rinha-asm-api1-1 rinha-asm-api2-1 rinha-asm-lb-1 \
    --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}'

# Drive the test.
for r in $(seq 1 "$RUNS"); do
    echo
    echo "==> k6 run $r/$RUNS"
    (cd "$TEST_DIR/.." && "$K6" run --quiet test/test.js 2>&1 | tail -2)
    cp "$TEST_DIR/results.json" "/tmp/profile-run-${r}.json"
    PVAL=$(python3 -c "import json; d=json.load(open('/tmp/profile-run-${r}.json')); print(d['p99'], d['scoring']['final_score'])" 2>/dev/null || echo "?")
    echo "    p99=$(echo $PVAL | cut -d' ' -f1)  score=$(echo $PVAL | cut -d' ' -f2)"
done

echo
echo "==> final container stats:"
docker stats --no-stream rinha-asm-api1-1 rinha-asm-api2-1 rinha-asm-lb-1 \
    --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'

# Optionally tear down.
if [ "${KEEP_UP:-0}" != "1" ]; then
    echo
    echo "==> docker compose down"
    docker compose down -v
fi
