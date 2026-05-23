#!/usr/bin/env bash
# Builds the rinha-asm image locally for profiling.  The reference corpus is
# downloaded inside the Dockerfile (stage 1) from the upstream Rinha repo, so
# the build context is just the source tree — no side-channel copy.

set -euo pipefail
cd "$(dirname "$0")/.."

docker build -t rinha-asm:latest .

echo
echo "image built: rinha-asm:latest"
docker image inspect rinha-asm:latest --format 'size: {{.Size}} bytes' 2>/dev/null || true
