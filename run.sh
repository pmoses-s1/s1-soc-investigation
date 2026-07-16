#!/usr/bin/env bash
# One-command launcher. Pulls and runs the published image, publishes to the host
# loopback only, and mounts ./investigations as the output folder. If a .env exists
# it is loaded automatically.
#
#   ./run.sh                 # http://localhost:8901
#   S1IE_HOST_PORT=9000 ./run.sh
#   S1IE_OUT=/data/cases ./run.sh
set -euo pipefail

IMAGE="${S1IE_IMAGE:-ghcr.io/pmoses-s1/s1-soc-investigation:latest}"
HOST_PORT="${S1IE_HOST_PORT:-8901}"
OUT="${S1IE_OUT:-$(pwd)/investigations}"
mkdir -p "$OUT"

ENVFILE=()
[ -f .env ] && ENVFILE=(--env-file .env)

echo "s1-soc-investigation -> http://localhost:${HOST_PORT}   (output: ${OUT})"
exec docker run --rm -p "127.0.0.1:${HOST_PORT}:8801" \
  -v "${OUT}:/data" "${ENVFILE[@]}" "$IMAGE"
