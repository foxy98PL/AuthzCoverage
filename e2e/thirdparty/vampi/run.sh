#!/usr/bin/env bash
# Runs the VAmPI evaluation (needs docker + go). Writes eval/results/vampi.json.
# Pulls the pinned image digest, starts vulnerable=1 and vulnerable=0 containers
# on free localhost ports, records HARs with the scripted recorder, runs
# authzcov (built from source into a temp dir) and prints the summary.
# Containers use --rm and are removed afterwards; HARs live in a temp dir.
# Only for the public demo app VAmPI.
set -euo pipefail
cd "$(dirname "$0")"
IMAGE=$(grep -o 'erev0s/vampi@sha256:[0-9a-f]*' main.go | head -1)
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE" >&2
exec go run . "$@"
