#!/usr/bin/env bash
# Runs the RealWorld evaluation (needs docker with the compose plugin + go). Writes eval/results/realworld.json.
# Pulls the digest-pinned images of compose.yaml, then for each suite starts a fresh RealWorld stack
# (unique compose project, ports bound to 127.0.0.1, `docker compose down -v` afterwards), records
# HARs with the scripted recorder, runs authzcov (built from source into a temp dir) and prints the summary.
# Only for the public demo app RealWorld.
set -euo pipefail
cd "$(dirname "$0")"
for IMAGE in $(grep -o '[a-z0-9/._-]*@sha256:[0-9a-f]\{64\}' compose.yaml | sort -u); do
  docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE" >&2
done
# No exec: the trap must outlive go. The Go program tears its own stack down on exit and on SIGINT/SIGTERM;
# the trap is a backstop that removes any project of this run that is still left (e.g. after SIGKILL of go).
export RWEVAL_RUN=$$
cleanup() {
  for p in $(docker compose ls -a --format json 2>/dev/null | grep -o '"Name":"rweval-'"$$"'-[0-9-]*"' | cut -d'"' -f4); do
    docker compose -p "$p" down -v --remove-orphans --timeout 5 >/dev/null 2>&1 || echo "run.sh: teardown of $p failed; remove it by hand" >&2
  done
}
trap cleanup EXIT
trap 'exit 130' INT TERM
go run . "$@"
