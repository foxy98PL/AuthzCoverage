#!/usr/bin/env bash
# Records a VAmPI happy path through mitmdump into testdata/raw/vampi.har (git-ignored).
#
# Walk: createdb; register + log in alice and bob; each POSTs and reads their own book;
# each calls /me; alice updates her own email; one anonymous read of alice's book.
# Deliberately NO cross-user calls, so authzcov has known gaps to find.
#
# Usage: e2e/recorders/vampi.sh            (expects VAmPI on http://localhost:5000)
#        START_VAMPI=1 e2e/recorders/vampi.sh   (starts erev0s/vampi in Docker first)
# Only for the public demo app VAmPI. Never point this at employer or client systems.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/testdata/raw/vampi.har"
BASE=${VAMPI_URL:-http://localhost:5000}
PROXY_PORT=${PROXY_PORT:-8081}

command -v mitmdump >/dev/null || { echo "mitmdump not found: pipx install mitmproxy (>= 10.1)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }

if [[ "${START_VAMPI:-0}" == 1 ]]; then
	docker rm -f vampi >/dev/null 2>&1 || true
	docker run -d --rm --name vampi -p 5000:5000 erev0s/vampi:latest >/dev/null
fi
for _ in $(seq 1 30); do curl -fsS "$BASE/" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$BASE/" >/dev/null || { echo "VAmPI not reachable at $BASE" >&2; exit 1; }

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
mitmdump -q -p "$PROXY_PORT" --set hardump="$OUT" &
MITM=$!
trap 'kill -INT $MITM 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do (echo >/dev/tcp/127.0.0.1/"$PROXY_PORT") 2>/dev/null && break; sleep 0.5; done

# Throwaway demo passwords, fresh per run; never printed.
pw() { head -c 12 /dev/urandom | base64 | tr -d '/+='; }
PW_ALICE=$(pw)
PW_BOB=$(pw)

req() { # method path [token] [json]
	local args=(-sS -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$PROXY_PORT" -X "$1" "$BASE$2")
	[[ -n "${3:-}" ]] && args+=(-H "Authorization: Bearer $3")
	[[ -n "${4:-}" ]] && args+=(-H 'Content-Type: application/json' --data "$4")
	printf '%-6s %-40s %s\n' "$1" "$2" "$(curl "${args[@]}")"
}
login() { # user password -> token on stdout (not echoed)
	curl -sS -x "http://127.0.0.1:$PROXY_PORT" -X POST "$BASE/users/v1/login" \
		-H 'Content-Type: application/json' \
		--data "{\"username\":\"$1\",\"password\":\"$2\"}" |
		python3 -I -c 'import json,sys; print(json.load(sys.stdin)["auth_token"])'
}

req GET /createdb
req POST /users/v1/register "" "{\"username\":\"alice\",\"password\":\"$PW_ALICE\",\"email\":\"alice@example.test\"}"
req POST /users/v1/register "" "{\"username\":\"bob\",\"password\":\"$PW_BOB\",\"email\":\"bob@example.test\"}"
TOK_ALICE=$(login alice "$PW_ALICE")
TOK_BOB=$(login bob "$PW_BOB")
echo "POST   /users/v1/login (alice, bob)"

req POST /books/v1 "$TOK_ALICE" '{"book_title":"alice-book","secret":"alice-secret"}'
req POST /books/v1 "$TOK_BOB" '{"book_title":"bob-book","secret":"bob-secret"}'
req GET /books/v1/alice-book "$TOK_ALICE"
req GET /books/v1/bob-book "$TOK_BOB"
req GET /me "$TOK_ALICE"
req GET /me "$TOK_BOB"
req PUT /users/v1/alice/email "$TOK_ALICE" '{"email":"alice2@example.test"}'
req GET /books/v1/alice-book   # anonymous

kill -INT "$MITM"; wait "$MITM" 2>/dev/null || true
trap - EXIT
echo "wrote $OUT ($(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["log"]["entries"]))' "$OUT") entries)"
