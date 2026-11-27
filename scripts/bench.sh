#!/usr/bin/env bash
# End-to-end coverage benchmark (KAN-73). Usage: scripts/bench.sh [--update]
set -euo pipefail
cd "$(dirname "$0")/.."

DOC=docs/benchmarks.md
UPDATE=0
for arg in "$@"; do
	case "$arg" in
	--update) UPDATE=1 ;;
	*) echo "usage: scripts/bench.sh [--update] (unknown argument: $arg)" >&2; exit 2 ;;
	esac
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

go test ./internal/cli -run '^$' -bench BenchmarkCoverage10k -benchmem -count 5 | tee "$tmp/bench.txt"

# Median of each metric over the runs.
median() { # $1 = unit name
	awk -v u="$1" '/^BenchmarkCoverage10k/ { for (i = 2; i < NF; i++) if ($(i+1) == u) print $i }' "$tmp/bench.txt" |
		sort -n | awk '{ a[NR] = $1 } END { if (NR) print a[int((NR + 1) / 2)] }'
}
ns=$(median ns/op)
bop=$(median B/op)
allocs=$(median allocs/op)
[[ -n "$ns" ]] || { echo "could not parse benchmark output" >&2; exit 2; }
ns=${ns%.*}

rss="n/a"
if [[ -x /usr/bin/time ]]; then
	mkdir -p "$tmp/fx"
	AUTHZCOV_BENCH_FIXTURE_DIR="$tmp/fx" go test ./internal/cli -run '^TestWriteBenchFixture$' -count=1 >/dev/null
	CGO_ENABLED=0 go build -trimpath -o "$tmp/authzcov" ./cmd/authzcov
	/usr/bin/time -v "$tmp/authzcov" coverage --spec "$tmp/fx/spec.yaml" --har "$tmp/fx/bench.har" \
		--identities "$tmp/fx/identities.yaml" --out "$tmp/out" >/dev/null 2>"$tmp/time.txt" ||
		echo "warning: coverage run for peak RSS failed (see below); RSS not recorded" >&2
	kb=$(awk -F: '/Maximum resident set size/ { gsub(/ /, "", $2); print $2 }' "$tmp/time.txt")
	if [[ -n "$kb" ]]; then
		rss=$(awk -v k="$kb" 'BEGIN { printf "%.1f", k / 1024 }')
	else
		tail -5 "$tmp/time.txt" >&2
	fi
else
	echo "warning: /usr/bin/time not found, skipping peak RSS" >&2
fi

printf 'median %.1f ms/op, %s allocs/op, %s B/op, peak RSS %s MiB\n' \
	"$(awk -v n="$ns" 'BEGIN { print n / 1e6 }')" "$allocs" "$bop" "$rss"

if ((UPDATE)); then
	sed -i "s/^baseline_ns_per_op: .*/baseline_ns_per_op: $ns/" "$DOC"
	echo "baseline updated to $ns ns/op in $DOC"
	exit 0
fi

base=$(sed -n 's/^baseline_ns_per_op: *\([0-9]*\).*/\1/p' "$DOC")
[[ -n "$base" && "$base" -gt 0 ]] || { echo "no baseline in $DOC (run with --update)" >&2; exit 2; }
if awk -v n="$ns" -v b="$base" 'BEGIN { exit !(n > b * 1.2) }'; then
	echo "REGRESSION: $ns ns/op is more than 20% slower than baseline $base ns/op" >&2
	exit 1
fi
echo "ok: $ns ns/op vs baseline $base ns/op (limit +20%)"
