# Benchmarks

`BenchmarkCoverage10k` (`internal/cli/bench_test.go`) runs the full CLI
`coverage` command (spec, HAR, identities, `coverage.json`) on a deterministic
synthetic HAR of 10,000 entries: a 44-operation spec, 6 identities (2 roles,
2 tenants), `learn_from_create` ownership, creates, owner and cross-user reads,
anonymous 401s, lists, about 3% unmatched paths and 1% static assets. Fixture
generation is outside the timer. `scripts/bench.sh` also records peak RSS of
the built binary on the same fixture via `/usr/bin/time -v`.

## Run

```
make bench                 # compare with the baseline; exit 1 on REGRESSION (> 20% slower)
make bench ARGS=--update   # re-measure and rewrite the baseline line below
AUTHZCOV_BENCH=1 go test ./internal/cli -run TestCoverage10kUnder5s -v   # hard 5 s limit
```

Not part of `make check`. Machine: WSL2 (Linux 6.18), go1.27.4 linux/amd64.

## Baseline

baseline_ns_per_op: 138120819

## First measurements

Median of 5 runs: 138.1 ms/op (limit 5000 ms), 895,368 allocs/op, 130.5 MB/op (B/op), peak RSS 31.7 MiB.
