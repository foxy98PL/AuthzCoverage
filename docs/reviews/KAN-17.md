# KAN-17 review (Haiku, read-only, 2026-11-27)

| Criterion | Result | Evidence |
| --- | --- | --- |
| (a) base path auto prints prefix + match % | proven | cli/basepath_test.go TestBasePath "auto default"; basepath TestDetect |
| (b) .har.zip read with decompressed-size limit | proven (unit) / weak (e2e) | har/zip_test.go TestZipLimits; cli TestHARZipEndToEnd happy path only |
| (c) unmatched grouped by shape | proven | TestShapeOfAndGrouping, TestUnmatchedTruncation |
| (d) explain shows candidates, winner, why | weak | TestExplainCommand, match TestExplain — not the ticket's own example |
| (e) fuzz 30 s no panics | proven | FuzzExplain 10.0M execs clean |

Rules: R1 zip total counted from bytes read — pass (ratio uses header size, caveat); R2 StripControl on printed
traffic strings — partial (base-path line uses %q only); R3 order independence — pass; R4 Explain.Result == Match — pass;
R5 no panic — pass.

## Findings → fixed 2026-11-27
Tests added: TestBasePathLineStripsControlBytes (regression guard; %q already escaped ESC),
TestZipForgedCompressedSizeStillBoundedByTotal (forged 1 GiB CompressedSize64 still stopped by the total cap),
TestHARZipBombEndToEnd (default limits → exit 3), TestExplainLiteralBeatsParamInline (`GET /api/orders/123`).

Original findings:
1. Base-path line: StripControl the prefix/host + test.
2. Zip ratio trusts header CompressedSize64: comment + test that the total cap still bounds a forged header.
3. CLI zip-bomb test (default limits → exit 3, "decompressed size limit exceeded").
4. Explain test with the ticket example `GET /api/orders/123`.
