# KAN-20 review (Haiku, read-only, 2026-11-27)

| Criterion / rule | Result | Evidence |
| --- | --- | --- |
| C1 schema field, sorted cells/findings | proven | cli TestCoverageJSONWritten; coveragejson TestSummaryAndFindings, TestCellsSortedAndEmitted |
| C2 report table == coverage table, no inputs | proven | cli TestReportMatchesCoverageTable (inputs deleted first, 4 fixtures), TestGolden |
| C3 -update rewrites, diff fails | proven (by reading) | golden_test.go checkGolden |
| C4 byte-identical runs | proven with SOURCE_DATE_EPOCH | TestCoverageJSONDeterministic |
| R1 no raw credential / object ID | gap | unmatched-path leak (F1); Basic not e2e-tested (F4) |
| R2 finding fingerprint formula | proven | TestSummaryAndFindings |
| R3 [] not null | proven | TestSlicesNeverNull; goldens grep clean |
| R4 Build pure | partial | time.Now fallback in Build (F3) |
| R5 no net/http, no new deps | pass | greps; go.mod |
| R6 report exit codes 2/3 | proven | TestReportExitCodes |
| R7 percent == table %.1f | proven | TestPercentMatchesTable |

## Findings and handling
1. **F1 (security)**: unmatched-path shapes keep ID-like segments that `looksLikeID` misses
   (`/nope/ab-Zq9x-Kd7`). They are written to coverage.json and stderr. → **fix**: a segment that has a digit
   and is ≥ 6 bytes, or is ≥ 24 bytes, counts as ID-like; e2e test added.
2. **F2**: without SOURCE_DATE_EPOCH, `generated_at` differs between runs. → **by design**: DOC-04 says
   generated_at is the only timestamp and is excluded from golden comparisons; SOURCE_DATE_EPOCH gives
   reproducible output.
3. **F3**: `Build` falls back to `time.Now` when `Input.Now` is nil. → **fix**: nil means Unix 0.
4. **F4**: no e2e test with Basic credentials. → **fix**: test that the password and base64 string are
   absent from coverage.json, stdout and stderr.
5. **F5**: schema/coverage.v1.json is not checked against the output. → **fix**: a key walker test over the
   goldens (no JSON Schema library, to avoid a new dependency).
6. **F6**: `summary.waived` is always 0. → **expected** until KAN-24 (waivers).

## Fixed 2026-11-27
Tests: TestLooksLikeID, TestUnmatchedIDLikeSegmentNotLeaked (F1), TestBuildDoesNotNeedClock rewritten (F3),
TestBasicPasswordNeverInOutputs (F4), TestGoldensMatchSchema (F5; schema and goldens already agreed).
No golden changed. `make check` green.

Status: passed after fix.
