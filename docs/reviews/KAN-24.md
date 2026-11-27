# KAN-24 review (Haiku, read-only, 2026-11-27)

All 5 acceptance criteria and rules R1–R8 pass (see the review agent's table; summary below).

| Item | Result | Evidence |
| --- | --- | --- |
| C1 keyed endpoint → relationship, no timestamps | proven | cli TestBaselineWriteDeterministic; baseline no-date regex test |
| C2 rewrite byte-identical | proven | TestBaselineWriteDeterministic |
| C3 waiver → diff "waived" | proven | TestBaselineDiffWaived |
| C4 expired → flagged | proven | TestBaselineDiffExpired, TestApplyExpired |
| C5 no reason → exit 2 | proven | TestWaiversWithoutReasonExit2 |
| R1 waiver validation (reason, expires, enum, keys, anchors, dups, bare list, 1 MiB) | proven | waivers_test.go |
| R2 covered never waived; expired never waives | proven | waivers Apply tests |
| R3 summary recomputation | proven | Apply test, coveragejson Percent test |
| R4 baseline content / Read | proven; size cap untested | F1 |
| R5 no clock in waivers/baseline | pass | grep |
| R6 exit codes | proven | cli baseline tests |
| R7 StripControl in diff; glob linear | code ok; no CLI test | F2 |
| R8 expired / waived→missing consistent | proven | TestBaselineDiffExpired, TestCompare |

Edge cases checked by hand: 500/501 × "é", Feb 29 (2027 rejected, 2028 accepted), today+365 ok / +366 rejected,
endpoint "*", ESC/newline stripped.

## Findings and handling
1. **F1 (medium, test gap)**: baseline 64 MiB cap untested and gives a generic decode error. → fix: explicit message + test.
2. **F2 (low)**: no CLI test with control chars through `baseline diff`. → fix: e2e test.
3. **F3 (low)**: Feb 29, non-ASCII reason boundary, Cell.Waiver JSON shape not committed as tests. → fix: tests.
4. **F4 (low)**: schema says lengths on untrimmed value; Go trims. → fix: schema description.
5. **F5 (info)**: baseline.Read ignores unknown top-level keys (v1 may gain fields, ADR 0004) and does not cross-check summary. → noted.
6. **F6 (info)**: invalid waivers fail `coverage` even with `--out ""`. → intended (fail fast).

## Fixed 2026-11-27 (orchestrator; the Sonnet agent hit the usage limit)
- F1: baseline.Read reads MaxSize+1 bytes and fails with "baseline.json exceeds the 64 MiB limit"; TestReadSizeCap.
- F2: TestBaselineDiffStripsControlInWaiver (internal/cli/kan24_review_test.go): ESC in a waiver pattern never reaches stdout.
- F3: TestLeapDayAndRuneBoundaries (waivers), TestCellWaiverJSONShape (coveragejson).
- F4: schema/waivers.v1.json descriptions say limits apply after trimming; Go parser authoritative.
`make check` green.

Status: passed after fix.
