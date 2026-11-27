# KAN-25 review (Haiku, read-only, 2026-11-27)

| Item | Result | Evidence |
| --- | --- | --- |
| AC1 new endpoint gap → listed, exit 1 | proven | cli TestGateNewEndpointGap |
| AC2 covered → missing → regression, exit 1 | proven | TestGateRegression, gate TestRegressions |
| AC3 drop beyond --max-drop → exit 1 with % | proven | TestGateDrop, TestDropBoundary |
| AC4 --fail-on new-gaps with only regression → 0 | proven | TestGateFailOnSubsetIgnores |
| AC5 unreadable coverage.json → 3 | proven | TestGateUnreadableInputs |
| R1 new-gaps only on absent endpoints | proven | TestNewGaps |
| R2 waived → missing not a regression | proven | TestRegressions, TestGateExpiredWaiver |
| R3 drop / --max-drop validation | **gap** → fixed | F1 |
| R4 expired before today; today passes | partial → fixed | F3 |
| R5 removed never fails | proven | TestRemovedNeverFails, TestGateRemovedEndpointNeverFails |
| R6 ignored line | proven | TestDisabledRulesIgnoredAndOrder |
| R7 exit codes, StripControl | proven | cli gate tests; printGate |
| R8 pure package | pass | imports: fmt, math, slices, strings, baseline |

## Findings and handling
1. **F1 (medium)**: `--max-drop Inf` was accepted and silently disabled the drop rule. → **fixed**: Inf rejected
   (exit 2); TestGateUsageErrors covers Inf, +Inf, inf.
2. **F2 (low)**: expired-waiver messages are deduplicated by text. → **no change**: two waivers with the same
   endpoint pattern and relationship are already rejected as duplicates by the waivers parser.
3. **F3 (low)**: no test that a waiver expiring today passes. → **fixed** in TestGateExpiredWaiver.
4. **F4 (low)**: 0 → 0 percent untested. → **fixed**: TestDropBoundary case.
5. **F5 (info)**: an empty baseline makes every endpoint new. → by design (DOC-04 rule); `baseline write` first.

Status: passed after fix.
