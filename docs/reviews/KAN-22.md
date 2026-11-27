# KAN-22 review (Haiku, read-only, 2026-11-27)

| Item | Result | Evidence |
| --- | --- | --- |
| AC1 offline, no external requests | static pass; browser check by owner | TestNoExternalRequests; python grep of goldens |
| AC2 CSP hashed script/style only | proven | TestCSP; hashes recomputed in python for all 4 goldens |
| AC3 <script> escaped | proven | TestEscaping |
| AC4 relationship filter | structure only; browser check by owner | TestFilterStructure; report.js read |
| AC5 < 500 KB | proven (thin margin) | TestBigReportSize: 485,926 B for 300×7 cells + 3000 findings |
| R1 unsafe template types only on embedded constants | pass | grep |
| R2 CSP strict, first after charset | pass | python check |
| R3 no src/href/link/url()/@import/on*/style= | pass | goldens + test |
| R4 JS: no innerHTML/eval/Function | pass | report.js |
| R5 attributes quoted | pass | report.html.tmpl |
| R6 deterministic, stdlib | pass | TestDeterministic |

## Findings and handling
1. **F1 (low)**: no test executes report.js (no browser/Node here). → owner browser check (steps in Jira).
2. **F2 (low)**: `report --format html` wrote stdout without redact.NewWriter. → **fixed**: same control-char filter as table/markdown.
3. **F3 (low)**: ~26 KB headroom at 3000 findings. → noted; RealWorld is ~20 endpoints. Revisit with real recordings.
4. **F4 (cosmetic)**: optional `</td>`/`</tr>` omitted (valid HTML5, done for size). → noted.
5. **F5 (info)**: escaping test does not cover Finding.Kind/Severity. → html/template escapes them; noted.
6. **F6 (info)**: 500 KB tested as 500×1024; passes at 500,000 too.

Status: passed after fix (AC1/AC4 pending owner browser check).
