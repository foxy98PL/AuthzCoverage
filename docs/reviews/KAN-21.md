# KAN-21 review (Haiku, read-only, 2026-11-27)

| Criterion / rule | Result | Evidence |
| --- | --- | --- |
| AC1 50 gaps → top 20 + <details> | proven | TestTopGapsAndDetails |
| AC2 escaping (\| ` < [ @) | proven | TestEscape, TestHostileEndpoint |
| AC3 first line one sentence X of Y | proven | TestFirstLine |
| AC4 golden diff fails without -update | proven | TestGolden (.md) |
| R1 every report string escaped | pass (by reading) | Render/build: only ints and fixed text unescaped |
| R2 ≤ MaxBytes, balanced <details> | **fail** → fixed | F1 |
| R3 deterministic | proven | TestDeterministic |
| R4 stdlib only | pass | imports |

## Findings and handling
1. **F1 (medium)**: cells were capped at 300 runes before escaping, and `@` escapes to 5 bytes. The top-20 rows are
   never dropped, so a hostile relationship string pushed output to 60034 > 60000 bytes. → **fixed (orchestrator)**:
   unknown relationship values render as "unknown"; cells are capped at 1000 bytes after escaping by trimming raw
   runes (an escape is never split); Render returns an error instead of writing over MaxBytes.
   Tests: TestTruncationWideEscapedCells, TestCellByteCapKeepsEscapesWhole, TestUnknownRelationshipLabel.
2. **F2 (low)**: truncation test lacked wide escaped cells → covered by the F1 tests.
3. **F3 (low)**: the CLI markdown path is not compared byte-for-byte to the golden (library is). → noted; the CLI
   only adds redact.NewWriter, which the table path already tests. Follow-up if it ever diverges.
4. **F4 (info)**: `$` not escaped (GitHub math). → noted, cosmetic; revisit if seen in practice.
5. **F5 (info)**: `.` escaped everywhere → intended (blocks www. autolinks).

Status: passed after fix.
