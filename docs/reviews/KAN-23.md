# KAN-23 review (Haiku, read-only, 2026-11-27)

| Item | Result | Evidence |
| --- | --- | --- |
| AC1 ruleId per kind + spec file/line | partial → fixed | TestStructure, TestLocations; F4 |
| AC2 stable partialFingerprints | partial → fixed | TestDeterministicFingerprints; F3 |
| AC3 GitHub upload | owner, manual | — |
| AC4 plain text | proven | TestPlainText, TestMessageCap |
| R1 GitHub conformance (uri relative) | **fail** → fixed | F1 |
| R2 deterministic, no timestamps | proven | goldens |
| R3 no markdown, control chars stripped | proven (+F5) | |
| R4 one result per finding | **fail** → fixed | F2 |
| R5 fallback line 1, results [] | proven | TestLocations, TestEmptyReport |
| R6 stdlib only | pass | imports |

Golden check (python): results == findings in all 4 goldens; ruleIndex/startLine/uri/fingerprints valid.

## Findings and handling (fixed by orchestrator)
1. **F1 (high)**: absolute, URL, `..` and drive-letter spec paths reached `artifactLocation.uri` (GitHub cannot map
   them; absolute paths leak local directory/user names into an uploaded file). → `repoURI` reduces them to the file
   name; `./` and backslashes normalised. TestRepoURI.
2. **F2 (high)**: findings of an unknown kind were silently dropped. → mapped to a fallback rule `authzcov/other`
   (added to the rule table only when needed). TestEveryKindAndUnknownKind.
3. **F3 (medium)**: cross-run fingerprint stability not proven. → fingerprint pinned to a value computed outside Go
   from the DOC-04 formula. TestFingerprintPinnedAndFilled.
4. **F4 (medium)**: suspicious_allow and undocumented_method never asserted. → TestEveryKindAndUnknownKind.
5. **F5 (low)**: U+2028/U+2029 and private-use survived; driver.version not sanitised. → stripped/replaced;
   version sanitised. TestPlainTextExtra.
6. **F6 (low)**: empty fingerprint emitted as "". → recomputed. TestFingerprintPinnedAndFilled.

Status: passed after fix (AC3 pending owner upload).
