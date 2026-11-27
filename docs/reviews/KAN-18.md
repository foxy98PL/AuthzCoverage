# KAN-18 review (Haiku, read-only, 2026-11-27)

`make check`: PASS (all packages, 0 lint issues, no vulnerabilities).

| Criterion | Result | Evidence |
| --- | --- | --- |
| (a) invalid yaml → exit 2 with file:line + key | proven | cli TestInvalidIdentitiesLocation; config TestParseErrors, TestV1Errors |
| (b) credential types extracted per list order | proven | identity TestNewExtractor |
| (c) learn_tokens → Learned confidence | proven (unit) / weak (e2e checks cells, not confidence) | TestLearnedTokens, TestLearnTokensEndToEnd |
| (d) discover skeleton with fingerprint + key claims | partial (claims line not asserted) | TestDiscover |
| (e) role warning | proven | TestWarnings, TestConfigWarnings |
| (f) anchors/aliases rejected | proven | config TestParseErrors |

Rules R1–R7 pass (token_env hashed only; basic password discarded; discover leaks no raw values; token learning
before resolution; ConfLearned only from learned bindings; schema keys = config keys; FuzzExtractSpecs clean).

## Fixed 2026-11-27 (owner sign-off needed on 1)
- redact.JSON: password/passwd/pwd/secret/clientsecret → `"[redacted]"` (no hash); token-like keys and JWT values keep `[redacted:<fp12>]`.
- identity basic: fingerprint = Fingerprint("basic:"+user) (or "basic:invalid"); never depends on the password.
- Tests: TestBasicFingerprintIndependentOfPassword, TestDiscoverShowsJWTClaims, TestDiscoverBasicLeaksNothingAboutPassword,
  TestLearnTokensYieldsLearnedConfidence; har test expectations updated to `[redacted]`.

Original findings:
1. **Security:** basic fingerprint = unsalted SHA-256 of base64(user:password); printed by discover → offline
   password guessing for weak passwords. Same class: password fields in JSON bodies redacted as `[redacted:<fp>]`.
   Fix: basic fp from username only; password-like JSON keys → plain `[redacted]`; token-like keys keep fp.
2. Assert discover's `# claims:` line.
3. Assert learned confidence end to end.
