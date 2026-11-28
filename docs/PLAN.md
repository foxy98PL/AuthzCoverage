# AuthzCoverage — Phase 0–1 implementation plan

Source of truth: the implementation prompt (sections 0–9), cross-checked against Jira project KAN
(epics KAN-4, KAN-5; stories KAN-10…16, 68–70, 75, 76; docs KAN-58, 60, 65, 66, 67) on 2026-11-27.
Where Jira and the prompt differ, the prompt wins until the owner decides (see "Decisions needed").

## Status

| Task | Scope | Jira | Status |
| --- | --- | --- | --- |
| 0 | Environment check | KAN-75 | done (mitmproxy still missing, needed for task 6) |
| 1 | Repo skeleton, CLI, Makefile, local gate, hook | KAN-10, KAN-11 (lite) | done |
| 2 | Spec loader + SpecLine | KAN-68, KAN-70 | done (awaiting review) |
| 3 | 🔒 Segment trie matcher | KAN-69 | done (awaiting review) |
| 4 | 🔒 HAR ingest, redact, identity, identities.yaml v0 | KAN-15 | done (awaiting review) |
| 5 | 🔒 Ownership, classifier, matrix, table, no-network test | KAN-16 | done (awaiting review) |
| 6 | Real VAmPI recording and run | KAN-12 (VAmPI part), KAN-16 demo | scripts written; needs mitmproxy + run |

Details of what was built: `docs/PROGRESS.md`. Working rules (orchestrator + subagents): `CLAUDE.md`.

ITER-01 (2026-11-28 → 12-04) per KAN-65/KAN-67: ACV-0.1, 0.3 (VAmPI), 1.1a/b, 1.2, 1.3.
KAN-70 (line numbers) may slip to ITER-02; it is cheap enough to include in task 2.

## Target folder tree (end of task 6)

```text
authzcov/
├── cmd/authzcov/main.go                 # T1  KAN-10
├── internal/
│   ├── cli/                             # T1  root, coverage, version, exit codes
│   │   ├── coverage.go                  # T5  two-pass pipeline wiring
│   │   └── nonet_test.go                # T5  failing http.DefaultTransport, end-to-end
│   ├── model/model.go                   # T2  Endpoint, Confidence, ... (stdlib only)
│   ├── spec/                            # T2  KAN-68, KAN-70
│   │   ├── load.go                      #     kin-openapi loader, external refs off
│   │   ├── lines.go                     #     yaml.Node pass -> SpecLine
│   │   └── load_test.go
│   ├── match/                           # T3  KAN-69 🔒 trie, Result, FuzzMatch
│   ├── ingest/har/                      # T4  KAN-15 streaming reader + filters
│   ├── redact/                          # T4  Fingerprint, header deny-list, StripControl
│   ├── identity/                        # T4  🔒 Bearer extraction, DecodeClaims, resolver
│   ├── config/                          # T4  identities.yaml v0, node validation
│   ├── testutil/hartest/                # T4  HAR builder, JWTs with fixed test key
│   ├── ownership/                       # T5  KAN-16 self_params, learn_from_create
│   ├── relate/                          # T5  🔒 classifier (5.5)
│   ├── matrix/                          # T5  🔒 requirements, cells, covered rule
│   └── report/table/                    # T5  tabwriter output
├── testdata/
│   ├── specs/                           # T2  vampi.yml + tiny edge-case specs
│   ├── har/                             # generated fixtures only
│   ├── identities/vampi.yaml            # T6
│   └── raw/                             # git-ignored real recordings
├── e2e/recorders/vampi.sh               # T6  KAN-12
├── docs/PLAN.md                         # this file
├── scripts/pre-commit                   # T1
├── .vscode/ .golangci.yml .gitignore Makefile LICENSE NOTICE SECURITY.md README.md
```

## Task details

### Task 2 — Spec loader (KAN-68, KAN-70)
- `model`: full section 5.1 structs (needed by later tasks; stdlib only).
- `spec.Load(path) ([]*model.Endpoint, error)`: kin-openapi `openapi3.Loader` with
  `IsExternalRefsAllowed=false`; `Validate`; one Endpoint per (path, method); sorted by ID.
- Params from template order; `ObjectParam` = last param; `Resource` = literal segment before it;
  `Kind` ObjectLevel iff ObjectParam != "".
- Duplicate (method, normalised template) → `ErrDuplicate` (cli maps to exit 3). Normalised =
  param names replaced (`/a/{x}` ≡ `/a/{y}`), trailing slash ignored.
- `SpecLine`: separate `yaml.Node` decode (JSON parses too); line of the path key; 0 if missing.
- Tests: VAmPI table (ID, params, kind, resource), duplicate spec, remote `$ref` rejected,
  JSON spec lines, deterministic order, unreadable file.

### Task 3 — Matcher 🔒 (KAN-69)
Prompt 5.2 plus the required rows in task 3; tests first, then `FuzzMatch` 30 s.

### Task 4 — HAR + identity 🔒 (KAN-15)
Prompt task 4. Jira adds: entries decoded one at a time via `json.Decoder` (test asserts streaming
with a reader that would fail on whole-buffer reads), example claim `sub: alice@shop.test`.

### Task 5 — Ownership, classifier, matrix, table 🔒 (KAN-16)
Prompt task 5. Jira adds: `GET /users/v1/alice` by alice with `self_params` → owner;
bob reading alice's created book → same_role_other_user.

### Task 6 — VAmPI run (KAN-12 VAmPI part)
Prompt task 6. Requires mitmproxy ≥ 10.1 (not installed yet). Resolves blocker G5
(what VAmPI puts in the JWT `sub`).

## Jira vs prompt — differences found

| # | Jira says | Prompt says | Handling |
| --- | --- | --- | --- |
| J1 | KAN-11: GitHub CI, SHA-pinned actions, Dependabot, branch protection | Local only; `make check` + hook | **Superseded 2026-11-27**: repo is on GitHub; KAN-11 GitHub parts now in scope |
| J2 | KAN-10: SECURITY.md has a private reporting address | Stub, channel TBD | **Decision needed** (DOC-09 E2) |
| J3 | ADR 0005 / D10: only `internal/probe/exec` may use net/http | `internal/probe/` | Tighten depguard to `internal/probe/exec` (harmless, stricter) |
| J4 | D7: local `$ref` allowed within the spec directory | External refs disabled | **Decision needed**; task 2 implements the prompt (all external refs off) |
| J5 | KAN-68: ObjectParam = last param *mapped to a resource* | Last path param | Equivalent in v0: every param maps to a resource by default (segment before it) |
| J6 | DOC-03 VAmPI example uses `learn_tokens` + `match.login` (schema v1, ACV-1.5) | v0 uses `match.jwt.sub` | Prompt (v0) for now; depends on G5 |
| J7 | KAN-65 DoD: PRs, gitleaks, fuzz smoke in CI | Local gate | **Superseded 2026-11-27**: CI on GitHub; local gate stays as pre-commit |
| J8 | KAN-75: mitmproxy ≥ 10.1, Node, `docs/dev-setup.md` | Task 0 tool list | mitmproxy needed before task 6; dev-setup doc deferred |
| J9 | KAN-76: name collision check, `THIRD_PARTY.md` | NOTICE only | NOTICE covers VAmPI now; name check is a manual web task for the owner |
| J10 | KAN-58: ingest returns `iter.Seq2`, `model.Result`, `Finding`, `internal/pipeline` interfaces | Not in prompt | Use `iter.Seq2` in task 4 (stdlib); `Result`/`Finding`/pipeline later (Phase 2) |

## Hosting (decided 2026-11-27)

Owner moved the project from local-only to GitHub: `origin` = https://github.com/foxy98PL/AuthzCoverage
(public), branch `main` (local history based on the remote "Initial commit"). Owner commits and pushes.
Unblocked: KAN-11 GitHub parts (CI, Dependabot, branch protection), KAN-26 GitHub Action, KAN-27 release
(KAN-71/72), KAN-23 AC3 SARIF upload. Still owner-only before wide publicity: G1, E2.

## Decisions needed (owner)

1. **J2 / E2** security contact for SECURITY.md — now urgent: the repo is public (GitHub private vulnerability reporting is an option).
2. **J4 / D7** local `$ref` within spec dir: allow (Jira) or reject all (prompt, implemented).
3. **G5** VAmPI JWT `sub` = username? Verified during task 6; if it is an id, identities v0 needs `match.jwt.sub: <id>`.
4. **G1** employment IP clause check — owner only, before anything is published.

## Decisions taken 2026-11-27 (owner delegated decisions to the implementation orchestrator)

Each one is reversible; the owner can overturn any of them.

| # | Question | Decision | Why |
| --- | --- | --- | --- |
| O1 | KAN-18 credential handling (Basic fp from username only; password-like fields redacted without hash) | **Accepted** | Hashing low-entropy passwords invites offline guessing; username is enough to tell callers apart |
| O2 | Caller without tenant vs known object tenant (DOC-03 said `""` = global) | **Keep: other_tenant**; only `*` means global | Fail-safe: a forgotten tenant claim must not hide cross-tenant access. DOC-03 wording superseded |
| O3 | KAN-19 F1: anonymous exempt from the owner-confidence condition | **Yes** | Anonymous is never the owner; relationship is certain without knowing the owner. "Unknown never counts as covered" still holds for the caller |
| O4 | Tenant-scoped endpoints (object param is a tenant param, e.g. `/orgs/{orgId}/orders`) required owner + same_role cells that nothing can cover | **Classify within the tenant with the function-level rule**: required = owner (member with enough role), lower_role, other_tenant, anonymous; no object owner needed | The tenant is the object; per-user ownership does not exist there |
| O5 | suspicious_allow on function-level / tenant-scoped endpoints | **Yes, from declared facts only**: anonymous 2xx on an operation whose effective spec security requires auth; lower_role 2xx when `requirements.overrides[].min_role` declares a higher role | Learned min roles are circular (a 2xx lowers the min role), so only declarations can make it a finding |
| O6 | D7 local `$ref` within the spec directory | **Keep rejecting all external refs in v0.1**; document `redocly bundle` / `swagger-cli bundle` | Path handling is an attack surface; bundling is a one-line workaround. Revisit on user demand |
| O7 | E2 security contact | **GitHub private vulnerability reporting** (already in SECURITY.md); no email alias | No personal address in a public repo. Owner must enable it in repo settings |
| O8 | Real-app goldens (VAmPI, crAPI, RealWorld) without committing HARs | **Goldens are outputs of scripted recorders, checked by `make eval`**; recordings never committed (`*.har` stays blocked) | Keeps the no-HAR rule; recorders are deterministic and pinned by image digest |
| O9 | KAN-66 D1–D12 architect decisions | **Accepted as implemented**, except D11: DCO kept, email alias replaced by O7 | They match what was built and reviewed |
| O11 | lower_role on function-level / tenant-scoped endpoints when no role ranks below the minimum (e.g. GET /me callable by every role) | **Not required** when the effective minimum (declared min_role, else learned) is the lowest defined rank; still required when the minimum is unknown | No identity can ever test it; a permanent GAP is noise. Unknown minimum keeps D1 (uncalled endpoint = gap) |
| O10 | Next release | **v0.1.0-rc.2** after O3–O5 + real-app goldens; final **v0.1.0** when rc.2 verifies | rc.1 (db3ddcc) is published; release plan needs goldens + known limitations |

Not delegable (owner only): G1/E3 employment IP check, Gate A practitioner outreach (KAN-13), repo settings (branch protection, private vulnerability reporting, Pages), pushing tags.

## Implementation decisions (made during implementation; moved from PROGRESS 2026-11-28)

1. Non-bearer credentials (Basic, cookie, API key) → identity unknown, never anonymous.
2. Request/response JSON bodies are scrubbed of password/token/secret fields at ingest.
3. Multiple identity rules matching one token → unknown.
4. learn_from_create only learns from 2xx responses by a known creator.
5. self_params for another user's subject → owner with confidence `learned` if that subject was seen in pass 1.
6. Unknown caller → relationship unknown; function-level with no 2xx observed → unknown.
7. Table status suffix: all distinct statuses when any is non-2xx (`ok 200,401`).
8. Partial-segment path templates (`/{id}.json`) rejected with exit 3.
9. `--base-path` defaults to `auto`; a non-empty prefix is not credited when the remainder is only `/`.
10. learn_tokens never needs the raw token: the login response is redacted at ingest to `[redacted:<fp12>]`, and that fingerprint is what later bearer requests carry.
- KAN-94 (KAN-34 AC2): raw credentials/IDs never survive ingest *into shareable artifacts* (coverage.json, SARIF, HTML); the opt-in `export --plan --har` file (0600, `--out` only) is the only raw-ID output.
11. `token_sha256` is matched on its first 12 hex chars (the stored fingerprint length).
13. Basic fingerprint = Fingerprint("basic:"+user); password-like body fields redacted without hash (offline-guessing risk).
14. Tenancy: a caller with no tenant vs a known object tenant → other_tenant (only `*` is exempt). Note DOC-03 said `""` = global; conflict to decide.
15. coverage.json: same HAR → byte-identical; reordered HAR changes only har sha256 + evidence refs. Percent is rounded like the table's %.1f.
12. JSON Schema is shipped for editors only; validation stays in the Go validator (a JSON Schema library would be a new dependency).
