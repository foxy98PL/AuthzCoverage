# Session 1.1 — Audit bugs: owner-answer follow-ups (KAN-97, 98, 100, 103)
Status: done — shard 2026-11-28-2359-session1.1.md
Budget: ~35k of ~100k
Depends on: owner answers listed in shard 2026-11-28-2300 (defaults below if still open)

These bugs predate the session files (audit of 2026-11-28); filed under session 1 as the first session.

## Goal
The agent-doable remainder of the four partial audit bugs is fixed; what needs the owner is left with a clear ask.

## Work (in order)
1. KAN-103 BUG Docs drift: DCO dropped in CONTRIBUTING, stale package list, SECURITY.md "no releases", fuzz 10s vs 30s — trivial ~5k — none
   ci.yml already runs `make fuzz FUZZTIME=30s` and the Makefile default is 30s: verify, then close the fuzz point
   in the Jira comment. Fix the "tenantshop ~200 lines" claim to the real size (grep where it's stated).
2. KAN-100 BUG HTML filter JS untested, size AC unmet, SARIF upload never exercised — trivial ~8k — implementer
   Default if unanswered: add a SARIF upload step to action-test.yml (SHA-pinned `github/codeql-action/upload-sarif`,
   `security-events: write` on that job only); it gets exercised on the next CI run after push. CSP: propose AC
   wording "hashed inline style" in the Jira comment. RealWorld size AC waits on session 3.
3. KAN-98 BUG README: demo GIF missing, contradictory release lines, Pages not live — trivial ~5k — none
   Default if unanswered: keep the tenantshop quickstart (no Docker needed) and propose the AC amendment
   (examples/vampi → tenantshop) in the Jira comment. GIF stays skipped (owner decision).
4. Jira batch + shard + commit — ~10k

## Owner / blocked
- KAN-97: cosign verify-blob, attestation API check, action checksum against v0.1.0-rc.2 — needs gh/cosign; owner runs.
- KAN-98: enable GitHub Pages for the sample report (repo setting, owner only).
- KAN-100 / KAN-98 / KAN-103 AC amendments are the owner's call; the orchestrator only proposes them in comments.

## Done when
- `make check` green; the three tickets have Jira comments stating what's fixed and what's left for the owner.

## Out of scope
- KAN-97 verification itself; RealWorld recording (session 3).
