# Session 5 — Launch week bugs, friction fixes and v0.2.0 prep
Status: active (blocked: no launch reports, v0.1.0 untagged)
Budget: ~75k of ~100k
Depends on: session 4; owner launch (KAN-32) done and the owner's list of friction points / launch-week issues

## Goal
Launch-week bugs are fixed, the top three friction points from launch feedback are fixed, and v0.2.0 is ready
to tag (CHANGELOG, known limitations, export --plan from KAN-34 included).

## Work (in order)
1. KAN-35 ACV-3.8 Buffer evening for launch-week bugs — normal ~30k — implementer → reviewer → fixer
   Each launch-week report the owner forwards becomes a Jira Bug and a regression row first. Bugs that don't
   fit go to `session5.1.md` (mechanical, no /planner run).
2. KAN-33 ACV-3.6 Fix top three friction points; release v0.2.0 — normal ~35k — implementer → reviewer → fixer
   Assumption if the owner names no friction points: take them from Gate B (quickstart time), the known
   limitations list and open In Review leftovers, and state the pick in the Jira comment. v0.2.0 prep only:
   CHANGELOG, docs/releasing.md checklist, SemVer minor. No tag.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- KAN-32 launch and the issue inbox (no gh here): the owner forwards issues/friction points.
- Push the v0.2.0 tag and verify the signed release (cosign/attestation, as KAN-97).
- Gate C (Sun 2027-01-31, KAN-65: at least 5 external issues or at least 1 team trying the Action) decides
  whether sessions 6–12 (Phase 4 probe) run; if it fails, KAN-65 says to switch to adoption work instead.

## Done when
- `make check` green; every fixed bug has a regression test; KAN-33/35 In Review (KAN-33 stays In progress
  until the owner tags v0.2.0).

## Out of scope
- Phase 4 probe (session 6+); new features beyond the three friction points.
