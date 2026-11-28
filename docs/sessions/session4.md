# Session 4 — v0.1.0 final prep and launch material
Status: active
Budget: ~60k of ~100k
Depends on: sessions 1–3; KAN-97 rc.2 verification by the owner before the v0.1.0 tag

## Goal
Everything for v0.1.0 is ready except the owner-only steps (tag push, signature check), and the launch post draft exists.

## Work (in order)
1. KAN-27 ACV-2.8 Signed v0.1.0 release — prep only — trivial ~10k — implementer
   CHANGELOG entry, known limitations (C2 if still open, VAmPI _debug FN), docs/releasing.md checklist; check the
   10k benchmark AC (< 5 s) against the CI bench job. No tag.
2. KAN-76 ACV-0.6 Name collision check and licence attribution — licence part — trivial ~8k — implementer
   Third-party licence attribution for the direct deps in the release archives/NOTICE. The name collision search
   needs web access: owner.
3. KAN-31 ACV-3.4 Technical post "What our API tests never check" — draft — normal ~25k — implementer → reviewer
   Draft under docs/ from the eval results (VAmPI, crAPI, RealWorld, tenantshop); no publication.
4. Jira batch + shard + commit — ~10k

## Owner / blocked
- Push the v0.1.0 tag and verify the release (KAN-27, KAN-97: cosign, attestation).
- G1 employment IP check before the post is published; KAN-13 Gate A outreach; KAN-32 launch.
- Name collision search (KAN-76).

## Done when
- `make check` green; KAN-27 prep and KAN-31 draft commented in Jira (stay In progress until the owner steps).

## Out of scope
- KAN-32/33/35 (post-launch), Phase 4 probe (gated on Gate C), Phase 5 and AI spikes.
