# Releasing authzcov

Releases are built by `.github/workflows/release.yml` (GoReleaser, config in `.goreleaser.yaml`)
when a tag matching `v*` is pushed. Nothing is built or published from a laptop.

## Tag naming

Semantic versioning with a leading `v`: `v0.1.0`, `v0.1.1`. Pre-releases carry a suffix:
`v0.1.0-rc.1`. GoReleaser marks any tag with a suffix as a pre-release automatically
(`prerelease: auto`). The workflow only matches `v*`; keep the leading `v`: the verify command in the README matches `refs/tags/v...`.

## Steps

1. Start from a clean, up-to-date `main` with CI green. Run `make check` locally.
2. Make sure README and `docs/PROGRESS.md` describe what the release contains.
3. **Cut a pre-release tag first** (annotated) and push it:
   ```sh
   git tag -a v0.1.0-rc.1 -m "v0.1.0-rc.1"
   git push origin v0.1.0-rc.1
   ```
4. Watch the Release workflow in the Actions tab. It runs `make check-offline`, builds six archives,
   SBOMs, `checksums.txt`, the cosign bundle, and the provenance attestation.
5. Check the release page (see below) and run the README verify commands against the downloaded files.
6. If anything is wrong, delete the release and the tag
   (`git push --delete origin v0.1.0-rc.1`, `git tag -d v0.1.0-rc.1`), fix, and use the next
   `-rc.N`. Never move or reuse a published tag.
7. When the pre-release is good, tag the final release the same way (`v0.1.0`) and repeat 4-5.

## What to check on the release page

- Six archives: linux, darwin, windows, each amd64 and arm64 (`.tar.gz`, `.zip` for windows).
- One SBOM per archive, `checksums.txt`, and `checksums.txt.sigstore.json`.
- Pre-release flag set for `-rc` tags, not set for final tags; not a draft.
- Changelog lists the expected commits (docs, ci and test commits are excluded).
- `cosign verify-blob`, `sha256sum --ignore-missing -c checksums.txt` and
  `gh attestation verify` all succeed (commands in README, "Releases and signatures").
- `authzcov version` from a downloaded archive prints `authzcov <tag without v> (commit <short sha>)`,
  e.g. `authzcov 0.1.0-rc.1 (commit 8fa2fbb)`.
- Actions tab: the attestation step succeeded; the repo's Attestations page lists the new entry.

## Notes

- Tools are pinned in the workflow (goreleaser, cosign, syft). Bump them deliberately and test with
  a pre-release tag.
- The release job holds `contents: write`, `id-token: write`, `attestations: write` and nothing else.
- Signing and attestation need GitHub's OIDC token, so they cannot be exercised locally. Local dry
  run: `go run github.com/goreleaser/goreleaser/v2@v2.20.3 release --snapshot --clean --skip=sign,sbom,publish`
  (then `rm -rf dist`).
