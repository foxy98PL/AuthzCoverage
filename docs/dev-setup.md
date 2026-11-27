# Development setup (Windows 11 + WSL2)

Target: a new contributor goes from zero to `make check` green in ≤ 30 minutes (KAN-75).
All commands run in the WSL Ubuntu terminal (VS Code: bottom-left shows **WSL: Ubuntu**).
Keep the repo in the WSL filesystem (`~/src/...`), never under `/mnt/c/`.

## 1. Tools

| Tool | Version checked (2026-11-27) | Needed for |
| --- | --- | --- |
| Go | 1.27.4 (must match `toolchain` in go.mod) | everything |
| make, git, build-essential, curl | GNU Make 4.4.1, git 2.53 | build, hooks |
| gopls | 0.24.0 | VS Code Go extension |
| golangci-lint | 2.15.0 (v2 config format) | `make lint` |
| govulncheck | 1.10.0 | `make vuln` (needs network for the vuln DB) |
| Docker Desktop (WSL2 backend, Ubuntu integration on) | server 28.4.0 | demo apps |
| mitmproxy | ≥ 10.1 — **not installed yet** | recording HARs (`e2e/recorders/`) |
| Node.js | LTS — not installed in WSL | Playwright recording (later) |

Install, in order:

1. `sudo apt update && sudo apt install -y make git build-essential curl pipx`
2. Go: download the latest `linux-amd64` tarball from https://go.dev/dl/, replace `/usr/local/go`
   with it, and add `export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin` to `~/.bashrc`.
3. `go install golang.org/x/tools/gopls@latest`
4. `go install golang.org/x/vuln/cmd/govulncheck@latest`
5. golangci-lint: official binary install script from https://golangci-lint.run into `$(go env GOPATH)/bin`.
6. `pipx install mitmproxy && pipx ensurepath`

Note: a Windows-side `claude`/`node` on PATH (`/mnt/c/...`) does not work inside WSL; install
Node inside WSL if you need it.

## 2. Repo

```bash
cd ~/src/authzcov
make hooks        # installs scripts/pre-commit (runs make check-offline, refuses HAR files)
make check        # vet + golangci-lint + go test -race + govulncheck
make build        # ./bin/authzcov
make fuzz         # every Fuzz* target, FUZZTIME=30s each
```

Expected: `make check` prints `0 issues.`, `ok` for every package and `No vulnerabilities found.`

## 3. Demo apps

| App | Start | RAM |
| --- | --- | --- |
| VAmPI | `docker run -d --rm --name vampi -p 5000:5000 erev0s/vampi:latest` | small |
| crAPI | upstream docker compose (ITER-02) | target ≥ 8 GB for Docker — **not yet verified** |

Recording VAmPI: see `e2e/recorders/vampi.sh` (writes git-ignored `testdata/raw/vampi.har`).

## 4. Rules that bite

- Never commit real traffic: `testdata/raw/` and `*.har` are git-ignored and refused by the hook.
  Committed fixtures are generated in Go tests (`internal/testutil/hartest`).
- Only public demo apps (VAmPI, crAPI, Juice Shop, PetClinic REST, RealWorld) — never employer or client systems.
- Direct dependencies are limited to cobra, kin-openapi, yaml/v3, golang-jwt/v5 (and x/time/rate in Phase 4).
