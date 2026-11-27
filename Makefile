SHELL   := /bin/bash
BIN     := bin/authzcov
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null)
LDFLAGS := -s -w -X authzcov/internal/cli.version=$(VERSION) -X authzcov/internal/cli.commit=$(COMMIT)

.PHONY: build test lint vet vuln fuzz golden check check-offline hooks clean bench e2e

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/authzcov

test:
	go test ./...

vet:
	go vet ./...

# Skips with a warning if golangci-lint is not installed.
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; \
	else echo "warning: golangci-lint not installed, skipping lint"; fi

# Fuzz every Fuzz* target for FUZZTIME each (default 30s).
FUZZTIME ?= 30s
fuzz:
	@for pkg in $$(go list ./...); do \
		for f in $$(go test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz'); do \
			echo "== $$pkg $$f"; go test -run='^$$' -fuzz="^$$f$$" -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

# Regenerate testdata/golden/*.txt; review the diff by hand before committing.
golden:
	go test ./internal/cli -run TestGolden -update

# Needs network to fetch the vulnerability DB.
vuln:
	govulncheck ./...

# Offline gate used by the pre-commit hook.
check-offline: vet lint
	go test -race ./...

# Full gate.
check: check-offline vuln

hooks:
	install -m 0755 scripts/pre-commit .git/hooks/pre-commit
	@echo "pre-commit hook installed"

clean:
	rm -rf bin/

# End-to-end coverage benchmark; ARGS=--update rewrites the baseline in docs/benchmarks.md.
bench:
	scripts/bench.sh $(ARGS)

# End-to-end demo apps (separate Go modules); builds authzcov from source.
e2e:
	cd e2e/apps/tenantshop && go vet ./... && go test ./... && go test -tags e2e -count=1 ./...
