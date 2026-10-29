.DEFAULT_GOAL := help

GO ?= go
GOLANGCI_LINT ?= golangci-lint
NATIVE_TAGS ?= static_link
BIN_DIR ?= bin
PREFIX ?= $(HOME)/.local
DESTDIR ?=
CORPUS ?= testdata/security-corpus/cases.json
LINT_PLATFORMS ?= darwin/arm64 linux/amd64 freebsd/amd64 windows/amd64
VERSION ?=
LDFLAGS ?=
export VERSION LDFLAGS

NATIVE := $(GO) run -mod=readonly ./internal/dev/builddeps --

.PHONY: help deps native-deps build build-core build-dev install test test-core acceptance race host-test evaluate releasecheck lint lint-core lint-nocgo lint-native clean

help:
	@printf '%s\n' \
	  'deps        Download and verify Go modules' \
	  'native-deps Download and verify the pinned native library if missing' \
	  'build       Build $(BIN_DIR)/scout (prepares native library automatically)' \
	  'build-core  Build $(BIN_DIR)/scout-core' \
	  'build-dev   Build $(BIN_DIR)/scout-dev (prepares native library automatically)' \
	  'install     Build and install scout to $(PREFIX)/bin (supports DESTDIR staging)' \
	  'test        Run the native test suite' \
	  'test-core   Run the reduced core test suite' \
	  'acceptance Verify recorded replay and release evidence integrity' \
	  'race        Run the native suite with the Go race detector' \
	  'host-test   Build native and test Pi/OpenCode adapters' \
	  'evaluate    Measure CORPUS with the native scanner' \
	  'releasecheck Build and verify the native binary' \
	  'lint        Lint platform matrix, non-CGO and native builds' \
	  'lint-core   Lint core builds for LINT_PLATFORMS' \
	  'lint-nocgo  Lint non-CGO parser/backend fallbacks' \
	  'lint-native Lint native build (prepares native library automatically)' \
	  'clean       Remove built binaries and disposable .work outputs; preserve dependency cache' \
	  'Paths:      BIN_DIR=bin PREFIX=$$HOME/.local; override either for local or CI builds'

deps:
	$(GO) mod download
	$(GO) mod verify

native-deps:
	$(NATIVE)

build:
	mkdir -p "$(BIN_DIR)"
	$(NATIVE) $(GO) build -mod=readonly -tags=$(NATIVE_TAGS) -trimpath -ldflags="$$LDFLAGS -X github.com/skarm/scout.buildVersionOverride=$$VERSION" -o "$(BIN_DIR)/scout" ./cmd/scout

build-core:
	mkdir -p "$(BIN_DIR)"
	$(GO) build -mod=readonly -tags=coreonly -trimpath -ldflags="$$LDFLAGS -X github.com/skarm/scout.buildVersionOverride=$$VERSION" -o "$(BIN_DIR)/scout-core" ./cmd/scout

install: build
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 "$(BIN_DIR)/scout" "$(DESTDIR)$(PREFIX)/bin/scout"

test:
	$(NATIVE) $(GO) test -vet=off -mod=readonly -tags=$(NATIVE_TAGS) ./...

build-dev:
	mkdir -p "$(BIN_DIR)"
	$(NATIVE) $(GO) build -mod=readonly -tags=$(NATIVE_TAGS) -trimpath -ldflags="$$LDFLAGS -X github.com/skarm/scout.buildVersionOverride=$$VERSION" -o "$(BIN_DIR)/scout-dev" ./cmd/scout-dev

test-core:
	$(GO) test -vet=off -mod=readonly -tags=coreonly ./...

acceptance:
	$(NATIVE) $(GO) test -vet=off -mod=readonly -tags=$(NATIVE_TAGS),acceptance -run TestRecordedAcceptance -count=1 ./tests/acceptance

race:
	$(NATIVE) $(GO) test -vet=off -mod=readonly -tags=$(NATIVE_TAGS) -race ./...

host-test: build
	SCOUT_TEST_BIN="$$(cd "$(BIN_DIR)" && pwd)/scout" node --test internal/distribution/integrations/host_test.mjs

evaluate: build-dev
	"$(BIN_DIR)/scout-dev" evaluate "$(CORPUS)"

releasecheck: build build-dev
	"$(BIN_DIR)/scout-dev" releasecheck --binary "$(BIN_DIR)/scout"

clean:
	rm -f "$(BIN_DIR)/scout" "$(BIN_DIR)/scout-core" "$(BIN_DIR)/scout-dev"
	rm -rf .work

lint:
	@status=0; \
	$(MAKE) lint-core || status=1; \
	$(MAKE) lint-nocgo || status=1; \
	$(MAKE) lint-native || status=1; \
	exit "$$status"

lint-core:
	@status=0; \
	for platform in $(LINT_PLATFORMS); do \
		target_os=$${platform%/*}; target_arch=$${platform#*/}; \
		printf '\nLint core: %s\n' "$$platform"; \
		GOOS="$$target_os" GOARCH="$$target_arch" CGO_ENABLED=0 \
			$(GOLANGCI_LINT) run -v --allow-serial-runners --config .golangci.yml --build-tags=coreonly,acceptance ./... || status=1; \
	done; \
	exit "$$status"

lint-nocgo:
	CGO_ENABLED=0 $(GOLANGCI_LINT) run -v --allow-serial-runners --config .golangci.yml --build-tags=acceptance ./...

lint-native:
	$(NATIVE) $(GOLANGCI_LINT) run -v --allow-serial-runners --config .golangci.yml --build-tags=$(NATIVE_TAGS),acceptance ./...
