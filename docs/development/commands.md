# Developer commands

Contents

- [Evaluation and release checks](#evaluation-and-release-checks)
- [Saved sources and replay](#saved-sources-and-replay)
- [Source-bound provenance](#source-bound-provenance)
- [External experiments](#external-experiments)
- [Tree-sitter memory checks](#tree-sitter-memory-checks)

English · [Русский](commands.ru.md)

Build the developer CLI alongside Scout:

```sh
make build build-dev
export PATH="$PWD/bin:$PATH"
scout-dev evaluate testdata/security-corpus/cases.json
scout-dev releasecheck --binary "$(command -v scout)"
```

`BIN_DIR` selects another output directory; add that directory to `PATH` instead.

For saved-data commands without native checks, use
`go run -tags=coreonly ./cmd/scout-dev <command> [flags]`.
Maintenance commands accept `--root PROJECT_ROOT` when invoked elsewhere.

## Evaluation and release checks

- `evaluate [--profile standard|custom] [--timeout 2m] CORPUS_JSON`: run a labeled
  corpus. In this command, custom selects built-ins only.
- `releasecheck --binary SCOUT`: inspect linkage and metadata, then execute fixed
  native self-tests. Add `--inspect-only` to avoid execution.

See [evaluation](evaluation.md) and [validation](validation.md).

## Saved sources and replay

- `verify-knowledge-sources --cache DIR`: verify pinned source bytes. Add `--download`
  to fetch missing files.
- `check-knowledge-runtime --binary SCOUT --output NEW_DIR`: check static scans and
  scripted local reviewer transport.
- `compare-upstream-suite prepare --capture SAVED_DIR --replay NEW_DIR`: verify blobs
  and prepare replay inputs.
- `compare-upstream-suite compare --capture SAVED_DIR --replay REPLAY_DIR
  --results RESULTS_JSONL --output DIFFERENCES_JSON`: compare replay with saved observations.
- `adjudicate-upstream-suite --upstream SOURCE --before OLD_DIFFERENCES_JSON
  --after DIFFERENCES_JSON --results RESULTS_JSONL --output LEDGER_JSON`: record reviewed differences.

```sh
scout-dev replay --input captures.jsonl.gz --output replay-results.jsonl \
  --workers 6 --analyzer-workers 1 --case-timeout 5s
```

Replay scans captured code as data and retains stable result order. Incomplete
results and runtime faults are counted separately. Use fresh output directories.

## Source-bound provenance

The active receipt is `testdata/provenance/scout-current-review.json`.
Stage new runs in `.work/`; replace `testdata/provenance/current/` when accepted.
Set `SCOUT_EVIDENCE_DIR` to the replay and release-check directory:

```sh
scout-dev provenance compare --root . \
  --before testdata/provenance/baseline/replay.jsonl.gz \
  --replay "$SCOUT_EVIDENCE_DIR/replay.jsonl.gz" \
  --output "$SCOUT_EVIDENCE_DIR/comparison.json"
scout-dev provenance generate --root . \
  --input testdata/acceptance/upstream-inputs.jsonl.gz \
  --replay "$SCOUT_EVIDENCE_DIR/replay.jsonl.gz" \
  --summary "$SCOUT_EVIDENCE_DIR/summary.json" \
  --releasecheck "$SCOUT_EVIDENCE_DIR/releasecheck.json" \
  --comparison "$SCOUT_EVIDENCE_DIR/comparison.json" \
  --output "$SCOUT_EVIDENCE_DIR/receipt.json"
scout-dev provenance verify --root . \
  --manifest "$SCOUT_EVIDENCE_DIR/receipt.json"
```

Artifacts must reside inside the project root. Changed observations require
adjudication with a reason and regression-test reference before generating a receipt.
Acceptance uses `testdata/acceptance/upstream-inputs.jsonl.gz`.
Explicit `--input-mode pinned` is available for separate checks without that capture.

The receipt's `engine_version` identifies the measured build; before the first
release, a commit SHA is sufficient. Verification checks exact source hashes and
requires replay and binary selftests to match that recorded identifier. It does
not require the verifier itself to have the same tag or commit-derived version.
Use `provenance verify --expected-version BUILD_ID` to require a particular
measured identifier as an additional check.

## External experiments

These commands execute external tools and are separate from ordinary Go gates:

- `compare-upstream --upstream-source SOURCE --skillspector CLI
  --scout SCOUT --output NEW_DIR`: compare the pinned corpus through both CLIs.
- `run-upstream-suite --upstream SOURCE --python PYTHON --output NEW_DIR`: run the
  pinned pytest suite under macOS `sandbox-exec`, with public networking denied.

## Tree-sitter memory checks

The C harness requires Python 3, Clang and downloaded Go modules:

```sh
python3 internal/dev/maintenance/treeparse_sanitize.py --sanitizer address --output /tmp/treeparse-asan
python3 internal/dev/maintenance/treeparse_sanitize.py --sanitizer thread --output /tmp/treeparse-tsan
python3 internal/dev/maintenance/treeparse_sanitize.py --sanitizer none --output /tmp/treeparse-plain
MallocStackLogging=1 leaks --atExit -- /tmp/treeparse-plain 1000
```

The last command is macOS-only. `--uaf-control` and `--leak-control` deliberately
introduce faults to test the detectors. Check Go ownership and concurrent closure
separately with `go test -race ./internal/syntax/treeparse`.
