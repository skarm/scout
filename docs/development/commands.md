# Developer commands

Contents

- [Evaluation and release checks](#evaluation-and-release-checks)
- [Saved sources and replay](#saved-sources-and-replay)
- [Source-bound provenance](#source-bound-provenance)
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
  single-file (schema 1) or package (schema 2) corpus. In this command, custom
  selects built-ins only. `--split train|tune|holdout` filters after full corpus
  validation. `--llm-config FILE --allow-source-upload` adds a separate LLM run;
  `--input-usd-per-million N --output-usd-per-million N` records price assumptions.
- `releasecheck --binary SCOUT`: inspect linkage and metadata, then execute fixed
  native self-tests. Add `--inspect-only` to avoid execution.

See [evaluation](evaluation.md) and [validation](validation.md).

## Saved sources and replay

- `verify-knowledge-sources --cache DIR`: verify pinned source bytes. Add `--download`
  to fetch missing files.
- `check-knowledge-runtime --binary SCOUT --output NEW_DIR`: check static scans and
  scripted local reviewer transport.

```sh
scout-dev replay --input captures.jsonl.gz --output replay-results.jsonl \
  --workers 6 --analyzer-workers 1 --case-timeout 5s
```

Replay scans captured code as data and retains stable result order. Incomplete
results and runtime faults are counted separately. Use fresh output directories.

## Source-bound provenance

The recorded receipt is `testdata/provenance/scout-current-review.json`.
Ordinary verification checks its saved artifacts without comparing today's source
files. Code edits do not require a new receipt. Use `provenance verify --current-sources`
only to audit whether that measurement describes the current checkout; the output's
`current_sources_checked` field distinguishes this audit from recorded-evidence verification.

When intentionally recording a new measurement, stage new runs in `.work/`; replace `testdata/provenance/current/` when accepted.
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
release, a commit SHA is sufficient. Verification requires replay and binary
selftests to match that recorded identifier. Exact current source hashes are checked
only with `--current-sources`. The verifier itself may have a different tag or
commit-derived version.
Use `provenance verify --expected-version BUILD_ID` to require a particular
measured identifier as an additional check.

## Tree-sitter memory checks

The C harness requires Go, Clang and downloaded Go modules:

```sh
go run ./internal/dev/treeparsecheck --sanitizer address --output /tmp/treeparse-asan
go run ./internal/dev/treeparsecheck --sanitizer thread --output /tmp/treeparse-tsan
go run ./internal/dev/treeparsecheck --sanitizer none --output /tmp/treeparse-plain
MallocStackLogging=1 leaks --atExit -- /tmp/treeparse-plain 1000
```

The last command is macOS-only. `--uaf-control` and `--leak-control` deliberately
introduce faults to test the detectors. Check Go ownership and concurrent closure
separately with `go test -race ./internal/syntax/treeparse`.
