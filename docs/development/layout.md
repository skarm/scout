# Repository layout

English · [Русский](layout.ru.md)

Scout uses one Go module. Public packages are `scout`, `report`, `policy`, `baseline`,
`review`, `fetch`, `osv`, `knowledge`, `rulepack` and `mcp`.

- `cmd/scout` and `cmd/scout-dev` are the public and developer entry points.
- `internal/capture` builds the inventory. `internal/syntax` parses captured sources and owns their coordinates.
- `internal/analysis` orchestrates checks and limits. `internal/signatures` owns native signature checks.
- `internal/commands` owns CLI parsing, configuration and output. `internal/discovery` inventories installed components.
- `internal/distribution` owns integration exports, registry snapshots and attestation checks.
- `internal/dev` contains build, evaluation, replay and release tooling.

[Architecture and trust boundaries](architecture.md)

## Code ownership

Language semantics belong to `internal/analysis/languages/<language>`; parsing and
coordinates belong to `internal/syntax`. Language packages export
`Rules() []check.Analyzer` and do not import each other or the common registry.
Shared checks belong to `analyzer`, facts to `check`, and quotas to `analysisbudget`.
Consumers use check contracts directly from `check`. Filename-based display
surfaces live in `syntax/filetype`; they never grant trust or suppress checks.

`environment/surface.go` owns the passive fact inputs for joint environment
analysis. `bundle/surface.go` implements their collection from prepared documents.
The environment evaluator remains independent of collectors and syntax backends.

`internal/promptguard` owns the narrow raw-byte prohibition shared by literal and
native signature checks. It depends only on the standard library; signature
backends do not depend on `internal/analysis`.

Keep unit tests and fixtures beside their package. Use `foo_test.go` for tests of
`foo.go`; separate files when build constraints or a substantial component justify it.
End-to-end Scanner tests live in `tests/`; shared support belongs to `internal/scantest`.
CLI tests stay with the command adapter. Host adapter tests stay with integration assets.

Move embedded assets with their owning package. Preserve license and provenance
references when moving or renaming code. Do not rewrite recorded evidence.

## Documentation and working data

Guides live under `docs/user`, `docs/reference` and `docs/development`. Use the [writing conventions](documentation.md) for English, Russian and GoDoc.

`bin/` holds builds and `.work/` holds temporary reports and metrics. See [build paths](native-build.md#installation-and-output-paths) for overrides and cleanup. Acceptance captures and provenance receipts live under `testdata/`.
