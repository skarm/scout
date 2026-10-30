# Repository layout

English · [Русский](layout.ru.md)

Scout uses one Go module. Public packages are `scout`, `report`, `policy`, `baseline`,
`review`, `fetch`, `osv`, `knowledge` and `mcp`.

```text
scout/
├── *.go                         # Scanner API; scan_test.go checks private helpers
│   └── doc.go                   # package documentation
├── cmd/{scout,scout-dev}/        # entrypoints
├── report/                      # independent public contract
├── policy/                      # policy evaluation of a sealed Run
├── baseline/                    # trusted approvals
├── review/                      # public provider protocols
├── fetch/                       # public download configuration
├── osv/                         # OSV and offline cache
├── knowledge/{data,prompts,sources}/
├── mcp/                         # public server API
├── internal/
│   ├── buildinfo/               # module versions embedded in the running binary
│   ├── capture/                 # ingest, artifact, rootfs, archives, extraction, external
│   ├── syntax/                  # parsers, frontend, language/filetype, source maps
│   ├── analysis/
│   │   ├── languages/{golang,python,shell,javascript,sql,literals}/
│   │   ├── analyzer/            # common catalog and cross-language checks
│   │   ├── check/               # Analyzer, Match, Facts and binding contract
│   │   ├── sourcepolicy/        # offline default package-source predicates
│   │   ├── document/            # prepared source views
│   │   ├── engine/              # orchestration and budgets
│   │   └── other analysis packages
│   ├── signatures/{rules,testdata}/
│   ├── distribution/{integrations,skills,registry,attestation}/
│   ├── discovery/               # passive agent configuration and component inventory
│   ├── commands/{cli,devcli,output}/
│   ├── dev/{maintenance,evaluation,replay,replaywire,provenance,releasecheck}/
│   ├── nativecheck/
│   ├── nativecontract/
│   ├── netpolicy/
│   ├── textmatch/
│   ├── architecture/
│   └── scantest/scenarios/
├── tests/{api,scan,languages,regression,acceptance,performance}/
├── testdata/                    # inputs, acceptance captures and provenance receipts
├── docs/{user,development,reference}/
├── licenses/
├── .github/workflows/
├── bin/                         # ignored: default build output; configurable with BIN_DIR
└── .work/                       # ignored: temporary artifacts, coverage and metrics
```

## Code ownership

Language semantics belong to `internal/analysis/languages/<language>`; parsing and
coordinates belong to `internal/syntax`. Language packages export
`Rules() []check.Analyzer` and do not import each other or the common registry.
Shared checks belong to `analyzer`, facts to `check`, and quotas to `analysisbudget`.
Consumers use check contracts directly from `check`. Filename-based display
surfaces live in `syntax/filetype`; they never grant trust or suppress checks.

Keep unit tests and fixtures beside their package. Use `foo_test.go` for tests of
`foo.go`; separate files when build constraints or a substantial component justify it.
End-to-end Scanner tests live in `tests/`; shared support belongs to `internal/scantest`.
CLI tests stay with the command adapter. Host adapter tests stay with integration assets.

Move embedded assets with their owning package. Preserve license and provenance
references when moving or renaming code. Do not rewrite recorded evidence.

## Documentation and working data

English guides use `.md`; Russian counterparts use `.ru.md`. Source GoDoc is English.
See [writing conventions](documentation.md).

`bin/` is the default binary output directory; `BIN_DIR` can point elsewhere.
`make install` copies Scout to `PREFIX/bin` (default `~/.local/bin`). `.work/`
holds temporary reports, coverage and metrics. `make clean` removes the built
binaries and `.work/`, preserving installed copies. Acceptance captures live in
`testdata/acceptance/`; saved replay and receipts live in `testdata/provenance/`.
Native dependencies use the user cache.
