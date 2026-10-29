# Validation

English · [Русский](validation.ru.md)

Run from the project root. Full checks require [native dependencies](native-build.md).

## Tests

```sh
make test-core
make test
make race
make host-test
```

`test-core` checks the reduced build and unavailable backends. `test` and `race`
exercise native parsers and signatures. `host-test` requires Node and checks host
adapters against SDK fixtures and the real CLI. Go tests do not require Python.

Make test targets use `-vet=off`; linting runs separately.

## Binary and source acceptance

```sh
make releasecheck
make acceptance
```

`releasecheck` checks the built binary's linkage, metadata and native self-tests.
`acceptance` verifies source closures, capture IDs, replay, release checks and
adjudicated observation changes against `testdata/provenance/scout-current-review.json`.
Native CI requires acceptance.

Receipts hash full source bytes, so Go comment edits also invalidate them.
Generate fresh evidence through the [provenance commands](commands.md#source-bound-provenance)
rather than editing recorded hashes. Inputs under `testdata/` survive `make clean`.

## Lint

```sh
make lint
```

The default matrix covers core builds for `darwin/arm64`, `linux/amd64`,
`freebsd/amd64` and `windows/amd64`, plus host non-CGO and native builds.
Every run includes the `acceptance` tag. Change the matrix with `LINT_PLATFORMS`.
Individual targets are `lint-core`, `lint-nocgo` and `lint-native`.

## Interpreting results

Regression tests and scripted providers check implementation behavior. They do not
measure live-model quality or independent detection accuracy. See
[evaluation](evaluation.md) and [knowledge runtime checks](../reference/knowledge-runtime.md).
Real-host and target-platform compatibility require separate acceptance.
