# Required validation data

This directory contains only data read by current tests, developer commands or
source-attribution metadata. Store temporary logs, coverage, benchmarks and new
experimental runs in `.work/` or GitHub Actions artifacts.

## Current acceptance

- `scout-current-review.json` binds the current source hashes to the measured run.
- `current/` contains that run's replay, summary, binary
  selftests and comparison.
- `baseline/replay.jsonl.gz` is the comparison's pinned
  baseline. The current acceptance verifier reads both replays.
- Raw scanner inputs are in `../acceptance/upstream-inputs.jsonl.gz`.

Run `make acceptance` to verify this evidence. When scanner sources change,
regenerate the active evidence using the commands in
[developer commands](../../docs/development/commands.md#source-bound-provenance).
Replace `current/` and the active receipt when updating acceptance. Keep `baseline/`
fixed; do not chain comparisons to previous runs. Stage new runs in `.work/`.
Other run directories are ignored by Git.

## Regression and attribution inputs

- `upstream-inventory.json` pins the upstream source and fixture inventory.
- `upstream-suite-0.20.json` supplies the test-module coverage inventory.
- `upstream-suite-0.21.json`, `upstream-adjudication-0.22.json` and
  `scout-0.22-runtime.tar.gz` support the compatibility-ledger regression test and
  developer adjudication commands. The archive is inspected as data, never run.
- `differential-0.19.json` is referenced by the embedded integration manifest and
  checked by source-reference and integration tests.
- `cisco-hardening-2026-10-29.json` records attribution referenced by root `NOTICE`
  and the port manifest.
