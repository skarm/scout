# Acceptance inputs

`upstream-inputs.jsonl.gz` contains the fixed corpus of 14,930 captured inputs.
Treat captured code as scanner data; never execute it.

`make acceptance` checks the corpus digest and input IDs pinned in
`tests/acceptance/provenance_test.go` against the
[current receipt](../provenance/scout-current-review.json).

Keep new run outputs in `.work/`; replace accepted results in
`testdata/provenance/current/`.
