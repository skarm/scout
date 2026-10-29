# Static detection evaluation

English · [Русский](evaluation.ru.md)

`scout-dev evaluate` scans a labeled JSON corpus through the public Scanner API
without executing case code. It requires an offline Scanner without OSV or LLM checks.

```bash
# Reduced/core: built-in checks only.
CGO_ENABLED=0 go run -mod=readonly -tags=coreonly ./cmd/scout-dev evaluate \
  --profile custom testdata/security-corpus/cases.json
# Full native build with a trusted PKG_CONFIG_PATH:
CGO_ENABLED=1 go run -mod=readonly -tags=static_link ./cmd/scout-dev evaluate \
  --profile standard testdata/security-corpus/cases.json
```

Standard selects the full static plan. In this command, custom selects built-ins
only. `--timeout` bounds the entire corpus. Use the format in
`testdata/security-corpus/cases.json`; each case is one file.

## Metrics

- `signal` and `known_static_gap` are positive cases. Missing findings count as
  misses, including incomplete scans.
- `benign` with a finding is a false positive. Complete benign scans without
  findings are successful negatives; incomplete ones remain unresolved.
- `ambiguous` cases are excluded from precision/recall.

Metrics use labels and actual findings; `expected_rules` is a regression expectation.
Output retains the corpus hash, engine and plan, case outcomes, category metrics,
incomplete count and local p50/p95 timings. `null` means no denominator.

The bundled 26 authored cases are a regression corpus, not an independent holdout.
For independent evaluation, supply separately reviewed sources, labels, licenses
and hashes with kind `independent_labelled_corpus`. Preserve each run's report.
