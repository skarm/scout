# Detection evaluation

English · [Русский](evaluation.ru.md)

`scout-dev evaluate` scans a labeled JSON corpus through the public Scanner API
without executing case code. The default is an offline static run. An optional
second run measures LLM proposals separately, using an explicitly supplied provider.

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
`testdata/security-corpus/cases.json` for schema 1; each case is one reader file.

## Packages and split isolation

Schema 2 scans each case as one directory with multiple regular files. Files are
materialized in a private temporary directory and removed after both scan modes.
The `executable` flag retains file metadata for analysis; no file is executed.
Materialized file type, size and executable bits must match the corpus. If the
filesystem cannot preserve them (including executable bits on Windows), evaluation
fails instead of measuring different input metadata. Corpus and configuration
inputs must be regular files; FIFOs and devices are refused before reading.
File paths must be relative portable ASCII paths, without traversal, backslashes,
Windows device names, case aliases, duplicate paths or file/directory conflicts.
File contents may contain Unicode. Limits: 8 MiB corpus JSON, 4096 cases, 4096
sources, 1024 files, 8192 total file/directory entries and 32 path components per
package. Namespace limits apply before temporary directories are created; normal
Scanner capture/analysis limits still apply. Files are created exclusively, so a
filesystem alias cannot overwrite an earlier file in the package.

```json
{
  "schema_version": 2,
  "kind": "independent_labelled_corpus",
  "sources": [{
    "id": "package-family-a",
    "origin": "https://example.invalid/repository-a",
    "revision": "reviewed-revision-or-source-sha256",
    "license": "MIT",
    "label_review": "Reviewer and labeling procedure; external evidence reference"
  }],
  "cases": [{
    "id": "package-a", "category": "documentation", "label": "benign",
    "source_id": "package-family-a", "split": "holdout",
    "expected_rules": [],
    "files": [
      {"path": "README.txt", "content": "Summarize the local notes.\n"},
      {"path": "references/notes.txt", "content": "Keep paragraph order.\n"}
    ]
  }]
}
```

This is a format example, not independently reviewed data. Every source needs an
origin, pinned revision or source hash, license and label-review record. Group
forks, revisions and related variants under the same source ID. A source ID or
exact origin may occur in only one of `train`, `tune`, `holdout`. Identical
nonempty file bytes in different splits are rejected even after renaming files.
Shared boilerplate must stay in one split or be excluded from the corpus.
Duplicate JSON keys and case aliases are rejected.

```bash
bin/scout-dev evaluate --split holdout testdata/security-corpus/packages.json > evaluation.json
```

Without `--split`, all cases are measured, with separate per-split metrics.
The **entire** corpus is validated before filtering, so an unselected split
cannot hide contamination. These checks cannot establish source authenticity,
semantic deduplication, independence from model training data or correct labels.
The bundled `packages.json` contains five authored format/regression cases;
its `holdout` partition is **not an independent holdout**.

## Optional LLM measurement

Use an operator-owned `scout.config/v1` with an explicit `review` provider,
endpoint, model and budgets; see [configuration](../user/usage.md)
and [semantic review](../user/semantic-review.md).
`--llm-config` supplies the scanner profile and is mutually exclusive with
`--profile`. For reduced builds, use `profile: custom` and explicitly disable
`patterns`, `python`, `yaml`, `toml`, `yara` in `checks`. This retains built-in
checks. Native builds may use `profile: standard` or `review`.

Example `operator-review.json` (replace the endpoint/model with your trusted service):

```json
{
  "schema": "scout.config/v1",
  "profile": "standard",
  "review": {
    "provider": "chat-completions",
    "endpoint": "https://reviewer.example.invalid/v1/chat/completions",
    "model": "operator-selected-model",
    "key_env": "SCOUT_EVAL_API_KEY",
    "max_requests": 16,
    "max_input_bytes": 262144,
    "max_output_tokens": 2048,
    "timeout": "30s"
  }
}
```

```bash
bin/scout-dev evaluate --llm-config operator-review.json --allow-source-upload \
  --split holdout --input-usd-per-million 2 --output-usd-per-million 4 \
  testdata/security-corpus/packages.json > evaluation-with-llm.json
```

The prices above are illustrative operator assumptions in USD per million tokens,
not current provider prices. Supply both prices or omit both. Credentials come
only from variables explicitly named in the config. No default provider, implicit
source upload, vulnerability lookup, download, baseline, extra rule file, advisory
cache or remote pin is accepted. Evaluation always uses its own high-severity
policy; config policy thresholds do not change signal counting.

Each case first runs through a separate offline Scanner with the same static
settings, then through a Scanner with review enabled. Top-level metrics remain
static. `llm` metrics count only validated model proposals; static findings and
model confirmations of those findings do not become LLM detections. Proposals
remain advisory even if a follow-up model assessment disputes them. LLM scan
timings include the second scan's static work and all review stages, not just
provider latency. Review request budgets apply per case; `--timeout` covers the
whole corpus and both modes.

## Metrics

- `signal` and `known_static_gap` are positive cases. Missing findings count as
  misses, including incomplete scans.
- `benign` with a finding is a false positive. Complete benign scans without
  findings are successful negatives; incomplete ones remain unresolved.
- `ambiguous` cases are excluded from precision/recall.
- `false_positive_rate` is FP / (FP + complete benign negatives), and is `null`
  when the denominator is absent or any benign case remains unresolved.

Metrics use labels and actual findings; `expected_rules` is a regression expectation.
Report schema 2 retains the corpus hash, engine/rulepack and plans, case outcomes,
category/split metrics, incomplete counts and local p50/p95 timings. Undefined
ratios are `null`. `selected_cases` and `completed` distinguish an interrupted
measurement from one that attempted the whole selection. Completed cases are
preserved on cancellation with exit code 2. A completed evaluation exits 0 even
when individual scans fail: failures remain in metrics, not successful negatives.

With LLM enabled, each case records provider identity, prompt/schema digests,
effective review settings and usage without source content, endpoint URLs or raw
provider errors. `known_input_tokens` / `known_output_tokens` sum provider-reported
counts; missing, failed or unvalidated responses make usage incomplete. Cost is
`null` without both price assumptions or complete usage. It excludes provider
pricing details such as caching, routing discounts, minimum charges and taxes;
it is not an invoice. Tests use a synthetic protocol provider, not a real model.
Cases without any planned review request remain unresolved in LLM metrics.

The bundled 26 authored cases are a regression corpus, not an independent holdout.
For independent evaluation, supply separately reviewed sources, labels, licenses
and hashes with kind `independent_labelled_corpus`. Preserve each run's report.
