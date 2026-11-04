# Pinned external collection candidates

[Русский](README.ru.md)

`sources.json` selects instruction files and their original license texts from
`obra/superpowers` and `trailofbits/skills`. URLs use full Git commit SHAs and each
file has a SHA-256 pin. These are selected files, not complete plugin packages;
referenced files and executable behavior are outside this collection.

The manifest uses `external_unreviewed_corpus` and `ambiguous` labels. Acquisition
does not establish that a package is benign or malicious, and does not create an
independent holdout. These cases cannot pass an evaluation quality gate.

From the repository root, after building `scout-dev`:

```sh
bin/scout-dev corpus collect --manifest testdata/external-corpus/sources.json \
  --allow-download --output /tmp/scout-external-corpus.json
bin/scout-dev evaluate --split holdout /tmp/scout-external-corpus.json
```

Collection performs bounded, credential-free HTTPS GETs without redirects. It
verifies every pin before publishing an output. It never executes source files or
follows their references. A pin mismatch, invalid UTF-8, invalid manifest, source
overlap between splits or acquisition failure leaves an existing output untouched.
Limits: 256 KiB manifest, 4096 files, 1 MiB per file and 8 MiB serialized corpus.

For offline collection, replace a file's `url` with `local`, retaining `sha256`.
Relative local paths are resolved from the manifest directory. Streams, devices
and source-file symlinks are refused; output cannot overwrite the manifest or a
local source. The stored original license files remain part of each case.

Prepare a separate pending review bound to the exact collected corpus bytes:

```sh
bin/scout-dev corpus review-template --corpus /tmp/scout-external-corpus.json \
  --output /tmp/scout-label-review.json
```

A reviewer fills every case with `signal`, `benign` or `ambiguous`, a `reviewer_id`,
a nonfuture RFC3339 `reviewed_at`, a rationale and 1..8 evidence URLs. Evidence
requires credential-free HTTPS without queries; URLs are recorded, never fetched.
The initial `pending` labels and empty fields cannot be evaluated as completed
reviews. Set `independent: true` only after an independent labelling procedure.
Reviewer IDs and independence remain declarations, not identity authentication or
proof of label quality. Keep source families in one split and preserve byte pins.

Select the completed review and its trusted reviewer IDs explicitly when measuring.
Changing even the corpus JSON formatting invalidates the review's SHA-256 binding;
recollecting or modifying sources requires renewed review. The raw corpus remains
unchanged; reviewed labels and the effective corpus kind are applied in memory.

```sh
bin/scout-dev evaluate --split holdout --require-independent \
  --label-review /tmp/scout-label-review.json \
  --trusted-label-reviewer operator-selected-reviewer \
  --min-recall 0.9 --max-fpr 0.05 --max-incomplete 0 /tmp/scout-external-corpus.json
```

Metrics stay in stdout even when a threshold fails. Exit 1 means a failed quality
gate; exit 2 means an invalid request or unfinished measurement. Undefined metrics
cannot satisfy thresholds. A corpus name or free-form `sources[].label_review`
text alone cannot satisfy `--require-independent`. The report stores review and
corpus hashes, used trusted reviewer IDs and case counts, excluding rationales and
evidence URLs. No independent accuracy measurement is supplied here.
