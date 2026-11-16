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

## Shell hooks

`shell-hooks.sources.json` captures every file of the Trail of Bits `gh-cli`
plugin and the Superpowers `SessionStart` hook, including its wrapper, script
and referenced skill. The Superpowers case covers this hook and omits the rest
of the plugin. Both cases retain their upstream licenses, executable bits and
`ambiguous` labels pending independent review.

```sh
bin/scout-dev corpus collect --manifest testdata/external-corpus/shell-hooks.sources.json \
  --allow-download --output /tmp/scout-shell-hooks.json
bin/scout-dev evaluate --profile standard --split holdout /tmp/scout-shell-hooks.json
```

`shell-hooks.review.json` contains Codex's provisional source review of both
cases. It records evidence from the pinned revisions. Codex also helped prepare
the corpus and has seen its scan results, so the review declares
`independent: false`. An independent reviewer can prepare a fresh review with
`corpus review-template` and assign labels from the pinned sources before seeing
the scan results.

Scout v0.7.0 and the 670cc18-based build both reported findings and partial
coverage for both provisionally benign cases. The evaluator counts any finding
on a benign case as a false positive, giving 2/2 on this pilot. Recall is
undefined because the pilot has no positive cases. Native CI instead checks the
authored `testdata/security-corpus/packages.json` and requires every declared
rule expectation to match. The baseline was 3/3 on both builds.

### Blind review package

The package combines the two pinned upstream cases with four synthetic cases
that exercise comparable hook behavior. Build it with Python 3 and the corpus
from the collection command above. A locally collected corpus works as well.
The builder checks the file sets, digests and executable metadata against the
manifest and calls `corpus review-template`.

```sh
python3 testdata/external-corpus/prepare-shell-hook-review.py \
  --scout-dev bin/scout-dev --upstream-corpus /tmp/scout-shell-hooks.json \
  --output /tmp/scout-shell-hook-review.zip
```

Send the archive to the independent reviewer. It includes the sources, review
instructions and a blank `review.json` bound to the exact `corpus.json` bytes.
Keep scan reports and the provisional review with the operator. After receiving
the completed review, run:

```sh
bin/scout-dev evaluate --profile standard --split holdout --require-independent --shell-hooks \
  --label-review /path/to/completed/review.json --trusted-label-reviewer REVIEWER_ID \
  /path/to/unpacked/corpus.json
```

Use `shell_hooks.metrics` for the behavior defined in the review instructions.
Aggregate metrics in `overall` credit any finding on a positive case. The two
upstream and four synthetic cases provide an initial scenario check.

### Expanded Shell-hook sample

The expansion adds 15 captured plugin scopes from eight repositories.
Candidates came from public repositories with declared Shell hooks and were
selected by configuration and available source before running Scout. The
manifest pins the original hook registrations, handlers, selected local
dependencies and licenses. Cases from a repository share a source ID.

```sh
bin/scout-dev corpus collect --allow-download --timeout 8m \
  --manifest testdata/external-corpus/shell-hooks.expansion.sources.json \
  --output /tmp/scout-shell-hooks-expansion.json
python3 testdata/external-corpus/prepare-shell-hook-review.py \
  --scout-dev bin/scout-dev --upstream-corpus /tmp/scout-shell-hooks.json \
  --additional-manifest testdata/external-corpus/shell-hooks.expansion.sources.json \
  --additional-corpus /tmp/scout-shell-hooks-expansion.json \
  --output artifacts/scout-shell-hook-review-expanded.zip
```

Extract the exact corpus bytes from each archive and pass the completed
expanded review to the evaluator. The archive's `review.json` is the template.

```sh
unzip -p artifacts/scout-shell-hook-review.zip corpus.json > artifacts/shell-hooks.corpus.json
unzip -p artifacts/scout-shell-hook-review-expanded.zip corpus.json > artifacts/shell-hooks.expanded.corpus.json
bin/scout-dev evaluate --profile standard --split holdout --require-independent --shell-hooks \
  --label-review artifacts/shell-hooks.expanded.blind-review.json \
  --trusted-label-reviewer codex-external-blind-reviewer \
  artifacts/shell-hooks.expanded.corpus.json > artifacts/shell-hooks.expanded-completion.evaluation.json
python3 testdata/external-corpus/assess-shell-hook-fpr.py \
  --corpus artifacts/shell-hooks.expanded.corpus.json \
  --baseline artifacts/shell-hooks.corpus.json \
  --report artifacts/shell-hooks.expanded-completion.evaluation.json \
  --target 0.05 > artifacts/shell-hooks.expanded-completion.fpr-assessment.json
```

The assessment counts false positives, fully covered negatives and unresolved
negatives among the new upstream cases. The pilot is excluded. The rate stays
undefined while any of those negatives have unresolved coverage. A one-sided
95% bound for a population FPR assumes independent, representative cases.
Use the repository counts to interpret a sample selected by configuration
and source availability.
The CI regression check uses the versioned `testdata/security-corpus/packages.json`.
Run the external assessment separately with the archived corpus and review.

### Runtime scenarios for three pinned hooks

`check-shell-hook-scenarios.py` checks the pinned expanded corpus and replays
seven selected paths of the original Bash handlers under a macOS sandbox.
It uses Bash 5 or later, locale `C`, temporary input files, and an absolute
plugin path without whitespace or glob characters. The sandbox rejects
network access and restricts subprocesses and writes.

- Ralph Loop continues a valid iteration or stops at its numeric limit.
- Security Guidance takes the POSIX launcher path with no Windows launcher
  cache or `cygpath`. A Python stub verifies both captured script destinations.
- Luca Toolkit receives an absolute transcript path. The scenarios check a
  short session, a successful ingest, and a failed ingest. Git and Claude
  responses are supplied by stubs.

```sh
python3 testdata/external-corpus/check-shell-hook-scenarios.py \
  --corpus artifacts/shell-hooks.expanded.corpus.json \
  --bash /opt/homebrew/bin/bash > artifacts/shell-hooks.conditional-scenarios.json
```

The report records reached Bash lines and verified scenario outcomes. These
runtime checks leave the static coverage and the 134-case FPR sample separate.

### Conditional static analysis for the three pinned hooks

`scout-dev hook-scenarios` checks the corpus and source hashes and analyzes the
registered commands and handler Bash AST with the same seven sets of inputs.
The model uses a temporary filesystem and supplies responses for external
commands. It starts no subprocesses. A scenario is `complete` when Scout
verifies its expected outcome and reaches the required handler lines. The
Security Guidance paths end at Python dispatch. The Luca Toolkit paths use
modeled Claude responses.

```sh
bin/scout-dev hook-scenarios --corpus artifacts/shell-hooks.expanded.corpus.json \
  > artifacts/shell-hooks.conditional-static.evaluation.json
```

The command returns 1 if any scenario remains partial. Ordinary static
coverage and the FPR evaluation use the `evaluate --shell-hooks` command.

### Fresh sample for the FPR threshold

Freeze the repository selection, pinned file bytes and scope before issuing
the blank review. The sample uses one case per owner, excludes known forks and
previously evaluated sources, and records duplicate shell handlers and capture
exclusions. The search frame and retained scope limit the population to which
the result applies.

The 2026-11-15 sample records its search frame and file hashes in
`artifacts/shell-hooks.fpr-blind.sampling.json`. Rerun it with the completed review:

```sh
bin/scout-dev evaluate --profile standard --split holdout --require-independent --shell-hooks \
  --label-review artifacts/shell-hooks.fpr-blind.review.json \
  --trusted-label-reviewer codex-shell-fpr-blind-reviewer \
  artifacts/shell-hooks.fpr-blind.corpus.json > artifacts/shell-hooks.fpr-blind.evaluation.json
python3 testdata/external-corpus/assess-shell-hook-fpr.py \
  --corpus artifacts/shell-hooks.fpr-blind.corpus.json \
  --report artifacts/shell-hooks.fpr-blind.evaluation.json \
  --target 0.05 > artifacts/shell-hooks.fpr-blind.assessment.json
```

The exact one-sided 95% upper bound requires an independent sample with
resolved negative coverage. `corpus_false_positive_rate_bounds` gives the
range on the reviewed sample by counting unresolved negatives first as clean
and then as false positives. The optimistic and pessimistic 95% upper bounds
use the same two counts and assume independent, representative cases. The
assessment also reports the zero-error sample size needed for the chosen
threshold. Add `--require-target` to make a failed or inconclusive threshold
return exit code 1 with the JSON assessment intact.

Once case outcomes have informed changes to Scout, subsequent runs on those
cases measure regressions. To confirm the threshold for the changed scanner,
freeze the scanner and evaluate a fresh sample whose cases and labels were
kept out of development.

For a conditional rerun, pass `--shell-hook-roots FILE` to the same static
evaluation command. The JSON file has a plugin `host`, an absolute `path`
using only ASCII letters, digits, slash, dot, underscore or hyphen, and a
`cases` array of selected Shell-hook case IDs. For example, the 41-case
experiment uses `artifacts/shell-hooks.fpr-static-safe-root-rerun.assumptions.json`.
Use `host: "auto"` to apply the root to Claude Code, Codex and Gemini CLI hook
launches in the selected cases.
The optional `lc_all` field accepts `"C"` or `"POSIX"` and models that locale
at entry to the first captured script. Keep such a run separate from the
measurement with an unspecified locale.
The path models the host-provided root in simple command templates. Scout
still resolves files against the captured plugin; it never sets environment
variables or runs the hook. The evaluation and FPR reports retain the
assumption. Use the result only for launch environments that satisfy it.

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
