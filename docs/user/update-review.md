# Update comparison

English · [Русский](update-review.ru.md)

`compare` rescans two local versions with one Scanner and compares their observed
content. Both sides retain findings; policy considers every candidate finding.

```sh
scout compare --profile standard --format markdown ./previous ./candidate
scout compare --profile standard --max-changes 4096 \
  --format json --output /ci-results/update.json ./previous ./candidate
```

The operator prepares both copies. URLs and download controls are rejected.
The shared timeout covers both scans and the delta.

## Compared changes

- Files match by relative path; two standalone files share one input slot.
- Extracted archive members match by name, other transforms by parent and ordinal.
- Components compare as multisets without guessed renames for unnamed hooks.
- Dependencies compare declarations rather than inferred installed versions.
- Findings match by check identity and exact evidence; duplicates remain separate.
- Manifest signals record selected declaration and permission changes.

Finding statuses are `introduced`, `relocated`, `context_changed`, `not_observed`
and `unverified`. `not_observed` does not prove remediation. Incomplete checks or
unavailable objects make affected comparisons `unverified`.

## Decision and output

A blocked candidate remains blocked. Incompleteness on either side or in the delta
prevents admission. Changed content requires review even without new findings.
Identical, fully checked inputs can receive allow under the selected policy.

JSON retains both target roles and `run.comparison`. SARIF has separate runs for
each side. Text and Markdown show the delta and target results. See
[report publication and exit codes](usage.md#save-reports).

`--max-changes` defaults to 4096 and accepts 1 through 20000. Omitted changes make
the comparison incomplete without deleting findings. Semantic review requires
upload consent for both versions.

Go callers use `Scanner.Compare` with `scout.DefaultCompareOptions()`.
See [API contracts](../development/go-api.md).
