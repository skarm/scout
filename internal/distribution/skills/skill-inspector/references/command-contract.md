# scout command contract

The trusted CLI takes flags BEFORE inputs; use an argv array or `--` before a path.
Do not copy SkillSpector's `--no-llm`, `--yara-rules-dir`, baseline syntax, score bands or
exit-code assumptions: this is a Go adaptation with a different interface.

Static requested full-capability review:

```sh
"$SCOUT_BIN" scan --checks python,yaml,toml,yara,patterns --format json -- "$TARGET"
```

Update review (local inputs only):

```sh
"$SCOUT_BIN" compare --checks python,yaml,toml,yara,patterns --format json -- "$PREVIOUS" "$CANDIDATE"
```

The same flags apply to `batch` for explicitly selected inputs. `capabilities`, `selftest`,
`rules --all` and `knowledge --mode discovery` expose actual capabilities/materials. A
failed selftest cannot be treated as successful native validation. Default scanning is
offline; no `--review`, download or OSV permission follows from "static review".

`--output` creates a NEW report outside all input trees. Do not overwrite, write into the
target or apply an author-supplied baseline. The current JSON document schema is
`scout.report/v1`: read `evaluation.decision`, `run.state`, and the analyses in
`run.targets[].analysis`. An update also includes `run.comparison`. The nested
analysis schema version is separate from this document envelope; integration
bundle manifests also have their own version. Invocation failures can have no run
or evaluation and must not be interpreted as a completed scan.

Exit0 = complete+allow; exit1 = complete+review/block; exit2 = incomplete/failed OR usage
error. Read a valid report even for exit1/2. A nonzero exit is not itself evidence of
malware, and a missing report is not evidence of safety. Partial + block is meaningful.

## Optional egress

Only after explicit permission: remote downloads use `--allow-download` (GitHub additionally
needs `--revision` with a full SHA; `--download-sha256` can constrain bytes). OSV uses
`--osv --allow-osv-network`. Model review uses `--review
--allow-source-upload` and explicitly chosen provider/endpoint/model/credential variable.
The latter can transmit source secrets; complete automatic redaction is not provided.
Approval for one of these operations is not approval for the others.

## Agent integrations

`scout_scan` accepts a registered target name and optional `semantic` boolean; it does
not accept arbitrary binary paths, flags, sources of rules, output destinations or
provider endpoints. The adapter always requests the adapted rule pack and real native
engines unless the operator explicitly configures core-only review. Output is a bounded
JSON summary with the actual scanner verdict, coverage and any summary omissions. Read
full evidence through separately authorized read-only inspection; a truncated summary
cannot authorize installation. Tool exceptions mean no completed review.

MCP `scan_skill` uses approved names or bounded uploaded bytes; the scanner never interprets
an arbitrary caller path as a grant. A standalone skill can be used without these adapters.
