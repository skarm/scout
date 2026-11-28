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
prevents admission. Changed content requires review without exact package approval.
Identical, fully checked inputs can receive allow under the selected policy.

JSON retains both target roles and `run.comparison`. SARIF has separate runs for
each side. Text and Markdown show the delta and target results. See
[report publication and exit codes](usage.md#save-reports).

`--max-changes` defaults to 4096 and accepts 1 through 20000. Omitted changes make
the comparison incomplete without deleting findings. Semantic review requires
upload consent for both versions.

Go callers use `Scanner.Compare` with `scout.DefaultCompareOptions()`.
See [API contracts](../development/go-api.md).

## Pull request summary and package approval

```sh
scout compare --pr-head "$PR_HEAD_REPO@$PR_HEAD_SHA" --pr-path skills/example \
  --report json=/ci-results/update.json -- ./previous ./candidate
```

Use the candidate's actual GitHub repository and full head commit SHA. Scout
uses this information to build source links. Your CI checkout supplies the
matching contents. The summary shows new static operations and declarations per
source file, including recognized network and DNS destinations, command execution, file
mutations, and selected tool and permission declarations. It shows a hostname
when resolved and excludes URL paths and query parameters. The Markdown lists up
to 100 changes. JSON retains the comparison's full bounded results. Observed
capabilities describe the selected static coverage and may differ from runtime
behavior or effective permissions.

After reviewing the output, supply **Candidate package SHA-256** with
`--approved-sha256` from a trusted CI setting. Use the snapshot digest in the
summary or `run.targets[1].analysis.artifact.snapshot_sha256` in JSON. The
comparison hashes the freshly captured files, including their paths, contents
and executable bits. A different digest requires review. An exact match clears
the change-only review requirement. Findings, declaration changes and coverage
still affect the decision under the current policy.

Copy the [GitHub Actions example](../../examples/scout-package-review.yml) into
`.github/workflows` for a package directory present in both PR revisions. Set
`SCOUT_PACKAGE_PATH`, pin a Scout commit that includes these flags in `SCOUT_REF`,
and set `SCOUT_APPROVED_SHA256` after review. Rerun the check after setting the
digest. The job compares the merge base with the PR head and publishes Markdown
in the run summary linked from the PR's Checks tab. For a mandatory gate, use a
trusted workflow and configuration controlled by maintainers so the candidate
cannot change how the check runs.

## GitLab merge requests

```sh
scout compare --pr-provider gitlab --pr-head "$GITLAB_PROJECT_URL@$SOURCE_SHA" \
  --pr-path skills/example -- ./previous ./candidate
```

Use the source project's full HTTP(S) URL, such as
`https://gitlab.example.com/group/subgroup/project`. Links go to the exact
source commit and line. This works for GitLab.com and self-managed instances.

Copy the job from the [GitLab CI example](../../examples/scout-package-review.gitlab-ci.yml)
into the project's `.gitlab-ci.yml`. Use a package directory present in both
revisions, and set `SCOUT_PACKAGE_PATH` and `SCOUT_REF` as for GitHub. Both examples
use the package staging script from the pinned Scout revision. The GitLab job
compares the MR diff base with the source commit, including in merged-results
pipelines. The merge request exposes `scout-review.md` as **Scout package review**,
including when the job exits with review, block or incomplete. After reviewing
the artifact, set the recorded digest as `SCOUT_APPROVED_SHA256` in the trusted
CI/CD configuration and start a new pipeline. For a mandatory gate, keep the
job definition and approval setting under maintainer control.

## MCP reference snapshots

Import already captured MCP results without contacting or starting a server:

```sh
scout mcp snapshot --source-id production/catalog-readonly \
  --output ./reference/server.mcp-snapshot.json ./capture.json
scout mcp snapshot --source-id production/catalog-readonly \
  --output ./candidate/server.mcp-snapshot.json ./new-capture.json
scout compare --profile standard --format json \
  ./reference/server.mcp-snapshot.json ./candidate/server.mcp-snapshot.json
```

The capture contains the `initialize` result and a `tools` result with the combined
tool list. Use result bodies, not JSON-RPC request/response envelopes:

```json
{
  "initialize": {
    "protocolVersion": "2025-11-25",
    "serverInfo": {"name": "catalog", "version": "1"},
    "capabilities": {"tools": {}},
    "instructions": "Read the product catalog."
  },
  "tools": {
    "tools": [{"name": "lookup", "inputSchema": {"type": "object"}}]
  }
}
```

Import rejects duplicate keys or tool names, malformed Unicode, missing required
shapes, any `nextCursor`, and a non-complete `resultType`. Combine every page before
importing. Captures and snapshots are bounded to 256 KiB, 32 JSON levels and 8192
nodes, with at most 256 tools. Schema references are never resolved; JSON Schema
semantics are not validated.

Server implementation `name` and `version` must be present strings; empty values
are retained as display metadata. Source IDs and tool names remain nonempty.

The operator reviews and protects the reference file, then explicitly selects it
as `before`. Creating a snapshot does not grant approval or suppress findings.
The source ID must distinguish the server and authorization context under review;
`serverInfo.name` alone is not a unique identity. The label is an operator assertion,
not proof of remote identity or list completeness. Snapshots contain the imported
descriptions and schemas; store them as source material. Reports retain hashes and
evidence coordinates instead of the values.

JSON `run.comparison.mcp_changes` identifies added/removed tools and changes to
instructions, protocol version, server information, capabilities, tool titles,
descriptions, input/output schemas and annotations. Other protocol fields are
pinned as extension groups. Names match case-sensitively by hash; tool-list and
object-key order do not create MCP declaration changes. Other arrays retain order.
Each change points to original snapshot bytes. A changed source ID or an invalid
or unavailable snapshot leaves comparison unverified. MCP changes share
`--max-changes` with other deltas and require review.

The MCP delta preserves the overall inspection state. Existing JSON extraction
scope limitations still make the full scan incomplete (exit 2), even when the
selected MCP declarations compare completely or have no changes. Inspect the
comparison completeness and MCP changes separately; unchanged declarations do not
prove server or tool safety. Byte-only formatting changes can still require review
under the existing file comparison policy.

Fields follow the [MCP tools specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/2026-07-28/docs/specification/2026-07-28/server/tools.mdx).
