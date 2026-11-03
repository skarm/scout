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
