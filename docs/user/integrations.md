# Integrations and MCP

English · [Русский](integrations.ru.md)

## Reviewer bundles

```sh
scout integrations list
scout integrations export --bundle agent-skill --output /tmp/scout-reviewer.zip
scout integrations export --bundle opencode --output /tmp/scout-opencode.zip
```

Available layouts are `agent-skill`, `claude-code`, `codex`, `pi`, `opencode` and
`review-materials`. Exports create new ZIP files with English/Russian instructions,
licenses and a file manifest. They do not install the bundle.
See [bundle setup](../../internal/distribution/integrations/assets/README.md).

## Pi and OpenCode

The operator supplies an absolute `SCOUT_BIN` and named targets in `SCOUT_TARGETS`.
The model chooses only a target alias and optional `semantic` flag. Pi requests
interactive confirmation; OpenCode uses `context.ask`.

The default profile is standard. Semantic review requires a configured `SCOUT_REVIEWER`
and separate upload permission. `SCOUT_REDUCED_CORE=1` explicitly selects custom
checks without native backends. The tool preserves partial/blocked results and
returns a bounded summary. Use a separate CLI call when the full report is needed.

## MCP server

```sh
scout mcp --profile standard --transport stdio \
  --target candidate=/absolute/review/candidate
scout mcp --profile standard --transport http --listen 127.0.0.1:8837 \
  --token-env SCOUT_MCP_TOKEN --target candidate=/absolute/review/candidate
```

`scan_skill` accepts an authorized target key or an upload with a filename and
base64 content. Decoded upload content is limited to 128 KiB.
`compare_skills` uses two authorized target keys. Tool arguments cannot choose
arbitrary paths or change the configured profile, provider or approvals.
Without named targets, stdio supports uploads only.

Reports include the same JSON in `structuredContent` and in a text block when
both fit in the 8 MiB JSON-RPC response limit (excluding the trailing newline).
If only the structured report fits, the text block is a summary, not a partial
JSON document. If the structured report with the summary cannot fit, the server
returns a JSON-RPC error; no approval is inferred.

The CLI HTTP transport requires a numeric loopback bind and an explicit bearer secret of
32–512 bytes. Browser origins are denied unless allowed through `--origin`.
The server supports JSON responses, without SSE or GET streaming.
After initialization, include the returned `Mcp-Session-Id` on subsequent
requests. POST and DELETE without it return HTTP 400, except for the initial
POST. An expired or terminated session returns HTTP 404 on POST, GET or DELETE;
GET without an ID or with an active session ID returns HTTP 405 because SSE is
not available.

The server negotiates MCP `2025-06-18` over JSON-RPC 2.0. Request parameter names
are case-sensitive; request metadata belongs in an optional `_meta` object within `params`.
Numeric request IDs use the signed 64-bit range; decimal and exponent spellings
of integers are accepted and echoed unchanged. Message, depth and node limits
still apply. HTTP authentication scheme names are case-insensitive; bearer
secrets are compared exactly. Responses with status 401 include a
`WWW-Authenticate` header with the Bearer scheme.

Go's `mcp.New` borrows a Scanner and trusted `policy.Gate`.
See [API ownership](../development/go-api.md#coordinates-limits-and-trust).

## Verification

`make host-test` checks permissions, cancellation and exit-code handling using
SDK fixtures and the real CLI. Real-host compatibility requires separate testing.
