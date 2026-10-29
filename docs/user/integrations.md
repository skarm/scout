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
  --auth-token-env SCOUT_MCP_TOKEN --target candidate=/absolute/review/candidate
```

`scan_skill` accepts an authorized target key or filename/base64 upload up to 128 KiB.
`compare_skills` uses two authorized target keys. Tool arguments cannot choose
arbitrary paths or change the configured profile, provider or approvals.
Without named targets, stdio supports uploads only.

HTTP requires a numeric loopback bind and an explicit bearer secret of at least
32 bytes. Browser origins are denied unless allowed through `--origin`.
The server supports JSON responses, without SSE or GET streaming.

Go's `mcp.New` borrows a Scanner and trusted policy Gate. See [API ownership](../development/go-api.md#coordinates-limits-and-trust).

## Verification

`make host-test` checks permissions, cancellation and exit-code handling using
SDK fixtures and the real CLI. Real-host compatibility requires separate testing.
