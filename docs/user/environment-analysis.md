# Analyze one selected environment

English · [Русский](environment-analysis.ru.md)

`scout scan --environment` relates the selected local roots as components of
one agent/project environment. Each root keeps its ordinary scan result.
`ScanMany` and `scan` without this flag continue to inspect independent inputs.
Select roots for one context explicitly; Scout does not establish which cached
versions or declarations are active.

```sh
scout scan --environment --format json ./skills ./mcp.json
scout discover --agent codex --scan -- --environment --format markdown
scout discover --agent claude-code --project /work/repo --scan -- --environment
```

Discovery requires one explicit `--agent` and at most one selected project for
this mode. Use `--no-project` to inspect user/system declarations without a
project. Split unrelated projects or agents into separate invocations. As with
ordinary discovered scans, discovery must complete and produce 1..32 roots.

Explicit scan roots must exist and must not overlap or alias each other.
Stdin, remote targets and external reference traversal are not supported.
Components, hooks, scripts and MCP servers are never executed or contacted by
environment analysis. Optional per-target review and advisory services retain
their existing explicit grants.

## Observations

The sealed `scout.report/v1` report gains an optional `run.environment` object,
using `scout.environment-analysis/v1`. It records:

- `mcp_name_collision`: the same root-level `mcpServers` / `mcp_servers` alias
  appears in different captured files or targets. These are server aliases,
  not fetched runtime tool names. Saved project maps are not merged into this
  namespace.
- `tool_name_collision`: captured root `tools` or `result.tools` arrays declare
  the same unqualified name in different files or targets. Host qualification
  and precedence remain unknown. Arbitrary nested examples are not joined.
- `capability_combination`: selected code observers find sensitive-data access
  and an outbound network operation in different skill scopes or roots. Shared
  domains, the words “token” or “config”, or a skill description alone do not
  establish these capabilities. A pairing does not prove a transfer or a call.
- `skill_reference`: a literal relative Markdown link names another captured
  `SKILL.md` in the same target. This records a reference, including quoted
  links; it does not establish invocation or authority. Remote, escaped and
  outside-root links are not resolved.

Capability collection reuses Scout's bounded Go/JS/TS/Python/Shell/SQL observers
on the captured documents. A nearest skill determines ownership; otherwise a
source file remains a separate scope. Archive/decoded objects are still checked
individually, but their relationships are outside the environment analysis.
Supported Shell file reads include `cat`, input redirections and curl file bodies
or uploads. Literal `~/` paths use symbolic HOME or an in-script constant; the
scanner's environment and credential files are never consulted. Unresolved HOME
after unknown shell effects leaves analysis incomplete.
Missing parser support, failed capture, cancellation or an exhausted budget
cannot become a complete environment result.

Each observation contains two evidence records with `target_id`, role, original
path, byte range, object hash and span hash. Equal relative paths in separate
targets remain distinct. Reports omit raw names, URLs, commands and source bodies.
The run digest binds the observations. JSON preserves the full object; text and
Markdown show evidence coordinates; SARIF retains it in `properties.environment`.

Collisions and capability combinations always require policy review. Static
blocking findings still block. Per-target baseline approvals cannot suppress an
environment observation. A skill reference alone does not require review.
Exit codes retain their meaning: 0 for policy allow after complete inspection,
1 for review/block after complete inspection, and 2 for any incomplete inspection
or operational failure. Existing per-target gaps, including extraction limits,
remain visible and still produce code 2.

## Bounds and API

At most 4096 facts are retained per root. Each root reserves a quarter of its
remaining analysis operations for collection. An eighth of the run's operation
budget is reserved for joining facts, capped at 100,000 operations. Retained
observations are capped by `--max-findings` and a hard ceiling of 4096. Omitted
observations or work produce explicit issues and a partial result; previously
retained evidence remains available.

Go callers opt in through `scanner.ScanEnvironment(ctx, targets)`. It returns
the same sealed `report.Run` contract as `ScanMany`, with `Environment` populated.
Treat `ErrIncomplete` as a partial result and evaluate the returned run with the
trusted policy gate. Do not infer coverage of runtime MCP tool descriptions or
the effective installed environment from a complete static result.
