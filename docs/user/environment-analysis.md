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
  plus a network operation, or untrusted input plus command execution, file
  mutation or infrastructure mutation, in different skill scopes or roots.
  Evidence roles identify the ordered pair. Shared domains, keywords or a skill
  description alone do not establish these capabilities. A pairing does not
  prove a transfer or a call.
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

The additional capability roles are:

- `untrusted_input`: selected HTTP response APIs, Python `input`, or Shell `read`.
  Request construction alone is excluded. Responses from authenticated endpoints
  still count as external content; this is not a claim that they are malicious.
  A modeled stdin read from a fully literal here-string/document is excluded;
  unknown expansions or input descriptors retain an untrusted-input candidate.
- `command_execution`: selected Go `os/exec`, Node `child_process`/`vm`, Python
  process/evaluation APIs, and explicit Shell interpreter/eval/source/exec calls.
  Constructing a process is a capability candidate even without a visible start.
  Shell builtin help requests and `exec` options without a command are excluded.
- `file_write`: selected filesystem write, append, create, remove, rename,
  directory and permission APIs; Python `open` with a literal writing mode;
  Shell output redirections and selected file-mutating commands. Pure descriptor
  duplication and `/dev/null` output do not contribute file-write facts.
  Operands after Shell `--` remain file operands, including dynamic or dash-prefixed names.
- `infrastructure_mutation`: selected modifying verbs of `kubectl`, `terraform`,
  `helm` and `docker`, either as Shell commands or literal argv passed to modeled
  process APIs. Known global options retain operand roles. Read-only verbs such
  as `get`, `plan` and `list`, help requests, supported dry-run/local modes and
  quoted command descriptions do not contribute this role. Shell command strings inside process API arguments,
  unknown option grammars and arbitrary cloud SDK methods are outside this model.
  Node/Python argv arrays must be inline literals; mutable array bindings and
  Python `shell`/`executable` overrides are excluded. The executable and verb
  must resolve to strings. The broader command-execution capability remains visible.
  Required option values, including values spelled `--help` or `--dry-run`, do
  not act as control flags. Known pflag short clusters preserve their value operand.
  Boolean help/list/local flags retain accepted true/false forms, including `1` and `TRUE`.

Python observations require Python checks to be selected (`standard`, or custom
`--checks python`) and its backend to be available. JS/TS require native grammar
support. Dynamic receivers, general type inference and complete filesystem or
cloud API coverage are not provided. Existing parser and flow gaps remain visible.
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
