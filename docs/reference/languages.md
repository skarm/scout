# Languages and configuration formats

English · [Русский](languages.ru.md)

Scout analyzes captured code, Markdown code blocks and supported attachments
without starting the inspected programs. `scout capabilities` lists available backends.

## Go

`go/parser` builds ASTs without importing inspected packages. GO001–GO006 check
shell construction, sensitive files, selected credential-to-HTTP flows, dynamic
SQL and disabled TLS verification. Aliases and local shadowing are considered;
general type resolution and a complete call graph are unavailable.

## Python

The full build uses Tree-sitter and a bounded projection from a concrete syntax tree
(CST) to an intermediate representation (IR), without a Python runtime.
Checks cover selected process/eval/import operations, sensitive files,
network arguments, deserialization, reconstruction and local flows.
Unsupported constructs and unresolved flows remain gaps.

## Shell

The bounded shell parser checks pipelines, assignments, redirects, substitutions and selected branches. `mvdan.cc/sh/v3/syntax` supplies command and source declarations. `SH001`–`SH004` cover download-to-execution, credentials in requests, execution capabilities and sensitive reads. Dynamic arguments and unsupported control flow leave coverage gaps.

### Hooks and local handlers

Scout reads supported hook events in `hooks.json`, local hook files referenced by plugin manifests, and Claude project settings in `.claude/settings.json` or `.claude/settings.local.json`. Claude project hooks can be inspected without a plugin manifest. Gemini hooks use `hooks/hooks.json` beside `gemini-extension.json`. [Claude Code hooks](https://code.claude.com/docs/en/hooks) · [Gemini CLI extensions](https://geminicli.com/docs/extensions/reference/)

The tracer follows fixed command strings, explicit interpreter arguments and resolved local launches, including `source` and `.`. It records the hook event, call or include path and original source bytes. Relative paths need a known working directory. Quoted host-root paths can resolve within the captured package. An unquoted root can produce a candidate with `hook_source_unquoted_root`; a Gemini substitution can also leave a gap when the installation path is unknown.

Selected assignments, function calls, branches, loops, substitutions and numeric guards preserve statically known bindings. Ambiguous or dynamic commands, paths, interpreter operands, writes and lookup effects can leave a gap. Supported Bash or POSIX shell command text and PowerShell `-Command` are reported separately from file sourcing. `SH003` also records explicit `npm run` calls from captured hook sources.

### Generated scripts

Scout recovers supported `cat` and `tee` heredoc writes and verified shell stdin. A filename, shebang or modeled shell use can establish that content is shell code. Recovery follows up to four generations within shared limits. Findings map back to the enclosing file or archive member, including substituted text.

`SH005` links a recovered write to a later shell use through supported appends, renames and working-directory changes. It also records supported redirects to `CLAUDE_ENV_FILE` in traced Claude hooks. An unresolved destination or append base can produce `generated_shell_dynamic_path` or `generated_shell_append`. Unknown effects can invalidate earlier links.

## JavaScript and TypeScript

The full build uses the official Tree-sitter grammars. `JS001`–`JS006` check shell APIs, dynamic evaluation, credentials in network arguments, dynamic SQL, sensitive files and disabled TLS verification. Analysis considers selected ESM and CommonJS imports, aliases, destructuring, shadowing and branches. Unsupported flows leave coverage gaps. Core and non-CGO builds report unavailable grammars.

If a hook resolves to captured source, Scout can link supported Node process calls to the hook. It can also analyze literal `node -e` and `python -c` programs or quoted Python heredocs. Findings cite the embedded program and its hook. Only selected isolated `python3 -I -S` programs, such as a literal JSON transformation with bounded inputs, can complete hook coverage statically. Dynamic module resolution and runtime behavior can leave gaps. [Node child processes](https://nodejs.org/api/child_process.html) · [Python command-line options](https://docs.python.org/3/using/cmdline.html#cmdoption-I)

## SQL

The Go parser works in core builds. SQL001–SQL004 check selected destructive
operations, authority and row-level security (RLS) changes, server filesystem/program I/O and disabled limits.
Comments, strings and identifiers are distinguished. Dollar-quoted procedural bodies
remain unsupported. Go and JS/TS SQL interpolation is checked on their own ASTs.

## Markdown

Goldmark parses CommonMark block containers, including nested lists, blockquotes,
fenced code and indented code. Code views preserve LF and CRLF, project bare CR
as LF, and retain physical byte coordinates after removing container prefixes. Unlabelled indented code uses
only existing narrow language hints; an unknown language remains a coverage gap.
Fences inside HTML blocks are inspected in a separate bounded raw-content pass;
HTML/runtime semantics remain unsupported. No rendering or reference fetching occurs.
Limits: 1 MiB per Markdown input, 2 MiB aggregate parsing bytes including HTML
projections, 64 container levels, 8192 block nodes, 512 regions, 8192 source segments
and 256 KiB per code view. Cancellation or a limit preserves available blocks and
raw checks and makes coverage incomplete.

## Configuration formats

JSON checks duplicate decoded keys. The full build provides general YAML and TOML
parsing. The core build also recognizes Codex, Grok and Kimi Code configuration
TOML and DeepSeek Cordis YAML in known layouts. YAML aliases, merges and custom
tags are unsupported. TOML evidence covers the entire parsed unit.
Parsing does not establish compatibility with every host loader.

## Scope

Cross-file flows use selected captured imports and functions: [flow checks](hardening-2026-10-29.md#data-flows).
Parser failures, unsupported forms and exhausted budgets remain visible gaps.
`complete` refers to selected checks; [policy scope](../user/inspection-profiles.md#scope)
controls declared language limitations.
