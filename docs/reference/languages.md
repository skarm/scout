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

Scout also analyzes command handlers for supported events in `hooks.json`.
It also accepts captured files with other names when the plugin manifest's
`hooks` field resolves to them within the same package.
It maps shell command strings and fixed `bash -c` or `sh -c` arguments, including
the explicit `command` plus `args` form, back to the JSON bytes. Findings retain
the hook event and physical file coordinates. An unresolved command string
argument leaves a coverage diagnostic.

Bounded command trees cover pipelines, assignments, redirects and substitutions.
`mvdan.cc/sh/v3/syntax` separately supplies command/source declarations.
SH001–SH004 check download-to-execution, credentials in requests, eval/source/shell
capabilities and sensitive reads. Selected curl/wget options and saved-file provenance
are tracked. Dynamic arguments and unsupported control flow limit completeness.

Scout reconstructs `cat` and `tee` heredoc writes to relative paths. Shell
evidence comes from a `.sh` suffix, a shell shebang, or a later modeled use
through a shell interpreter, `source`, `.`, or an explicit executable path.
For direct execution of other filenames, an explicit non-shell shebang prevents
shell recovery. This works in supported blocks, functions, pipelines with explicit
stdin, and files captured from archives. The same shebang parser identifies the
interpreter for ordinary files and generated scripts. It handles a fixed
interpreter path and simple `env` or `env -S` forms. Scout also analyzes verified
heredocs read directly by a shell on stdin, including an unchanged `cat | sh`
pipeline. Scout resolves simple parameters from
preceding, unambiguous assignments and analyzes up to four nested generations
under shared limits. Findings retain byte and line coordinates in the
enclosing captured file or archive member. Substituted text cites the parameter
reference that produced it. Observed effects from functions, traps, PATH and
command hash entries can make a writer's identity or its input uncertain.
Scout evaluates statically resolved local function calls with the bindings and
lookup state at each call site, including simple temporary assignments and known
positional arguments such as `$1` and `${10}`. Later
changes to `PATH` or `hash` do not affect an earlier resolved call. Uncalled
functions and unresolved calls use conservative file-wide effects. Recursion,
unresolved expansions, uncertain writers and exhausted limits leave coverage gaps.

Recognizable shell writes with unresolved destinations, such as `"${name}.sh"`,
report `generated_shell_dynamic_path`. Scout combines supported `>>` and
`tee -a`/`--append` writes with the latest known complete version and maps each
fragment to its own source bytes. An unknown base or intervening mutation leaves
`generated_shell_append`. Diagnostics include the original line and column when
available. Generic recovery gaps include a specific reason. A wholly unknown
destination with no shell evidence remains outside this detection.

The informational SH005 finding links a recovered write, its body and a later
`source`, `.`, shell invocation or explicit executable path in the same modeled
command sequence, including direct local function calls. The trace follows
resolvable `cd` and simple `mv` renames between two local file paths. It uses the
latest recovered write and preserves the original write, append, rename and use
locations. For `if`/`elif`/`else`, a link survives when continuing branches agree
on the working directory and the file's version and source. Long chains of
appends and renames can exceed the trace limit while their contents are still
analyzed. Unresolved directory changes, overwrites and commands with unknown
effects invalidate earlier links. File paths are lexical and runtime file types,
permissions and command success are unverified. Use an explicit path with
`source` or `.` to avoid search-path ambiguity.

## JavaScript and TypeScript

The full CGO build uses official Tree-sitter grammars. JS001–JS006 check shell APIs,
dynamic evaluation, credentials in network arguments, dynamic SQL, sensitive files
and disabled TLS verification. Analysis considers selected ESM/CommonJS aliases,
destructuring, lexical shadowing, overwrites and branches.
Unsupported control flow leaves gaps. Core/no-CGO builds report unavailable grammars.

## SQL

The Go parser works in core builds. SQL001–SQL004 check selected destructive
operations, authority and row-level security (RLS) changes, server filesystem/program I/O and disabled limits.
Comments, strings and identifiers are distinguished. Dollar-quoted procedural bodies
remain unsupported. Go and JS/TS SQL interpolation is checked on their own ASTs.

## Markdown

Goldmark parses CommonMark block containers, including nested lists, blockquotes,
fenced code and indented code. Code views preserve LF/CRLF and physical byte
coordinates after container prefixes are removed. Unlabelled indented code uses
only existing narrow language hints; an unknown language remains a coverage gap.
Fences inside HTML blocks are inspected in a separate bounded raw-content pass;
HTML/runtime semantics remain unsupported. No rendering or reference fetching occurs.
Limits: 1 MiB per Markdown input, 2 MiB aggregate parsing bytes including HTML
projections, 64 container levels, 8192 block nodes, 512 regions, 8192 source segments
and 256 KiB per code view. Cancellation or a limit preserves available blocks and
raw checks and makes coverage incomplete.

## Configuration formats

JSON checks duplicate decoded keys. YAML and TOML require full-build backends.
YAML aliases, merges and custom tags are unsupported. TOML byte spans may cover
the entire parsed unit.
Parsing does not establish compatibility with every host loader.

## Scope

Cross-file flows use selected captured imports and functions: [flow checks](hardening-2026-10-29.md#data-flows).
Parser failures, unsupported forms and exhausted budgets remain visible gaps.
`complete` refers to selected checks; [policy scope](../user/inspection-profiles.md#scope)
controls declared language limitations.
