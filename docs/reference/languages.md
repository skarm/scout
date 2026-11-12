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

Bounded command trees cover pipelines, assignments, redirects and substitutions.
`mvdan.cc/sh/v3/syntax` separately supplies command/source declarations.
SH001–SH004 check download-to-execution, credentials in requests, eval/source/shell
capabilities and sensitive reads. Selected curl/wget options and saved-file provenance
are tracked. Dynamic arguments and unsupported control flow limit completeness.

Scout reconstructs `cat` and `tee` heredoc writes to relative `.sh` paths,
including supported blocks, functions, pipelines with explicit stdin, and
shell files captured from archives. It resolves simple parameters from
preceding, unambiguous assignments and analyzes up to four nested generations
under shared limits. Findings retain byte and line coordinates in the
enclosing captured file or archive member. Substituted text cites the parameter
reference that produced it. Observed effects from functions, traps, PATH and
command hash entries can make a writer's identity or its input uncertain.
Unresolved expansions, uncertain writers and exhausted generation limits leave
coverage gaps.

Recognizable `.sh` writes with unresolved destinations, such as `"${name}.sh"`,
report `generated_shell_dynamic_path`. Writes that append to a shell script via
`>>` or `tee -a`/`--append` report `generated_shell_append`. Both diagnostics
refer to the enclosing captured file. A wholly unknown destination with no
evidence of a `.sh` target remains outside this detection.

The informational SH005 finding links a recovered write, its body and a later
`source`, `.`, shell invocation or explicit executable path in the same modeled
command sequence. The trace follows literal `cd` and uses the latest recovered
write to a path. Unresolved changes to the working directory, intervening
overwrites and commands with unknown effects invalidate earlier links. Use an
explicit path with `source` or `.` to avoid search-path ambiguity.

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
