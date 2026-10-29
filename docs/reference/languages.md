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

The full build uses Tree-sitter and a bounded CST-to-IR projection, without Python
runtime. Checks cover selected process/eval/import operations, sensitive files,
network arguments, deserialization, reconstruction and local flows.
Unsupported constructs and unresolved flows remain gaps.

## Shell

Bounded command trees cover pipelines, assignments, redirects and substitutions.
`mvdan.cc/sh/v3/syntax` separately supplies command/source declarations.
SH001–SH004 check download-to-execution, credentials in requests, eval/source/shell
capabilities and sensitive reads. Selected curl/wget options and saved-file provenance
are tracked. Dynamic arguments and unsupported control flow limit completeness.

## JavaScript and TypeScript

The full CGO build uses official Tree-sitter grammars. JS001–JS006 check shell APIs,
dynamic evaluation, credentials in network arguments, dynamic SQL, sensitive files
and disabled TLS verification. Analysis considers selected ESM/CommonJS aliases,
destructuring, lexical shadowing, overwrites and branches.
Unsupported control flow leaves gaps. Core/no-CGO builds report unavailable grammars.

## SQL

The Go parser works in core builds. SQL001–SQL004 check selected destructive
operations, authority/RLS changes, server filesystem/program I/O and disabled limits.
Comments, strings and identifiers are distinguished. Dollar-quoted procedural bodies
remain unsupported. Go and JS/TS SQL interpolation is checked on their own ASTs.

## Configuration formats

JSON checks duplicate decoded keys. YAML and TOML require full-build backends.
YAML aliases, merges and custom tags are unsupported; TOML spans are conservative.
Parsing does not establish compatibility with every host loader.

## Scope

Cross-file flows use selected captured imports and functions: [flow checks](hardening-2026-10-29.md#data-flows).
Parser failures, unsupported forms and exhausted budgets remain visible gaps.
`complete` refers to selected checks; [policy scope](../user/inspection-profiles.md#scope)
controls declared language limitations.
