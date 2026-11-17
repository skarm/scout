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
Explicit interpreter text is reported separately from `source`. This includes
POSIX shell `-c` and supported PowerShell `-Command` invocations. Scout also
maps declared commands in `.claude/settings.json` to their original JSON bytes.
For simple hook launches, Scout follows local `source` and `.` references within
the captured package. Relative paths require a known working directory, such as
after `cd "$PLUGIN_ROOT" &&`. Findings in sourced files retain their own source
coordinates and a separate path with the hook event and include locations.
Simple assignments and known working directories carry across a sourced file.
After `if`/`elif`/`else`, the analyzer keeps values shared by all continuing
branches. Findings inside a resolved local function also cite the call site.
Dynamic paths, unknown directories, ambiguous functions, missing files, and
cycles produce coverage diagnostics at the corresponding command.

For captured Gemini CLI extensions, Scout reads `hooks/hooks.json` beside
`gemini-extension.json` and follows simple launches that use
`${extensionPath}`. Gemini substitutes the path before shell parsing.
Without an explicit shell-safe root assumption, the trace identifies a
candidate handler and retains a coverage gap for the actual installation path.
[Gemini CLI extension reference](https://geminicli.com/docs/extensions/reference/).

The component graph records captured handlers traced through a guarded change to
the plugin root. Quoted plugin-root paths, including the `:-.` fallback form,
resolve against the modeled host root. For an unquoted launch with a literal
suffix, Scout traces the candidate handler and reports `hook_source_unquoted_root`
at the expansion. An interpreter invocation with this file operand already
has a known shape. A dynamic operand of `-c` still leaves a command-text gap.
Inside a captured script, an empty `IFS` and `set -f` or `set -o noglob`
prove a single path when both settings hold on every path to the launch.
The host can substitute placeholders in hook configuration before the shell
reads its options, so the proof applies inside scripts. An explicit Bash hook
can also project an executable text
handler without a shebang into shell syntax. For wrappers that also contain
Windows batch code, that code retains its own coverage status. Selected `set`
options, single-operand `command -v` lookups, read-only Bash tests and a bounded
`eval` of constant `printf` text preserve bindings for subsequent source tracing.
Pipeline stages and background lists retain their own shell scope. Scout
also considers Bash `lastpipe` when a pipeline can change the caller.
Literal inline output hooks have a source-mapped handler in their own
configuration file. An explicit system-only `PATH` and bare `export` preserve
bindings visible to the shell tracer.
Unmodified command groups retain their exit and return effects. Scout
recognizes fixed-arity bracket tests, including negated file checks. An
`ERR` or `EXIT` trap with a literal exit status can terminate an additional
path and preserves bindings on continuing paths. Redefining a command that
the trap uses leaves a coverage gap.
For `case` with a statically known selector, the hook tracer follows the first
matching `;;` arm for literals, literal prefixes followed by `*`, `*` alone,
and slash or backslash presence tests. With an unknown selector and literal glob patterns, Scout checks each
possible arm. Dynamic patterns and fallthrough operators leave a coverage gap. For a
directly launched text wrapper handled by the hook's explicit Bash, the tracer
can derive the script directory from `$0` and follow `exec "$BASH"` through a
resolved local script path, including when the interpreter is stored in a variable.
Recognized `dirname` and `cd … && pwd` substitutions can resolve captured paths
from `$0` or a known Bash source frame. Supported shell launches remain traceable
with output discarded. Command and process substitutions in projected control
operands are analyzed in isolated shell scopes.
For a modeled `while` condition and body, Scout discards values the loop can
assign and preserves independent bindings. A command with unresolved effects
or a change to command lookup in the loop leaves a coverage gap.
For `while IFS=… read -r name …` with supported input redirects, the tracer
accepts multiple read variables, literal `IFS` separators, scalar assignments,
simple local declarations and read-only tests. The tracer discards bindings
that a loop may write and checks substitutions for local source edges in an
isolated scope.
An anchored decimal check or a `grep -c` count with a verified option boundary
also establishes a numeric binding. Regex ranges such as `[0-9]` require a
known `C` or `POSIX` locale. A simple scalar assignment from `$((…))` preserves
numeric provenance when its operands are verified. Supported numeric inputs
include scalar and array lengths, `printf '%s\n' … | wc -l` counts, and Bash
expressions such as `$((10#$(date +%H)))`. A shell array subscript made from a
variable or a nested array read requires proof that the values used in the
index are numeric.
For a loop over projected shell words
with assignments, static `case` patterns and read-only tests, the tracer
forgets bindings written by the loop, including array appends. A subsequent
`set --` with an array spread invalidates positional argument bindings.
For an exact list of known positional arguments, the tracer can follow the
selected arms of an option loop that only performs simple assignments.
The hook tracer tracks simple scalar and indexed-array `local` declarations in functions and
restores shadowed bindings on return when their values are known across paths.
Declaration options, explicit subscript assignments, and local appends leave a coverage gap.
For a plain empty array assignment, the tracer forgets the target's scalar
value and preserves independent bindings.
For quoted `${name//pattern/replacement}`, the hook tracer supports simple
literal operands, including the backslash, quote, newline, carriage return, and
tab patterns used in Bash JSON escaping. With an unknown input, the result stays
unknown and independent bindings carry forward. Globs, dynamic operands, and
match references in the replacement leave a coverage gap.
The plain builtin `trap '' PIPE` (or `trap '' SIGPIPE`) preserves bindings
for source tracing. Trap handlers and dynamic operands leave a coverage gap.
For a loop over `"$PLUGIN_ROOT"/literal/directory/*` that checks each item
with `[ -f "$item" ]` before `bash "$item"` and ignores failures, the tracer
follows the directly contained files in the captured package. It keeps both
outcomes of read-only string comparisons and literal `ls | grep` predicates
for source tracing.
Scalar `unset`, `set +e`, and a literal `git -C "$dir" rev-parse --git-dir`
probe preserve independent shell bindings. A scalar assigned from `$?` can
be used in a bounded arithmetic predicate. Arithmetic operands that could
contain shell expressions still leave a coverage gap.

Bounded command trees cover pipelines, assignments, redirects, substitutions
and `case` arms terminated by `;;` or a final `esac`. The execution parser
leaves fallthrough arms and command substitutions in selectors or patterns
unverified.
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

SH005 also records supported output redirects to `CLAUDE_ENV_FILE` on traced
Claude Code hooks that receive the variable. The trace ends at the redirect
whose output Bash can read as code on a later invocation.
[Claude Code hooks reference](https://code.claude.com/docs/en/hooks#persist-environment-variables)

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

JSON checks duplicate decoded keys. YAML and TOML require full-build backends.
YAML aliases, merges and custom tags are unsupported. TOML byte spans may cover
the entire parsed unit.
Parsing does not establish compatibility with every host loader.

## Scope

Cross-file flows use selected captured imports and functions: [flow checks](hardening-2026-10-29.md#data-flows).
Parser failures, unsupported forms and exhausted budgets remain visible gaps.
`complete` refers to selected checks; [policy scope](../user/inspection-profiles.md#scope)
controls declared language limitations.
