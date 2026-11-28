# Saved environment snapshots

English · [Русский](environment-snapshots.ru.md)

Scout saves the exact local content it inspects, then compares later versions with
that checkpoint. Skills, plugins, instructions, agent/MCP configuration, scripts,
dependencies and all other captured files are included. Captured code is not run.

## Start with discovery

Save one agent/project context. Flags before `--` select discovery; flags after it
configure scanning and reporting:

```sh
scout discover --agent codex --project /work/project \
  --snapshot /review/checkpoints/project.json -- --format markdown
```

Use `--agent claude-code` for Claude Code or `--no-project` for user/system context
without a project. Discovery must complete. Narrow the selection with `--kind`,
`--include-path`, or `--exclude-path`. The checkpoint must be a **new** private file
outside agent configuration locations and selected inputs. The inspection goes to
stdout, `--output`, or repeatable `--report FORMAT=PATH`.

After an update, run:

```sh
scout snapshot compare --snapshot /review/checkpoints/project.json --format markdown
```

Scout repeats the saved agent, home and configuration overrides, project, system
locations and filters. New snapshots record the resolved locations and where the
project ancestor search stops. If a link redirects a path or the project boundary
changes, live comparison stops. Use `--candidate`
to compare captured bytes or `--root` to choose the current inputs explicitly.
Older snapshots still open and use their saved discovery arguments. When
`--save-candidate` saves a live comparison against an older snapshot, the candidate
records the resolved locations and project boundaries. Repeat discovery finds new
components and reports missing components as removed. Incomplete discovery stops
comparison.

Use `inspect` to see the saved arguments, resolved locations and historical status:

```sh
scout snapshot inspect --snapshot /review/checkpoints/project.json
```

Checkpoints are trusted operator files. Repeated comparison reads saved paths or
reruns saved discovery. Inspect context before using a checkpoint supplied by someone
else. SHA-256 detects corruption; it does not authenticate an author.

## Explicit roots and scope changes

For individual packages, choose stable portable root IDs: `a-z`, `0-9`, `_`, `-`,
1–64 characters.

```sh
scout snapshot create --snapshot /review/checkpoints/manual.json \
  --root skills=/work/project/.agents/skills --root mcp=/work/project/.mcp.json
scout snapshot compare --snapshot /review/checkpoints/manual.json --format markdown
```

Without `--root`, comparison rechecks the saved absolute paths. Missing roots are
removals; unreadable paths and nested symlinks are not removals. Manual mode cannot
find sibling roots absent from the checkpoint; use discovery or supply a new set.

Explicit `--root` flags replace the saved selection entirely. Omitted IDs mean
removed roots; new IDs mean added roots. Keep IDs when moving content. `--empty`
without roots explicitly compares with an empty environment and skips discovery.
Selected declarations do not establish runtime activation.

## Change report

The report leads with aggregate decision, coverage and changes by root, with source
paths. Files include added/removed/modified status, byte sizes and an explanation
classifying agent instructions, dependencies, configuration or executable source.
Small text files include changed line-range sizes; these are not minimal diff counts.
Dependency details include package names and old/new declared versions.

Both versions and **both environments** are rescanned with the current scanner
configuration. Relationships use stable root IDs and source evidence to match
observations, retaining multiplicity. Statuses are `introduced`, `persistent`,
`not_observed`, or `unverified` when absence cannot be established under incomplete
coverage. Both reports and source coordinates remain available. Adding another
root cannot create a new relationship merely by changing a target index.
Capability combinations do not prove invocation or data flow; `not_observed` is
not proof of remediation.

Skill description overlaps are saved as `skill_description_overlap` observations.
Scout compares the top-level YAML `description` values from captured `SKILL.md`
files, including skills under the same root. It reports pairs with Jaccard
similarity above 0.5 after case folding, Unicode word splitting and removal of
common English stop words. Reports include the score and both source spans.
JSON and SARIF store the score as `similarity_basis_points` (10,000 means 100%).
This is a review signal for potentially competing skills.

An overlap is identified by both stable root IDs and relative manifest paths.
Edits that leave a pair above the threshold keep the overlap `persistent`.
This analysis uses the YAML check and considers descriptions up to 1,024 UTF-8
bytes. If an unavailable description could affect a pair, environment coverage
is partial and an absent overlap is `unverified`.

Unchanged complete/allowed roots do not repeat their full inspection in human output.
JSON retains all reports under `scout.environment-comparison/v1`: `roots`,
`relationships`, `previous_environment`, `environment`, `decision`, `exit_code`.
Nested reports use `scout.report/v1`. For CI, use `--format sarif` or add a second
destination with `--report sarif=changes.sarif`. SARIF results describe the
candidate, with file locations resolved against their original roots and finding
change status when known. Root properties retain historical results and per-root
coverage. The comparison properties include both joint inspections, relationship
changes, and the decision and exit code. Source excerpts from `--source-diff`
are available in text, Markdown and JSON.

## Source excerpts

Reports exclude source lines by default. Explicitly enable them when needed; they
can contain secrets:

```sh
scout snapshot compare --snapshot /review/checkpoints/project.json \
  --source-diff --format markdown
```

These are bounded removed/added line excerpts, not applyable patches. Lines are
escaped for terminals and Markdown. UTF-8 files without NUL up to 128 KiB qualify.
Total output is limited to 400 lines and 64 KiB; omissions/truncation are explicit
and do not imply omitted static analysis.

## Decisions, storage and limits

Creation saves source bytes and inspection, including review/block or incomplete
results. It does not approve findings or change an operator baseline. Historical
decisions never authorize the current version. Changed content requires at least
review. Findings in removed roots remain historical evidence, not candidate blockers.

Exit codes: 0 complete/allow; 1 complete/review-or-block; 2 incomplete, invalid input
or output failure. Evaluate `decision` and `exit_code` together. Preflight/capture
failures do not create a checkpoint; an incomplete inspection of captured bytes is
preserved with code 2. Capture diagnostics identify the affected path and any
limit, with its value and unit. JSON destinations receive
`scout.environment-snapshot-error/v1` with `operation`, `exit_code` and `problem`.
The problem contains `code` and `message`, plus `root`, `path`, `limit`, `actual`
and `unit` when available. Argument and preflight errors go to stderr.

Checkpoints contain **source bytes**, possibly secrets, paths and discovery context.
Protect them as source material. The content digest binds root IDs, relative paths,
directories, bytes and executable bits. The reader checks that the saved inspection's
file hashes and executable flags match the captured content. Context and reports
are not signed attestations. Restored files, packages, hooks and MCP servers are
never run. MCP analysis concerns captured declarations.

Capture limits: 1–32 nonoverlapping roots, 4096 entries including directory roots,
32 path components, 512 path bytes, 4 MiB/file, 16 MiB of source bytes and 48 MiB for
the checkpoint with inspection. Scanner budgets apply separately. `--max-changes`
bounds each root comparison and the separate relationship comparison; omissions
leave coverage incomplete.

Capture includes every entry under selected roots. Nested symlinks, special files,
read errors, unsafe/colliding portable paths, exhausted limits and detected concurrent
changes fail capture. Root aliases are resolved before overlap checks. Capture is
not atomic: freeze inputs externally if concurrent writers matter. Ownership,
timestamps, ACLs and non-executable permission bits are outside content identity.
This workflow does not start background monitoring.

## Save the checked candidate and compare two snapshots

Save the candidate alongside the change report:

```sh
scout snapshot compare --snapshot /review/checkpoints/project.json \
  --save-candidate /review/checkpoints/candidate.json --format markdown
```

`--save-candidate` writes a new private file with the same captured bytes and joint
candidate inspection from this comparison. After reviewing the report, use that
file as the next `--snapshot` without recapturing the reviewed content. The file
preserves the candidate scan's outcome, including review/block or incomplete
inspection. When comparison repeats discovery, the candidate retains that context.
Saving requires at least one current root. Candidate and report files are published
independently, with the candidate written first.

To compare two saved states, including when their original directories are gone:

```sh
scout snapshot compare --snapshot /review/checkpoints/project.json \
  --candidate /review/checkpoints/candidate.json --format markdown
```

Both versions come from the snapshot files and are rescanned with the current
configuration. Source paths are displayed as metadata. Roots are matched by ID.
For snapshots from different machines, use the same manual IDs if discovered
paths differ.

## Larger environments

Comparison shares Scanner aggregate capture counts between both versions. For
example, a 2500-file environment needs more than the default 4096 captured-file
slots for a complete pair comparison. Supply a trusted configuration outside
the inputs via `--config`, such as:

```json
{"schema":"scout.config/v1","limits":{"max_capture_files":8192,"max_capture_entries":16384}}
```

Byte, operation and other analysis budgets still apply. Explicit coverage gaps
return code 2; successful creation alone does not promise that a later comparison
with a smaller per-version budget can complete. Format, container and encoding
analysis boundaries may also produce incomplete coverage; the report retains
specific reasons. Every created checkpoint is validated with the checkpoint reader
before publication. A saved manual source or parent that becomes a symbolic link
is refused; explicitly select `--root` to change its target.
