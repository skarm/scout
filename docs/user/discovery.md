# Discover installed agent components

English · [Русский](discovery.ru.md)

`scout discover` inventories local Codex and Claude Code declarations before
scanning their files. It reads configuration and manifests without starting MCP
servers, running commands, expanding environment variables from files or making
network requests.

```sh
scout discover
scout discover --agent codex --format json --output /tmp/environment.json
scout discover --project /work/repository --scan -- --format markdown
scout discover --home /review/home --system=false --no-project --format json
```

Flags before `--` control discovery. With `--scan`, flags after `--` are ordinary
scan flags: profile, reports, policy, checks, service grants and scan budgets.
The inventory's `--format` and `--output` cannot be combined with `--scan`; put
scan report destinations after `--` instead. Scan inputs and stdin are not accepted
in that mode. Configuration for Scout remains explicitly operator-selected.

## Locations

By default discovery selects the current user's home, the current project and
known system locations. `--project` is repeatable and replaces the default project;
`--no-project` omits projects. Each selected project's parents are checked up to
the nearest `.git` entry, the selected home or filesystem root. Paths recorded in
agent configuration do not cause discovery to walk other projects.
Selected project aliases are canonicalized before matching inline MCP registrations;
both the selected spelling and its canonical path are recognized.

Codex locations:

- User MCP declarations in `~/.codex/config.toml`, skills under
  `~/.agents/skills` and `~/.codex/skills`, including the `.system` group.
- Project MCP declarations in `.codex/config.toml` and `.agents/skills`.
- Plugin packages under `~/.codex/plugins/cache`, with portable `plugin.json`
  or compatibility `.codex-plugin/plugin.json` / `.claude-plugin/plugin.json`.
- System `config.toml` and `skills` under `/etc/codex`, or the default
  `C:\ProgramData\OpenAI\Codex` location on Windows.

Claude Code locations:

- User MCP declarations in `~/.claude.json`, including inline registrations
  for selected projects. Skills and legacy Markdown commands under
  `~/.claude/skills` and `~/.claude/commands`.
- Project `.mcp.json`, `.claude/skills`, `.claude/commands`,
  `.claude/settings.json` and `.claude/settings.local.json`.
- Plugin packages under `~/.claude/plugins/{cache,repos,synced}`.
- `managed-mcp.json` and `managed-settings.json` under
  `/Library/Application Support/ClaudeCode` on macOS, `/etc/claude-code` on Linux,
  or `C:\Program Files\ClaudeCode` on Windows.

`CODEX_HOME` and `CLAUDE_CONFIG_DIR` from the scanning process can relocate their
configuration directories. Explicit `--home` disables these implicit overrides;
`--codex-home` and `--claude-home` select replacements explicitly. Claude's legacy
`~/.claude.json` and the relocated `.claude.json` are both inventoried when present.

Compatibility plugin manifests can add contained skill directories and inline or
file-based MCP maps. Paths must stay within the plugin. Portable Codex packages
use fixed `skills/` and `mcp.json`; compatibility declarations do not redirect them.
Marketplace catalogs are not searched as installed plugin packages.

Claude plugins can omit `.claude-plugin/plugin.json`. Their default `skills/` and
`.mcp.json` are still discovered; the usual cache layout is
`cache/<marketplace>/<plugin>/<version>`. A root `SKILL.md` is loaded as the plugin's
single skill when both `skills/` and the manifest's `skills` field are absent.
For packages without a manifest, the directory supplies the candidate plugin name
and a captured default component supplies its source reference.

## Inventory and scan results

JSON uses `scout.environment/v1`. Components record agent, kind, scope, path,
source configuration, JSON-pointer-style key where applicable, and local declared
state. `sources` contains SHA-256 hashes of the bytes read. `scan_targets` contains
deduplicated configuration files and skill/plugin roots. `enablement` preserves
plugin, skill and MCP settings separately from component declarations.
Claude's per-project `disabledMcpServers` and `enabledMcpServers` lists come from
`projects.<path>` in `.claude.json` for selected projects. Their source keys remain
distinct from the `enabledMcpjsonServers` / `disabledMcpjsonServers` approval settings.

Names and paths are untrusted metadata. Configuration values such as commands,
arguments, headers, credentials, URLs and skill bodies are not copied to the
inventory. Paths, selectors and hashes may themselves be sensitive.

`enabled`, `disabled` and `unknown` describe declarations only. Discovery does not
resolve configuration precedence, approvals, project trust or the effective set
of tools available to an agent. Cached plugin versions can be inactive or obsolete.

Inventory exit code 0 means discovery of the documented surface completed. Code 2
means invalid input, an unreadable/unsupported part, a limit, cancellation or an
output failure. A partial inventory retains components and explicit `issues`.
It is not a security verdict.

Inventory `--output` must be outside selected agent configuration directories,
skill roots and configuration files, including locations skipped because of limits,
read errors or cancellation. Project protection conservatively covers known
configuration locations in up to 64 ancestors of each selected path and its
canonical alias, even above a repository boundary. An existing report elsewhere
in the home or project can still be replaced with a partial inventory.

`--scan` requires complete discovery and 1..32 grouped roots. Larger environments
can be split by agent/project or inspected with explicit `scout scan` inputs.
This mode emits the existing `scout.report/v1` scan report, with ordinary policy
and exit codes. It scans disabled declarations as well as enabled ones. Roots may
contain supporting files beyond the inventoried components; normal capture and
analysis budgets apply. Sources are captured again by Scanner, so changes between
discovery and capture remain possible.
Known plugin caches containing files remain scan targets even if no supported
component metadata is recognized. Directory trees containing no files are omitted.

For an explicit joint review, pass `--environment` after `--`, select one
`--agent`, and choose at most one project context. See
[environment analysis](environment-analysis.md) for observations and limitations.

## Bounds and coverage

Defaults are 10 seconds, 10,000 probes/directory entries, depth 12 and 8 MiB total
configuration/manifest bytes. A single file is limited to 256 KiB. Limits, refused
symlinks, malformed configurations, unsupported plugin references and read errors
make discovery incomplete. Operator-selected root aliases are canonicalized;
descendant links are not followed. `.git`, `node_modules`, `.venv` and `__pycache__`
subdirectories are not recursively searched for components.
Cancellation during finalization also marks the inventory incomplete and returns
exit code 2; publishing a partial result cannot clear the discovery error.

The initial surface excludes cloud and MDM configuration, profile overlays,
runtime/CLI overrides, in-place plugins outside known caches, plugin seed/cache
environment overrides, enterprise Claude skills, linked skills, MCP bundles and
remote plugin references. An inventory marked complete does not establish coverage
of those locations or compatibility with every host version. No tool descriptions
are fetched from running servers. Snapshot comparison is not part of this command.

Locations and layouts were checked against the [Codex skills guide](https://developers.openai.com/codex/skills),
[OpenAI plugin packaging](https://developers.openai.com/plugins/build/plugins),
[Claude MCP scopes](https://code.claude.com/docs/en/mcp),
[Claude skills](https://code.claude.com/docs/en/skills) and
[Claude plugin manifests](https://code.claude.com/docs/en/plugins-reference),
on 2026-10-30. Discovery is an original Scout implementation; Snyk's client and
analysis service are not dependencies.
