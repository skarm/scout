# Discover installed agent components

English · [Русский](discovery.ru.md)

`scout discover` inventories local Codex, Claude Code, Cursor, GitHub Copilot CLI, OpenCode, Gemini CLI, OpenClaw, Grok CLI, DeepSeek Harness, ZCode, Qwen Code, and Kimi Code declarations before
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
Inline MCP registrations in `~/.claude.json` are matched by path spelling against
the selected project and its symlink-resolved path. Use the spelling in
`projects` for paths that differ only by case or Unicode normalization on disk.

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

Cursor discovery reads MCP and flat lifecycle hooks under `~/.cursor` and
project `.cursor`, and inventories rules, agents, commands and skills. Installed
packages under `~/.cursor/plugins/local` and `plugins/cache` can declare components
through `.cursor-plugin/plugin.json`. Scout also reads the system hooks file in
the known platform directory. [Cursor plugin reference](https://cursor.com/docs/reference/plugins) · [Cursor hooks](https://cursor.com/docs/hooks)

GitHub Copilot CLI discovery reads `~/.copilot/mcp-config.json`, user skills and
agents, and packages under `~/.copilot/installed-plugins`. Project MCP maps in
`.mcp.json` and `.github/mcp.json` can be wrapped or bare. Scout reads
project and user hook files and inline hooks in known Copilot settings, including
shell fields and direct `exec` declarations,
and inventories `.github/agents` and `.github/skills`. It recognizes the legacy
plugin manifest locations and the Agent Plugins 1.0 `com.github.copilot`
component directory. [Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)

OpenCode discovery reads `opencode.json` and `opencode.jsonc` in project roots,
project `.opencode`, `~/.config/opencode` and known system directories. Scout
reads MCP argv, explicit disabled settings in both MCP layouts, configured
plugin references and captured local JavaScript/TypeScript plugins and tools.
The inventory also includes agents, commands and skills. Scout does not fetch
plugin dependencies or read managed macOS preferences.
[OpenCode configuration](https://opencode.ai/docs/config/) · [OpenCode MCP](https://opencode.ai/docs/mcp-servers/)

Gemini CLI discovery reads user and workspace `.gemini/settings.json` and
`settings.json` and `system-defaults.json` in the platform system directory.
Settings support comments and use strict JSON comma rules. Scout inventories
MCP servers, grouped lifecycle hooks, local skills, agents, TOML commands and
policies, and default `GEMINI.md` context files in known locations. The
`.agents/skills` alias is included. The inventory records selected settings
such as `mcp.allowed`, `mcp.excluded` and `skills.disabled` without resolving
their precedence. `--gemini-home` selects the parent that contains `.gemini` and
`.agents`, following the same convention as `GEMINI_CLI_HOME`.
[Gemini CLI configuration](https://geminicli.com/docs/reference/configuration/)

Scout reads installed packages under `.gemini/extensions/` using
`gemini-extension.json`, `hooks/hooks.json` and the package's local component
directories. Extension context paths must stay inside the package. Static MCP
analysis recognizes stdio, SSE `url` and Streamable HTTP `httpUrl`. The loader's
custom system file overrides, external links and effective extension enablement
are outside this coverage. [Gemini CLI extension reference](https://geminicli.com/docs/extensions/reference/)

OpenClaw discovery reads JSON5 `openclaw.json` and inventories the state
directory's `skills`, `hooks` and `extensions`. The default state is
`~/.openclaw`. Select another state with `--openclaw-home` or
`OPENCLAW_STATE_DIR` when `--home` is omitted. Scout also inspects the usual
state-relative `workspace` and explicit `--project` roots for `skills/`,
`.agents/skills/`, `hooks/` and `.openclaw/extensions/`. In the default state
Scout includes personal `~/.agents/skills/`.
[OpenClaw configuration](https://docs.openclaw.ai/gateway/configuration/) · [OpenClaw skill locations](https://docs.openclaw.ai/agent)

Scout reads `mcp.servers`, local enablement declarations, native
`openclaw.plugin.json` manifests, OpenClaw metadata in `package.json` and
`HOOK.md` hook directories. Extension skill roots and declared package
entrypoints are checked against the package boundary. Hook labels identify
their directories, and scan links captured handlers by filename precedence.
[OpenClaw plugin manifest](https://docs.openclaw.ai/plugins/manifest) · [OpenClaw hook discovery](https://docs.openclaw.ai/automation/hooks/configuration)

Use `--project` for a workspace stored elsewhere. Scout reports `$include`
directives as unresolved and leaves discovery incomplete. Paths in load
configuration, alternative config filenames, profile selection, linked
packages, and compatible bundle loading across hosts are outside this
OpenClaw discovery coverage. Session and credential stores are outside the
known discovery locations.

Grok CLI discovery reads `config.toml` in `~/.grok` and project `.grok`. It
also reads user and system `managed_config.toml` and `requirements.toml` at
known locations, including `/etc/grok` on Unix. `--grok-home` or `GROK_HOME`
selects the configuration directory directly. The inventory includes MCP
servers and local plugin enablement declarations. Project hooks come from
`.grok/hooks/*.json`. Inline TOML hooks are inventoried at user and system
scope. A scan of a standalone TOML file may retain inline hooks as
declarations with unknown activation. TOML evidence covers the whole file.
[Grok settings](https://docs.x.ai/build/settings) · [Grok hooks](https://docs.x.ai/build/features/hooks)

Scout inventories `lsp.json`, agents, skills, commands and Rhai workflow
files in known Grok locations, including the user aliases `~/.agents/skills`
and `~/.agents/commands`. Under `.grok/plugins`, Scout recognizes
`.grok-plugin/plugin.json`, compatible manifests and local packages with a
conventional layout. Package contents may include `.mcp.json`, `.lsp.json`
and `hooks/hooks.json`. Scout inspects captured declarations and records
package-local references without running hooks or workflows, resolving
runtime trust or loading marketplace sources.
[Grok plugins](https://docs.x.ai/build/features/skills-plugins-marketplaces) · [Grok workflows](https://docs.x.ai/build/modes-and-commands)

DeepSeek Harness discovery reads `~/.dsh/settings.yaml`, the home-level
`cordis.patch.yml`, and `profiles/<name>/{package.json,cordis.patch.yml}`. Use
`--deepseek-home` to select the directory directly. Scout also reads root
`cordis.yml` and `cordis.patch.yml` in selected projects as authoring files.
Project bundle manifests in `package.json` may declare one or more contained
YAML layers in `dsh.bundle.patch`. Profile manifests record bundle names in
`dsh.profile.bundles`. [DeepSeek Harness profiles and bundles](https://github.com/deepseek-ai/deepseek-harness/blob/master/apps/cli/reference/README.md)

Scout reads MCP client rows, manager server rows and the manager's
`config.servers` map, including entries under `insert` and Cordis groups.
`!!js` expressions remain opaque and credential references remain unresolved.
Local disablement is recorded independently of effective configuration. The
parser rejects duplicate keys, aliases and additional YAML documents. Includes
are reported as unresolved, and profile layering and npm resolution are
outside the static interpretation. [DeepSeek Harness MCP](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/mcp.md)

Known skill roots under `.dsh/skills` and `.agents/skills` support both
`<name>/SKILL.md` and flat `<name>.md` files. Scout includes the user-global
`AGENTS.md` files and the project instruction candidates based on `AGENTS.md`
and `CLAUDE.md`. Discovery skips credential stores and runtime state.
[DeepSeek Harness skills](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/skills.md) · [Instruction files](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/context/agent-instructions/README.md)

ZCode discovery reads `~/.zcode/cli/config.json`, `zcode.json` and
`.zcode/config.json` in selected projects. `--zcode-home` selects the
`.zcode` directory directly. Scout inventories `mcp.servers`, grouped
`hooks.events`, and local plugin settings. Within a scope, a native MCP
map with a recognized server takes precedence over the compatible `.agents/mcp.json`
inventory. Scout keeps user and project declarations as separate
observations. [ZCode MCP configuration](https://zcode.z.ai/en/docs/mcp-services) · [ZCode hooks](https://zcode.z.ai/en/docs/hooks)

Known user and project locations supply skills, Markdown commands,
subagents and `AGENTS.md`. Scout reads native `.zcode-plugin/plugin.json`
and the compatible `.claude-plugin/plugin.json` fallback, plus the
installation index and package versions under `cli/plugins/cache`.
Local plugin directories must stay within the selected root. Marketplace
checkouts and plugin data directories are outside discovery. Plugin
`hooks/hooks.json`, declared hook files, and MCP declarations support
static inspection. Captured package references may use
`${ZCODE_PLUGIN_ROOT}`. Trust records, runtime enablement, credentials
and template values stay unresolved.
[ZCode plugin formats](https://zcode.z.ai/en/docs/plugin) · [ZCode CLI plugin storage](https://github.com/zai-org/ZCode/blob/main/apps/zcode-cli/docs/usage/10-plugins.md)

`CODEX_HOME` and `CLAUDE_CONFIG_DIR` from the scanning process can relocate their
configuration directories. Explicit `--home` disables these implicit overrides;
`--codex-home` and `--claude-home` select replacements explicitly. The other
clients use `CURSOR_CONFIG_DIR`, `COPILOT_HOME` and `OPENCODE_CONFIG_DIR` with
the corresponding `--cursor-home`, `--copilot-home` and `--opencode-home` flags. Claude's legacy
`~/.claude.json` and the relocated `.claude.json` are both inventoried when present.

Compatibility plugin manifests can add contained skill directories and inline or
file-based MCP maps. Paths must stay within the plugin. Scout reads Agent Plugins
1.0 and 1.1 packages in the Codex cache from root `plugin.json`, immediate
`skills/<name>/SKILL.md` declarations, and root `mcp.json`. Version 1.1 also
uses root `hooks.json`. Each component configuration must declare the manifest's
schema version. Package scans use the inline `extensions.com.openai` object for
Codex settings when present and consult `.codex-plugin/plugin.json` as a fallback.
Marketplace catalogs are not searched as installed plugin packages.

Claude plugins can omit `.claude-plugin/plugin.json`. Their default `skills/` and
`.mcp.json` are still discovered; the usual cache layout is
`cache/<marketplace>/<plugin>/<version>`. A root `SKILL.md` is loaded as the plugin's
single skill when both `skills/` and the manifest's `skills` field are absent.
For packages without a manifest, the directory supplies the candidate plugin name
and a captured default component supplies its source reference.

## Inventory and scan results

Direct directory scans recognize known native paths. When scanning a
standalone `hooks.json`, `mcp.json` or `.mcp.json`, use `--harness cursor` or
`--harness copilot-cli` to select the intended format. Discovery-driven scans and snapshots
carry the single selected native agent into scanning by default. To scan a
standalone Gemini CLI `settings.json` or `system-defaults.json` directly, pass
`--harness gemini-cli`.

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

`--scan` requires complete discovery and 1..32 selected roots. Filter large inventories
before scanning, or split them by agent/project:

```sh
scout discover --agent codex --kind skill \
  --include-path /home/operator/.agents/skills \
  --exclude-path /home/operator/.agents/skills/archived \
  --scan -- --format markdown
```

`--kind` accepts `skill`, `plugin`, `mcp-server`, `command`, `hook`, `agent`, `rule`, `tool`, `lsp-server` and `workflow`; it and the path
filters are repeatable, with at most 32 values each. Includes intersect known roots
and cannot add outside inputs. Excludes omit whole overlapping roots; use a kind
filter to select individual components instead of a broad skills/cache directory.
The `hook` kind selects packages containing portable hooks so the scan can resolve their handlers.
Existing path aliases follow the filesystem's case and Unicode comparison rules.
Missing suffixes retain resolved symlink ancestors; other path-resolution errors
reject the selection, including dangling or cyclic links.
Inventory components, source hashes and issues remain unfiltered. Optional
`selection` metadata describes the requested scope; incomplete discovery still
refuses automatic scanning. Report publication protects all known configuration
locations, including ones excluded from the scan.

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

Discovery excludes cloud and MDM configuration, profile overlays,
runtime/CLI overrides, in-place plugins outside known caches, plugin seed/cache
environment overrides, enterprise Claude skills, linked skills, MCP bundles and
remote plugin references. An inventory marked complete does not establish coverage
of those locations or compatibility with every host version. No tool descriptions
are fetched from running servers. Snapshot comparison is not part of this command.

[Codex skills](https://developers.openai.com/codex/skills) · [Codex plugin packaging](https://developers.openai.com/plugins/build/plugins) · [Claude MCP scopes](https://code.claude.com/docs/en/mcp) · [Claude skills](https://code.claude.com/docs/en/skills) · [Claude plugin manifests](https://code.claude.com/docs/en/plugins-reference)

### Qwen Code

Use `discover --agent qwen-code` for the user and project `.qwen/settings.json`,
project `.mcp.json` and `.lsp.json`, and the standard system settings when system
discovery is enabled. `--qwen-home` or `QWEN_HOME` selects the user configuration
directory. Scout inventories MCP servers and grouped hooks, Markdown and TOML
commands, subagents, rules, direct-child skills in `.qwen/skills` and
`.agents/skills`, JavaScript workflows, and the default instruction files.
[Qwen Code settings](https://qwenlm.github.io/qwen-code-docs/en/users/configuration/settings/) · [Qwen Code hooks](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/) · [Qwen Code skills](https://qwenlm.github.io/qwen-code-docs/en/users/features/skills/)

Scout reads native `qwen-extension.json` and portable Agent Plugins v1 packages
in the user extension directory. Native packages can declare inline MCP
servers, inline or file-based hooks and LSP servers, context, commands,
subagents, skills, workflows, and channel entry points. Use
`scout scan --harness qwen-code PATH` for a standalone settings file or a
portable package outside the Qwen Code directory layout. The scan records
captured declarations. Effective approvals, extension installation state,
process environment, and external paths require runtime context.
[Qwen Code extension format](https://qwenlm.github.io/qwen-code-docs/en/users/extension/introduction/) · [Qwen Code Agent Plugins v1](https://qwenlm.github.io/qwen-code-docs/en/users/extension/agent-plugins/)

### Kimi Code

Use `discover --agent kimi-code` to inventory user hooks in
`~/.kimi-code/config.toml`, user and project `.kimi-code/mcp.json`, instructions,
skills and custom agents under the Kimi and shared `.agents` directories.
`--kimi-home` or `KIMI_CODE_HOME` selects the user data directory. The default
search also recognizes `~/.kimi` hooks, MCP settings and skills from the
earlier CLI. Use `scout scan --harness kimi-code PATH` for a standalone
configuration file.
[Kimi data locations](https://github.com/MoonshotAI/kimi-code/blob/main/docs/en/configuration/data-locations.md) · [Hooks](https://github.com/MoonshotAI/kimi-code/blob/main/docs/en/customization/hooks.md) · [MCP](https://github.com/MoonshotAI/kimi-code/blob/main/docs/en/customization/mcp.md)

Scout reads installed plugin state from `plugins/installed.json` and
materializes registered packages under the selected home's `plugins/managed`
directory. It recognizes `kimi.plugin.json` and `.kimi-plugin/plugin.json`,
including declared MCP servers, hooks, commands, agents, skills and prompt
contributions. The scan records declarations and links to contained captured
handlers. Loading user settings, remote environments, custom search directories,
and extension activation require runtime context.
[Kimi plugin manifest](https://github.com/MoonshotAI/kimi-code/blob/main/docs/en/customization/plugins.md)
