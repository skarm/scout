# CLI reference

English · [Русский](cli.ru.md)

This page lists the current public `scout` commands and every named flag.
For examples, see [CLI usage](../user/usage.md). Developer-only `scout-dev`
commands have a [separate guide](../development/commands.md).

Contents

- [Syntax and help](#syntax-and-help)
- [Commands](#commands)
- [Scan flags](#scan-flags)
- [Compare](#compare)
- [Environment discovery](#environment-discovery)
- [Configuration validation](#configuration-validation)
- [MCP server](#mcp-server)
- [Doctor](#doctor)
- [Baseline](#baseline)
- [Policy shadow](#policy-shadow)
- [Rules, profiles and capabilities](#rules-profiles-and-capabilities)
- [Knowledge and integrations](#knowledge-and-integrations)
- [Registry](#registry)
- [Attestation verification](#attestation-verification)
- [Exit codes](#exit-codes)

## Syntax and help

```sh
scout -h
scout scan -h
scout scan -f json ./my-plugin
scout scan --format json -- "$target"
scout scan --stdin SKILL.md -f json < ./SKILL.md
```

Use `--help` (`-h`) at the root or run `scout help` for the complete reference.
`scout scan -h` prints scan flags and defaults. Commands with a flag parser
accept either spelling before their inputs.

Put flags before positional inputs. `--` ends flag parsing; it is optional for
ordinary paths such as `./my-plugin`. Keep it before a path supplied by a variable
or a name beginning with `-`. Every token after `--` is an input, including tokens
that look like flags.

Boolean flags enable an option when written without a value. Use `--flag=false`
to disable it; do not write `--flag false`. Byte limits take integer byte counts,
without `MiB` suffixes. Durations take units, for example `500ms`, `30s`, `2m` or
`168h`. Defaults below apply without configuration; explicit flags override fields
from `--config`. Permissions always come from the current invocation.

## Commands

```text
scout scan [flags] <target> [target...]
scout scan [flags] --stdin NAME
scout compare [flags] <before> <after>
scout discover [flags] [--scan -- <scan flags>]
scout config validate [flags]
scout mcp [flags]
scout mcp snapshot --source-id ID [--output FILE] <capture.json>
scout doctor [flags]
scout baseline create|approve|renew [flags]
scout policy shadow --report FILE --current FILE --trial FILE [flags]
scout rules list [--all]
scout rules pack create|inspect [flags]
scout profiles
scout capabilities
scout knowledge [--mode MODE]
scout integrations list
scout integrations export --bundle NAME --output FILE
scout registry fetch [flags]
scout registry compare [--output FILE] <previous> <current>
scout attestation verify --public-key KEY --envelope FILE --artifact FILE --subject NAME
scout version
```

Current aliases are `batch` for `scan`, `selftest` for `doctor`, `rules` for
`rules list`, `integrations` for `integrations list`, and root `--version` for
`version`. A scan accepts 1 through 32 local paths or explicit HTTP(S) URLs.
Stdin accepts one named input and cannot be mixed with positional targets.

## Environment discovery

`scout discover` inventories Codex, Claude Code, Cursor, GitHub Copilot CLI, OpenCode, Gemini CLI, OpenClaw and Grok CLI. `--scan` passes discovered
roots to the existing Scanner. See [locations, format and limits](../user/discovery.md).

- `--agent all|codex|claude-code|cursor|copilot-cli|opencode|gemini-cli|openclaw|grok-cli` (`-a`): agent; default `all`.
- `--home DIR`: selected user home; default current user's home.
- `--codex-home DIR`, `--claude-home DIR`, `--cursor-home DIR`, `--copilot-home DIR`, `--opencode-home DIR`: explicit agent configuration directories.
  Without `--home`, process `CODEX_HOME` and `CLAUDE_CONFIG_DIR` are honored.
- `--gemini-home DIR`: directory containing `.gemini` and `.agents`. Without `--home`, Scout honors `GEMINI_CLI_HOME`.
- `--openclaw-home DIR`: OpenClaw state directory. Without `--home`, Scout honors `OPENCLAW_STATE_DIR`.
- `--grok-home DIR` selects the Grok configuration directory directly. Without `--home`, Scout honors `GROK_HOME`.
- `--project DIR`: repeatable selected project; default current directory.
- `--no-project`: omit projects; default `false`.
- `--system[=BOOL]`: known system locations; default `true`.
- `--max-entries N`: aggregate probes/directory entries; default 10000, 1..100000.
- `--max-depth N`: skill/plugin traversal depth; default 12, 1..32.
- `--max-bytes N`: aggregate config/manifest bytes; default 8388608, 1..67108864.
  A single file is limited to 256 KiB.
- `--timeout DURATION` (`-t`): discovery deadline; default `10s`, greater than 0 and at most `2m`.
- `--format text|json` (`-f`): inventory format; default `text`.
- `--output FILE` (`-o`): inventory outside scan inputs; default stdout.
- `--scan`: scan discovered roots; default `false`. Ordinary scan flags follow `--`.
  Inventory `--format`/`--output` flags are rejected in this mode.
- `--snapshot FILE` (`-s`) saves the discovered environment. Select one agent
  and pass scan flags after `--`.
- `--kind skill|plugin|mcp-server|command|hook|agent|rule|tool|lsp-server|workflow` (`-k`): repeatable component-type selection;
  unset selects the original grouped scan roots.
- `--include-path PATH`: repeatable intersection with discovered scan roots;
  cannot add paths outside the inventory.
- `--exclude-path PATH`: repeatable exclusion of entire overlapping scan roots.
  Use `--kind` to select individual components before excluding paths.

Inventory uses `scout.environment/v1`; exit 0 means complete within the documented
surface, and 2 means error or incomplete discovery. It is not a policy decision.
`--scan` requires complete discovery and 1..32 roots; it returns the ordinary scan
report and exit code. Declaration states do not establish component activation.

## Scan flags

### Input and configuration

- `--environment` (`--env`): explicitly relate selected local roots as one agent/project
  environment; default `false`. Independent scans remain independent by default.
  Requires existing, nonoverlapping local roots and does not support external traversal.
  See [environment analysis](../user/environment-analysis.md).

- `--config FILE` (`-c`): explicit operator JSON configuration; unset by default. May be
  supplied only once. Configuration is never discovered inside targets.
- `--profile standard|review|custom` (`-p`): inspection preset; default `standard`.
  `standard` selects all static checks; `review` also requires a configured reviewer;
  `custom` permits explicit check selection. CLI aliases: `extended` = `standard`,
  `semantic` = `review`, `basic` = `custom` with all optional static checks disabled.
- `--harness auto|claude-code|codex|cursor|copilot-cli|opencode|gemini-cli|openclaw|grok-cli|agent-skills`: interpretation of agent/plugin
  declarations; default `auto`.
- `--stdin NAME` (`-i`): read one input from stdin. Use a relative filename such as
  `SKILL.md` for format detection and source coordinates. Omit positional inputs.
- `--exclude GLOB`: repeatable file exclusion for a direct scan of one local skill
  directory. Example: `scout scan --exclude 'tests/*' --exclude 'fixtures/*.json' ./my-skill`.
  Patterns match the entire relative POSIX path case-sensitively, and `*` can
  span directory levels. Quote patterns so the shell passes them to Scout.
  Pass up to 32 patterns, each up to 256 UTF-8 bytes.

The directory must contain exactly one manifest at its root. Patterns that
match `SKILL.md` or `skill.md` are rejected, and an actual manifest with a
different spelling of those letters is protected as well. JSON records all
requested patterns in `artifact.exclude_globs`, including patterns with no
matches. Each excluded file is listed as `skipped` with reason
`operator_excluded` and remains in the coverage inventory. Any matched file
makes coverage partial and returns exit 2.

Keep config, baseline, extra rules and caches outside all inspected inputs.
See [configuration](../user/usage.md#configuration) and
[profiles](../user/inspection-profiles.md).
Copy a [ready-to-use config](../../examples/configs/README.md) for a common workflow.

### Reports

- `--format text|json|sarif|markdown` (`-f`): primary report format; default `text`.
  `terminal` is an alias for `text`.
- `--output FILE` (`-o`): primary report destination; default stdout. An existing regular
  file is replaced atomically; directories and symlinks are rejected.
- `--report FORMAT=PATH` (`-r`): additional report destination; repeatable, none by default.
  Uses the same formats as `--format`. Destinations must be distinct and outside
  inputs and trusted operator files. The primary report is still produced.

Diagnostics go to stderr. Create destination directories before running Scout.
File reports require resolvable input boundaries; a dangling input symlink is
rejected. Use stdout to inspect diagnostics for such an input.
See [report publication](../user/usage.md#save-reports).

### Policy

- `--fail-on info|low|medium|high|critical` (`--fo`): minimum unsuppressed finding severity
  that blocks admission; default `high`. Other policy reasons can still require
  review, and incomplete execution still exits with code 2.
- `--scope conservative|selected`: language coverage policy; default `conservative`.
  `selected` accepts declared language-analysis limitations, but does not waive
  parsing failures, unfinished checks or exhausted budgets.
- `--baseline FILE` (`-b`): trusted operator baseline JSON; unset by default.
- `--allow-baseline-globs`: permit glob approvals in that baseline; default `false`.

See [baseline](../user/usage.md#baseline) and
[coverage policy](../user/inspection-profiles.md#scope).

### Optional static checks

- `--checks LIST` (`--chk`): complete comma-separated selection of optional static checks.
  Default without config: `python,yaml,toml,yara,patterns`; the `basic` profile alias
  defaults to `none`. An explicit list replaces the configured selection.
  Names: `python` for Python AST checks, `yaml` and `toml` for structural parsing,
  `yara` for native YARA-X signatures, and `patterns` for adapted SkillSpector checks.
  `none` disables all optional static checks. Built-in checks always remain enabled.
  Supply the flag only once; empty, unknown, duplicate names and mixing `none`
  with other names are rejected.
- `--yara FILE` (`-y`): additional trusted YARA source; unset by default. Requires
  enabled YARA checks. Includes and console access are prohibited.

Subsets and `none` require `--profile custom`; `standard` and `review` require the
full set. For built-in checks only, use `--profile custom --checks none`.
See [checks and extensions](../user/inspection-profiles.md).

### Concurrency and budgets

- `--rulepack FILE`: explicit trusted `scout.rulepack/v1` additional YARA source
  artifact; unset by default. Requires YARA selection and is mutually exclusive
  with `--yara`. The file must be outside every inspected input.
- `--rulepack-sha256 DIGEST`: optional lowercase 64-digit SHA-256 pin for all
  artifact bytes. Requires `--rulepack`; version metadata and whitespace are bound.
  A mismatch or incompatible ABI fails initialization. No automatic download or fallback.
- `--workers N` (`-w`): analyzer workers shared across the operation's targets; default
  `4`, range 1..32.
- `--target-workers N` (`--tw`): simultaneous targets; default `1`, range 1..32.
- `--timeout DURATION` (`-t`): entire scan or comparison deadline; default `2m`, positive
  and at most `10m`.
- `--parser-timeout DURATION`: deadline for one parser operation; default `3s`,
  positive and at most `10s`.
- `--max-files N`: captured files per target; default `4096`, positive and no larger
  than `--max-entries`.
- `--max-entries N`: inventoried entries per target, including rejected entries;
  default `8192`, range 1..100000.
- `--max-file-bytes N`: bytes per captured file; default `1048576` (1 MiB),
  range 1..33554432.
- `--max-target-bytes N`: captured bytes per target; default `33554432` (32 MiB),
  at least `--max-file-bytes` and at most `268435456`.
- `--max-archive-bytes N`: source archive bytes per target; default `33554432`,
  range 1..134217728.
- `--max-run-bytes N`: aggregate captured bytes across the run; default
  `33554432`, range 1..268435456.
- `--max-operations N`: analysis work budget shared across targets and tasks;
  default `16777216`, range 1..1099511627776.
- `--max-matches-per-rule N`: candidate match ceiling per analyzer across one
  target's files; default `1024`, range 1..100000.
- `--max-findings N`: retained findings across the whole run; default `1024`,
  range 1..100000. Omitted findings make the run incomplete.
- `--extract-depth N`: recursive extraction depth; default `4`, range 1..16.
- `--extract-objects N`: derived objects per target; default `256`, range 1..4096.
- `--extract-entries N`: visited extraction entries per target; default `8192`,
  range 1..100000.
- `--extract-object-bytes N`: bytes per derived object; default `1048576`,
  range 1..33554432.
- `--extract-bytes N`: extracted bytes per target; default `16777216`
  (16 MiB), at least `--extract-object-bytes` and at most `134217728`.

Per-target ceilings are also bounded by shared run budgets, divided among targets.
Configuration additionally exposes `limits.max_extracted_bytes` (default 16 MiB),
`limits.max_capture_files` (4096), `limits.max_capture_entries` (8192) and
`limits.max_service_requests` (64); these currently have no CLI flags.
Increasing a per-target limit does not increase the corresponding run budget.

### Downloads

- `--allow-download`: authorize explicit remote acquisition; default `false`.
- `--download-timeout DURATION`: deadline for acquiring one remote target; default `30s`,
  positive and at most `2m`. Use with `--allow-download`.
- `--download-allow-loopback`: permit explicit numeric loopback download endpoints
  and their plain HTTP URLs; default `false`. Requires `--allow-download`.
- `--git`: treat an ambiguous HTTPS URL as a Git clone URL. Requires `--allow-download`.
- `--revision SHA`: optional full 40-character Git commit SHA. Git scans capture
  the remote `HEAD` when omitted. Requires `--allow-download`.
- `--git-auth-origin ORIGIN`, `--git-auth-user USER`, `--git-token-env NAME`:
  supply all three for authenticated Git over HTTPS. Scout reads the token from
  the named environment variable and sends it only to the exact origin.
  Requires `--allow-download`.
- `--download-sha256 HEX`: expected SHA-256 of the complete downloaded bytes,
  64 hexadecimal characters. Requires `--allow-download`. Applies to direct
  downloads and GitHub archives. For Smart HTTP Git, use the pinned commit SHA.

Revision/checksum flags override matching `remote_pins` from config for every remote
target in the invocation. See [remote sources](external-sources.md).

### External references

- `--follow-external`: capture supported literal external source references;
  default `false`. Requires `--allow-download`.
- `--external-origin ORIGIN`: exact allowed origin; repeatable. Supplying this flag
  replaces the defaults `https://raw.githubusercontent.com` and `https://github.com`.
- `--external-depth N`: maximum reference hops; default `2`, range 1..8.
- `--external-max-requests N`: traversal request ceiling across the run; default
  `16`, range 1..64, also bounded by the shared service budget.
- `--external-max-bytes N`: aggregate traversal response bytes; default `4194304`
  (4 MiB), range 1..33554432.

All `--external-*` flags require `--follow-external`. Allowed origins must use HTTPS
unless an explicit numeric loopback exception applies.

### Vulnerabilities

- `--osv`: enable exact-coordinate advisory lookup; default `false`.
  A bundled subset supplies positive matches where online and cache answers are unavailable.
- `--allow-osv-network`: authorize package-coordinate queries independently
  of downloads and source upload; default `false`.
- `--osv-cache FILE`: trusted exact-query cache; unset by default. A cache path also
  enables the service. Version 1 covers ordinary vulnerability IDs; version 2
  also selects `MAL001` for explicitly classified malicious-package records.
  Fresh version-2 cache answers take precedence over ordinary network queries.
  A nonempty cache path also takes precedence over `--osv=false`.
- `--osv-snapshot-dir DIR`: local OSV archive directory containing `Go/all.zip`,
  `npm/all.zip` or `PyPI/all.zip`. Enables offline lookup and cannot be combined
  with `--allow-osv-network`. The config equivalent is `vulnerabilities.snapshot_dir`.
- `--osv-cache-max-age DURATION`: maximum cache age; default `168h` (7 days),
  range `1m`..`8760h`.
- `--osv-endpoint URL`: query endpoint; default `https://api.osv.dev/v1/querybatch`.
- `--osv-allow-loopback`: permit an explicit numeric loopback query endpoint;
  default `false`.
- `--osv-max-requests N`: request ceiling including failed requests, pagination and advisory details;
  default `128`, range 1..256. The shared service budget can reduce it.

Use `--osv-*` tuning flags with an enabled service. Bundled answers leave coverage
partial and are omitted from exact-query cache exports.
See [OSV usage](../user/usage.md#network-services-and-extra-rules).

### LLM review

- `--review` (`--llm`): enable a reviewer configured by flags; default `false`. A `review`
  object in config also enables the reviewer. `--review=false` disables that
  configured service; also select a non-review profile when disabling it.
- `--allow-source-upload`: authorize captured source upload; default `false`.
  Required for every enabled reviewer, including local services.
- `--quality-review`: include the optional quality/policy stage; default `false`.
- `--llm-provider chat-completions|anthropic|anthropic-proxy|bedrock`: provider
  transport; default `chat-completions`.
- `--llm-endpoint URL`: explicit trusted reviewer endpoint; unset by default.
- `--llm-model NAME`: explicit model; unset by default.
- `--llm-api-key-env NAME`: environment variable containing the API key; unset by
  default. No automatic credential discovery. Used for non-Bedrock providers.
- `--llm-aws-region REGION`: Bedrock region; unset by default.
- `--llm-aws-access-key-env NAME`: Bedrock access-key variable; unset by default.
- `--llm-aws-secret-key-env NAME`: Bedrock secret-key variable; unset by default.
- `--llm-aws-session-token-env NAME`: optional Bedrock session-token variable;
  unset by default.
- `--llm-allow-loopback`: permit an explicit numeric loopback reviewer endpoint;
  default `false`.
- `--llm-max-output-tokens N`: requested completion token ceiling; default `2048`,
  range 128..8192.
- `--llm-max-response-bytes N`: provider HTTP response byte ceiling; default `65536`
  (64 KiB). This does not increase the separate decoded-review response budget.
- `--llm-max-requests N`: review requests per target, shared across passes; default
  `64`, range 1..256. The run's shared service budget can reduce it.
- `--llm-max-input-bytes N`: serialized user-request bytes across the run, shared
  across targets and passes; default `2097152` (2 MiB), range 32768..8388608.
- `--llm-timeout DURATION`: deadline per provider request; default `30s`, positive
  and at most `2m`, also bounded by the overall operation deadline.

Provider/quality flags require an enabled reviewer. `--profile review` still needs
`--review` when the reviewer is supplied only through flags. See
[semantic review](../user/semantic-review.md) for consent and provider requirements.

## Compare

`compare` requires exactly two local paths. It supports scan configuration, report,
policy, check, concurrency, budget, OSV and reviewer flags.

- `--max-changes N`: maximum retained comparison deltas; default `4096`,
  range 1..20000. Truncation makes the comparison incomplete.
- `--pr-head OWNER/REPO@SHA` enables static capability comparison and selects
  the candidate commit for source links. For GitLab, supply `PROJECT_URL@SHA`.
  The commit SHA must be full and lowercase. Markdown becomes the default format
  and renders the compact summary.
- `--pr-provider github|gitlab` selects the source-link format. Defaults to
  `github` and requires `--pr-head` when explicitly supplied.
- `--pr-path DIR` prefixes source links with the repository-relative POSIX
  directory. For a standalone file, use its parent directory. Requires `--pr-head`.
- `--approved-sha256 DIGEST` supplies the trusted candidate package snapshot
  digest as 64 lowercase hex digits. A match can clear the change-only review
  requirement. A mismatch requires review and incomplete checks retain exit `2`.

The timeout and aggregate budgets cover both scans and comparison.
See [update comparison](../user/update-review.md).

## Configuration validation

`config validate` uses the scan configuration, policy, static-check, concurrency,
budget and service flags to construct and validate a scanner, without targets.
`--config FILE` (`-c`) is optional. Validation starts from defaults when omitted.
The result is always the prepared inspection plan as JSON on stdout.

## MCP server

`mcp` uses scan configuration, policy, static-check, concurrency, budget and service
flags. Authorize named inputs with `--target` or supply them through tool uploads.
Reports are returned in tool responses.

- `--transport stdio|http`: transport; default `stdio`.
- `--listen ADDRESS`: HTTP numeric loopback bind; default `127.0.0.1:8837`.
- `--token-env NAME`: environment variable containing the HTTP bearer token;
  unset by default. Required for HTTP; token length 32..512 non-whitespace bytes.
- `--tool-timeout DURATION`: deadline for each admitted tool call; default `1m`,
  positive and at most `10m`. `--timeout` also bounds the scanner operation.
- `--concurrency N`: tool-call concurrency across sessions; default `2`,
  range 1..8.
- `--target NAME=LOCAL_PATH`: authorized named local input; repeatable, none by
  default, maximum 64. Tool callers select names rather than arbitrary paths.
- `--origin ORIGIN`: explicitly allowed browser HTTP Origin; repeatable, none by
  default. Empty means browser origins are denied. For HTTP only.

`--token-env` is also HTTP-only. Without named targets, use uploads.
See [MCP setup](../user/integrations.md#mcp-server).

`mcp snapshot` imports a local MCP capture. Use `--source-id ID` for a stable
source identifier and `--output FILE` (`-o`) to write the snapshot to a file.

## Doctor

`doctor` (alias `selftest`) checks the linked native backends.

- `--format text|json` (`-f`): output format; default `terminal`, an alias for `text`.
- `--timeout DURATION` (`-t`): cooperative total self-test deadline; default `90s`,
  positive and at most `2m`.

## Baseline

`baseline create`, `baseline approve` and `baseline renew` accept:

- `--from FILE`: required source. `create` reads a validated single-target JSON
  report; `approve` and `renew` read a baseline JSON document.
- `--output FILE` (`-o`): destination outside the source; required unless `--dry-run` is set.
- `--reason TEXT`: operator justification; required for nonempty create/approve
  operations. Renew preserves each existing reason when omitted.
- `--expires RFC3339`: required future expiry, for example `2099-01-01T00:00:00Z`.
- `--fingerprint SHA256`: repeatable exact-entry selector for approve/renew;
  omitted selects all. Unknown, duplicate or malformed selectors fail without writing.
- `--dry-run` (`-d`): print `scout.baseline-preview/v1` JSON changes to stdout without
  writing a baseline. `--output` is optional; a supplied destination is validated.

`create` writes pending entries. `approve` approves selected entries. `renew` only
extends approved entries; selecting a pending entry or a non-increasing expiry
fails. Without selectors it leaves pending entries untouched. Other entries retain
their reasons and expiry times. See [baseline workflow](../user/usage.md#baseline).

## Policy shadow

```sh
scout policy shadow --report scan.json --current current.json --trial trial.json --format json
```

- `--report FILE` selects a saved `scout.report/v1` JSON from `scan` or
  `compare`, up to 64 MiB.
- `--current FILE` and `--trial FILE` select two operator-owned
  `scout.config/v1` files. Only the `policy` section is applied, including
  explicitly configured baseline paths. Each policy starts from the CLI
  defaults. Include any scan-time policy flag overrides in the current config
  to reproduce its policy settings.
- `--at RFC3339` sets one evaluation time for both policies and their
  approval expiry checks. The default is the time of invocation.
- `--format text|json` (`-f`) selects output on stdout. The default is text.

A trial config that raises the blocking threshold and sends lower-severity
findings to review can be written as:

```json
{"schema":"scout.config/v1","policy":{"fail_at":"critical","review_below_threshold":true}}
```

Both policies evaluate the same validated observations offline. The saved
evaluation supplies no approvals. The preview shows both decisions and reason
codes, target-qualified finding changes, and threshold changes for manifest
signals. A finding can move between `block`, `review`, `below_threshold` and
`suppressed`. In a saved comparison, finding dispositions apply to the
candidate side. JSON uses `scout.policy-shadow/v1` and includes policy hashes.

The command returns 0 when it writes a preview and 2 on error. Each policy has
its own projected admission exit code in the preview, including 2 for an
incomplete run.

## Rules, profiles and capabilities

- `rules list --all`: include adapted, Python and YARA rule metadata; default
  `false`. Without `--all`, print the base catalog. Output is JSON.
- `profiles`: profile-name JSON list; no flags.
- `capabilities`: compiled parser/signature backend JSON; no flags.
- `version` prints the build version. The root flag `--version` (`-v`) does the same.

## Knowledge and integrations

`knowledge` prints the compiled catalog as JSON by default.

- `--mode discovery|intent|tool_consistency|assessment|proposal_assessment|quality`:
  print the exact trusted runtime prompt for the selected mode; unset by default.

`integrations list` prints bundle manifests as JSON and takes no flags.
`integrations export` accepts:

- `--bundle agent-skill|claude-code|codex|pi|opencode|review-materials`: required
  bundle name; unset by default.
- `--output FILE` (`-o`): required new ZIP path. Existing files are never replaced.

See [integration bundles](../user/integrations.md).

## Registry

`registry fetch` takes no positional inputs and accepts:

- `--endpoint URL`: registry servers endpoint; default
  `https://registry.modelcontextprotocol.io/v0/servers`.
- `--name NAME`: exact server name; unset means all names.
- `--latest`: select registry-asserted latest records per name; default `false`.
- `--allow-download`: authorize registry requests; default `false`.
- `--allow-loopback`: permit a numeric loopback fixture endpoint; default `false`.
- `--max-pages N`: page ceiling; default `32`, range 1..128.
- `--max-bytes N`: aggregate response bytes; default `8388608` (8 MiB),
  range 1..33554432.
- `--output FILE` (`-o`): snapshot JSON destination; default stdout.

`registry compare` takes two snapshot paths, previous then current:

- `--output FILE` (`-o`): comparison JSON destination; default stdout.

See [registry snapshots](external-sources.md#mcp-registry).

## Attestation verification

`attestation verify` requires all four flags, unset by default:

- `--public-key FILE`: explicit trusted PKIX public key PEM, outside inspected inputs.
- `--envelope FILE`: DSSE envelope or OMS bundle.
- `--artifact FILE`: regular artifact file whose exact bytes must match the signature.
- `--subject NAME`: exact signed subject name.

See [signature verification](external-sources.md#dssein-toto-verification).

## Exit codes

For scans and comparisons: `0` = complete and allowed; `1` = complete but review or
block required; `2` = incomplete, cancelled, invalid request or output failure.
Available reports are still useful on nonzero exit codes.

For attestation verification: `0` = agreement, `1` = signature or subject mismatch,
`2` = malformed input or operational failure. Doctor returns `2` when a native
self-test fails. Other operator commands use `0` for success and `2` for failure.

### Rulepack artifacts

`scout rules pack create --id ID --version VERSION --yara FILE [--output FILE]`
packages trusted UTF-8 additional source as deterministic JSON. The artifact goes
to stdout by default. Use `--output FILE` (`-o`) to write it to a file.
Publication cannot overwrite the source file. The command requires `--id`,
`--version` (`-v`) and `--yara` (`-y`) and rejects positional arguments.
Creation validates metadata and bounds; it does not compile YARA.

`scout rules pack inspect [--sha256 DIGEST] FILE` validates exact schema fields,
`scout.yara-source/v1` compatibility, the embedded source checksum and an optional
independent artifact pin. It prints only identity JSON, without the rule source.
No installation, compilation or network access occurs. Scanner initialization
compiles selected rules and rejects invalid YARA, includes and console usage.

Both commands require explicitly selected local files. The artifact is limited to
256 KiB, including JSON escaping and metadata; source also has the backend's
256 KiB ceiling. A hash is byte identity, not publisher authentication. See
[rulepack usage](../user/usage.md#versioned-rulepacks) for configuration and rollback.

## Environment snapshots

```text
scout snapshot create --snapshot FILE --root ID=PATH [local scan flags]
scout snapshot compare --snapshot FILE --root ID=PATH [compare flags]
scout snapshot compare --snapshot FILE --empty [compare flags]
scout snapshot compare --snapshot FILE --candidate FILE [compare flags]
scout snapshot compare --snapshot FILE --save-candidate NEW_FILE [compare flags]
scout snapshot compare --snapshot FILE [--source-diff] [compare flags]
scout snapshot inspect --snapshot FILE [--format text|json]
scout discover --agent AGENT --snapshot FILE [discovery flags] -- [local scan flags]
```

`--snapshot FILE` (`-s`) selects a new checkpoint for create or an existing checkpoint for compare.
Repeat `--root` for the complete current selection. `--empty` explicitly selects no roots.
`snapshot inspect` accepts `--format text|json` (`-f`).
`snapshot compare` accepts `--format text|json|markdown|sarif` and `--report FORMAT=PATH`.
See [saved environments](../user/environment-snapshots.md).

Without `--root`, `--empty` or `--candidate`, snapshot compare repeats saved discovery or rechecks saved source paths.
`--candidate` reads a second snapshot and cannot be combined with `--root`, `--empty` or `--save-candidate`.
`--save-candidate` writes the current bytes used in the comparison and their inspection to a new file.
`--source-diff` includes bounded source excerpts only when explicitly selected.
