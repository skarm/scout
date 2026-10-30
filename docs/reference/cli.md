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
- [Rules, profiles and capabilities](#rules-profiles-and-capabilities)
- [Knowledge and integrations](#knowledge-and-integrations)
- [Registry](#registry)
- [Attestation verification](#attestation-verification)
- [Exit codes](#exit-codes)

## Syntax and help

```sh
scout -h
scout scan -h
scout scan --format json ./my-plugin
scout scan --format json -- "$target"
scout scan --input - --name SKILL.md --format json < ./SKILL.md
```

`scout -h`, `scout --help` and `scout help` print the complete command and flag
reference. `scout scan -h` or `scout scan --help` prints scan flags and defaults.
Commands with a flag parser also accept `-h` and `--help` before their inputs.

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
scout scan [flags] --input - --name <relative-name>
scout compare [flags] <before> <after>
scout discover [flags] [--scan -- <scan flags>]
scout config validate [flags]
scout mcp [flags]
scout doctor [flags]
scout baseline create|approve [flags]
scout rules list [--all]
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

`scout discover` inventories Codex and Claude Code; `--scan` passes discovered
roots to the existing Scanner. See [locations, format and limits](../user/discovery.md).

- `--agent all|codex|claude-code`: agent; default `all`.
- `--home DIR`: selected user home; default current user's home.
- `--codex-home DIR`, `--claude-home DIR`: explicit agent configuration directories.
  Without `--home`, process `CODEX_HOME` and `CLAUDE_CONFIG_DIR` are honored.
- `--project DIR`: repeatable selected project; default current directory.
- `--no-project`: omit projects; default `false`.
- `--system[=BOOL]`: known system locations; default `true`.
- `--max-entries N`: aggregate probes/directory entries; default 10000, 1..100000.
- `--max-depth N`: skill/plugin traversal depth; default 12, 1..32.
- `--max-bytes N`: aggregate config/manifest bytes; default 8388608, 1..67108864.
  A single file is limited to 256 KiB.
- `--timeout DURATION`: discovery deadline; default `10s`, greater than 0 and at most `2m`.
- `--format text|json`: inventory format; default `text`.
- `--output FILE`: inventory outside scan inputs; default stdout.
- `--scan`: scan discovered roots; default `false`. Ordinary scan flags follow `--`.
  Inventory `--format`/`--output` flags are rejected in this mode.

Inventory uses `scout.environment/v1`; exit 0 means complete within the documented
surface, and 2 means error or incomplete discovery. It is not a policy decision.
`--scan` requires complete discovery and 1..32 roots; it returns the ordinary scan
report and exit code. Declaration states do not establish component activation.

## Scan flags

### Input and configuration

- `--environment`: explicitly relate selected local roots as one agent/project
  environment; default `false`. Independent scans remain independent by default.
  Requires existing, nonoverlapping local roots and does not support external traversal.
  See [environment analysis](../user/environment-analysis.md).

- `--config FILE`: explicit operator JSON configuration; unset by default. May be
  supplied only once. Configuration is never discovered inside targets.
- `--profile standard|review|custom`: inspection preset; default `standard`.
  `standard` selects all static checks; `review` also requires a configured reviewer;
  `custom` permits explicit check selection. CLI aliases: `extended` = `standard`,
  `semantic` = `review`, `basic` = `custom` with all optional static checks disabled.
- `--harness auto|claude-code|codex|agent-skills`: interpretation of agent/plugin
  declarations; default `auto`.
- `--input -`: read one input from stdin; unset by default. Only `-` is supported.
- `--name RELATIVE_PATH`: required with `--input -`; the input's relative filename,
  used for format detection and source coordinates. Unset by default.

Keep config, baseline, extra rules and caches outside all inspected inputs.
See [configuration](../user/usage.md#configuration) and
[profiles](../user/inspection-profiles.md).
Copy a [ready-to-use config](../../examples/configs/README.md) for a common workflow.

### Reports

- `--format text|json|sarif|markdown`: primary report format; default `text`.
  `terminal` is an alias for `text`.
- `--output FILE`: primary report destination; default stdout. An existing regular
  file is replaced atomically; directories and symlinks are rejected.
- `--report FORMAT=PATH`: additional report destination; repeatable, none by default.
  Uses the same formats as `--format`. Destinations must be distinct and outside
  inputs and trusted operator files. The primary report is still produced.

Diagnostics go to stderr. Create destination directories before running Scout.
See [report publication](../user/usage.md#save-reports).

### Policy

- `--fail-on info|low|medium|high|critical`: minimum unsuppressed finding severity
  that blocks admission; default `high`. Other policy reasons can still require
  review, and incomplete execution still exits with code 2.
- `--block-at SEVERITY`: alias for `--fail-on`; same default. If both occur, the
  last supplied value wins.
- `--scope conservative|selected`: language coverage policy; default `conservative`.
  `selected` accepts declared language-analysis limitations, but does not waive
  parsing failures, unfinished checks or exhausted budgets.
- `--baseline FILE`: trusted operator baseline JSON; unset by default.
- `--allow-baseline-globs`: permit glob approvals in that baseline; default `false`.

See [baseline](../user/usage.md#baseline) and
[coverage policy](../user/inspection-profiles.md#scope).

### Optional static checks

- `--checks LIST`: complete comma-separated selection of optional static checks.
  Default without config: `python,yaml,toml,yara,patterns`; the `basic` profile alias
  defaults to `none`. An explicit list replaces the configured selection.
  Names: `python` for Python AST checks, `yaml` and `toml` for structural parsing,
  `yara` for native YARA-X signatures, and `patterns` for adapted SkillSpector checks.
  `none` disables all optional static checks. Built-in checks always remain enabled.
  Supply the flag only once; empty, unknown, duplicate names and mixing `none`
  with other names are rejected.
- `--yara-rules FILE`: additional trusted YARA source; unset by default. Requires
  enabled YARA checks. Includes and console access are prohibited.

Subsets and `none` require `--profile custom`; `standard` and `review` require the
full set. For built-in checks only, use `--profile custom --checks none`.
See [checks and extensions](../user/inspection-profiles.md).

### Concurrency and budgets

- `--workers N`: analyzer workers shared across the operation's targets; default
  `4`, range 1..32.
- `--target-workers N`: simultaneous targets; default `1`, range 1..32.
- `--timeout DURATION`: entire scan or comparison deadline; default `2m`, positive
  and at most `10m`.
- `--parser-timeout DURATION`: deadline for one parser operation; default `3s`,
  positive and at most `10s`.
- `--max-files N`: captured files per target; default `4096`, positive and no larger
  than `--max-entries`.
- `--max-entries N`: inventoried entries per target, including rejected entries;
  default `8192`, range 1..100000.
- `--max-file-bytes N`: bytes per captured file; default `1048576` (1 MiB),
  range 1..33554432.
- `--max-total-bytes N`: captured bytes per target; default `33554432` (32 MiB),
  at least `--max-file-bytes` and at most `268435456`.
- `--max-archive-bytes N`: source archive bytes per target; default `33554432`,
  range 1..134217728.
- `--max-capture-bytes N`: aggregate captured bytes across the run; default
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
- `--extract-total-bytes N`: extracted bytes per target; default `16777216`
  (16 MiB), at least `--extract-object-bytes` and at most `134217728`.

Per-target ceilings are also bounded by shared run budgets, divided among targets.
Configuration additionally exposes `limits.max_extracted_bytes` (default 16 MiB),
`limits.max_capture_files` (4096), `limits.max_capture_entries` (8192) and
`limits.max_service_requests` (64); these currently have no CLI flags.
Increasing a per-target limit does not increase the corresponding run budget.

### Downloads

- `--allow-download`: authorize explicit remote acquisition; default `false`.
- `--download-timeout DURATION`: deadline for one download request; default `30s`,
  positive and at most `2m`. Use with `--allow-download`.
- `--download-allow-loopback`: permit explicit numeric loopback download endpoints
  and their plain HTTP URLs; default `false`. Requires `--allow-download`.
- `--revision SHA`: full 40-character commit SHA for a GitHub repository root;
  unset by default. Requires `--allow-download`.
- `--download-sha256 HEX`: expected SHA-256 of the complete downloaded bytes,
  64 hexadecimal characters; unset by default. Requires `--allow-download`.

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

- `--vuln`: enable exact-coordinate OSV queries; default `false`.
  Requires network permission or an explicit offline cache.
- `--allow-vulnerability-network`: authorize package-coordinate queries independently
  of downloads and source upload; default `false`.
- `--osv-cache FILE`: trusted exact-query cache; unset by default. A cache path also
  enables the service. Currently, `--vuln=false` does not override a
  nonempty cache path.
- `--osv-cache-max-age DURATION`: maximum cache age; default `168h` (7 days),
  range `1m`..`8760h`.
- `--osv-endpoint URL`: query endpoint; default `https://api.osv.dev/v1/querybatch`.
- `--osv-allow-loopback`: permit an explicit numeric loopback query endpoint;
  default `false`.
- `--osv-max-requests N`: request ceiling, including failed requests and pagination;
  default `128`, range 1..256. The shared service budget can reduce it.

Use `--osv-*` tuning flags with an enabled service. Missing or stale cache records
leave inspection gaps. See [OSV usage](../user/usage.md#network-services-and-extra-rules).

### LLM review

- `--semantic`: enable a reviewer configured by flags; default `false`. A `review`
  object in config also enables the reviewer. `--semantic=false` disables that
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
- `--llm-max-requests N`: review request budget shared across passes; default `64`,
  range 1..256. The shared service budget can reduce it.
- `--llm-max-input-bytes N`: aggregate serialized user-request bytes; default
  `2097152` (2 MiB), range 32768..8388608.
- `--llm-timeout DURATION`: deadline per provider request; default `30s`, positive
  and at most `2m`, also bounded by the overall operation deadline.

Provider/quality flags require an enabled reviewer. `--profile review` still needs
`--semantic` when the reviewer is supplied only through flags. See
[semantic review](../user/semantic-review.md) for consent and provider requirements.

## Compare

`compare` requires exactly two local paths. It supports scan configuration, report,
policy, check, concurrency, budget, OSV and reviewer flags. It rejects `--input`,
`--name`, `--allow-download`, `--revision`, `--download-*`, `--follow-external` and
`--external-*`.

- `--max-changes N`: maximum retained comparison deltas; default `4096`,
  range 1..20000. Truncation makes the comparison incomplete.

The timeout and aggregate budgets cover both scans and comparison.
See [update comparison](../user/update-review.md).

## Configuration validation

`config validate` uses the scan configuration, policy, static-check, concurrency,
budget and service flags to construct and validate a scanner, without targets.
`--config FILE` is optional; without it, validation starts from defaults.
The result is always the prepared inspection plan as JSON on stdout.
Scan report flags (`--format`, `--output`, `--report`) do not control this output.

## MCP server

`mcp` uses scan configuration, policy, static-check, concurrency, budget and service
flags. Inputs are authorized using `--target` or supplied by tool uploads;
`--input`/`--name` do not select stdin scan inputs. Scan report flags do not control
protocol output.

- `--transport stdio|http`: transport; default `stdio`.
- `--listen ADDRESS`: HTTP numeric loopback bind; default `127.0.0.1:8837`.
- `--auth-token-env NAME`: environment variable containing the HTTP bearer token;
  unset by default. Required for HTTP; token length 32..512 non-whitespace bytes.
- `--scan-timeout DURATION`: deadline for each admitted tool call; default `1m`,
  positive and at most `10m`. `--timeout` also bounds the scanner operation.
- `--max-concurrent N`: tool-call concurrency across sessions; default `2`,
  range 1..8.
- `--target NAME=LOCAL_PATH`: authorized named local input; repeatable, none by
  default, maximum 64. Tool callers select names rather than arbitrary paths.
- `--origin ORIGIN`: explicitly allowed browser HTTP Origin; repeatable, none by
  default. Empty means browser origins are denied. For HTTP only.

`--auth-token-env` is also HTTP-only. Without named targets, use uploads.
See [MCP setup](../user/integrations.md#mcp-server).

## Doctor

`doctor` (alias `selftest`) checks the linked native backends.

- `--format text|json`: output format; default `terminal`, an alias for `text`.
- `--timeout DURATION`: cooperative total self-test deadline; default `90s`,
  positive and at most `2m`.

## Baseline

Both `baseline create` and `baseline approve` accept:

- `--from FILE`: required source. `create` reads a validated single-target JSON
  report; `approve` reads a baseline JSON document.
- `--output FILE`: required destination; must not replace the source.
- `--reason TEXT`: operator justification; unset by default, required for nonempty
  baselines.
- `--expires RFC3339`: required future expiry, for example `2099-01-01T00:00:00Z`.

`create` writes pending entries. `approve` approves every entry in the selected
document. See [baseline workflow](../user/usage.md#baseline).

## Rules, profiles and capabilities

- `rules list --all`: include adapted, Python and YARA rule metadata; default
  `false`. Without `--all`, print the base catalog. Output is JSON.
- `profiles`: profile-name JSON list; no flags.
- `capabilities`: compiled parser/signature backend JSON; no flags.
- `version`: build version text; no flags. Root `--version` is equivalent.

## Knowledge and integrations

`knowledge` prints the compiled catalog as JSON by default.

- `--mode discovery|intent|tool_consistency|assessment|proposal_assessment|quality`:
  print the exact trusted runtime prompt for the selected mode; unset by default.

`integrations list` prints bundle manifests as JSON and takes no flags.
`integrations export` accepts:

- `--bundle agent-skill|claude-code|codex|pi|opencode|review-materials`: required
  bundle name; unset by default.
- `--output FILE`: required new ZIP path. Existing files are never replaced.

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
- `--output FILE`: snapshot JSON destination; default stdout.

`registry compare` takes two snapshot paths, previous then current:

- `--output FILE`: comparison JSON destination; default stdout.

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
