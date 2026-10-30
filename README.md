# Scout

English · [Русский](README.ru.md)

Scout checks AI agent skills and plugins before installation or updates. It analyzes
instructions, configuration, code and supported attachments without executing the
inspected package. Use it through the CLI, Go API or MCP.

## Install from source

Requires Go 1.26+, a C compiler, `make` and `pkg-config`.

```sh
make deps install
export PATH="$HOME/.local/bin:$PATH"
scout doctor
```

Make prepares the native dependencies automatically on supported macOS and Linux
platforms. The default installation directory is `~/.local/bin`; add it to your shell's
`PATH` once. Scout can then run from any directory. See the
[build guide](docs/development/native-build.md) for custom installation paths, CI builds
and offline preparation.

## Scan and compare

```sh
scout scan --format markdown ./my-skill
scout scan --format json --fail-on high ./skills ./plugins
scout compare --format markdown ./previous ./candidate
scout scan --input - --name SKILL.md --format json < ./SKILL.md
```

The default `standard` profile runs static checks offline. `review` adds a configured
LLM reviewer and requires source-upload consent. `custom` lets you choose checks.
Downloads and network vulnerability lookup require separate permissions.

Reports retain findings, inspection gaps and the policy decision. Incomplete checks
require attention even when no findings were reported. See [CLI usage](docs/user/usage.md)
for configuration, report files, baselines and exit codes.
The [CLI reference](docs/reference/cli.md) lists every flag and default;
`scout -h` prints the complete list in the terminal.
Start with [ready-to-use configurations](examples/configs/README.md) for standard review,
CI, batch scans, the core build, OSV or LLM review.

## Checks and extensions

The full build includes checks for agent instructions and prompt injection,
permissions and hooks, MCP configuration, hidden content, dependencies and
selected data flows in Go, Shell, JS/TS, Python and SQL. The `standard` profile
also includes adapted SkillSpector rules and embedded YARA-X signatures for
malware, webshells, cryptominers, hacktools and agent skill threats.

Without rebuilding, add custom or third-party YARA rules with `--yara-rules`,
enable OSV with `--vuln`, or connect an LLM through the `review`
profile. Network access and source uploads require separate grants.

```sh
scout rules list --all
scout capabilities
scout scan --yara-rules /etc/scout/organization.yar --fail-on medium ./my-plugin
```

See [checks and profiles](docs/user/inspection-profiles.md) for categories,
limitations and extension examples.

## Go API and integrations

Create a Scanner with `scout.New(ctx, scout.DefaultOptions())` and release it with
`Close`. Use `Scan`, `ScanMany` or `Compare`, then evaluate the result with a trusted
`policy.Gate` and prepare it for output with `report.Prepare`.
[API contracts](docs/development/go-api.md) · [Go API example](examples/go-api/README.md).

[Integration guides](docs/user/integrations.md) cover MCP and reviewer bundles for
Claude Code, Codex, Pi and OpenCode.

## Development

```sh
make test-core
make test
```

The full suite requires native dependencies. `make build` writes to `bin/` by default;
override it with `BIN_DIR`. `make clean` removes built binaries and temporary working
data; installed copies remain available. See [validation](docs/development/validation.md)
for other checks.

[Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

[Documentation](docs/README.md) · [Examples](examples/README.md) · [Architecture](docs/development/architecture.md) ·
[Languages](docs/reference/languages.md) · [Licenses and sources](docs/reference/port-manifest.md)
