# Scout

[Русский](README.ru.md)

Scout inspects AI agent skills and plugins before installation or updates. It checks instructions, configuration, code and supported attachments without executing the package.

## Install

On supported macOS and Linux platforms, use Go 1.26+, a C compiler, `make` and `pkg-config`. Make prepares the native dependencies. Add `~/.local/bin` to your shell's `PATH` to use Scout from any directory. [Build guide](docs/development/native-build.md)

```sh
make deps install
export PATH="$HOME/.local/bin:$PATH"
scout doctor
```

## Scan and compare

```sh
scout scan --format markdown ./my-skill
scout scan --format json --fail-on high ./skills ./plugins
scout compare --format markdown ./previous ./candidate
```

Read the findings, completeness and policy decision together. A run with zero findings can still require review. The default `standard` profile runs offline. The `custom` profile selects checks, and `review` adds an LLM with explicit source-upload consent. Downloads and network vulnerability lookup have separate permissions. [CLI guide](docs/user/usage.md) · [Checks and profiles](docs/user/inspection-profiles.md)

## Use Scout in your workflow

- [CLI commands and flags](docs/reference/cli.md) and [configuration examples](examples/configs/README.md)
- [Go API](docs/development/go-api.md) and [Go API example](examples/go-api/README.md)
- [MCP and agent integrations](docs/user/integrations.md)
- [Documentation](docs/README.md), [contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)
