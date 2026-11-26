# Scout

[Русский](README.ru.md)

Scout inspects AI agent skills and plugins before installation or updates. It checks instructions, configuration, code and supported attachments without executing the package.

## Install

Download the archive for your platform and `SHA256SUMS` from [GitHub Releases](https://github.com/skarm/scout/releases). Look for `macos-arm64` on Apple Silicon, `linux-amd64` on x86-64 Linux, or `windows-amd64` on Windows x64. Available archives are listed on each release.

On macOS or Linux, replace the example archive name below with the one you downloaded. Run the commands in the download directory and extract only after the checksum check succeeds.

```sh
archive=scout-vX.Y.Z-macos-arm64.tar.gz
checksum=$(awk -v file="$archive" '$2 == file { print; matches++ } END { if (matches != 1) exit 1 }' SHA256SUMS) &&
  printf '%s\n' "$checksum" | shasum -a 256 -c - &&
  tar -xzf "$archive" && ./scout doctor
```

On Linux, `sha256sum -c -` is an alternative to `shasum -a 256 -c -`.

On Windows, run `Get-FileHash -Algorithm SHA256 .\scout-vX.Y.Z-windows-amd64.zip` in PowerShell and compare `Hash` with the entry for that exact archive in `SHA256SUMS`. Extract the verified archive and run `.\scout.exe doctor`. Add the binary's directory to `PATH` for the examples below.

To build from source on supported macOS and Linux platforms, use Go 1.26+, a C compiler, `make` and `pkg-config`. Make prepares the native dependencies. [Build guide](docs/development/native-build.md)

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

## Track changes to your agent environment

From your project directory, capture its Codex skills in `.agents/skills`.

```sh
scout discover --agent codex --project . --kind skill --include-path "$PWD/.agents/skills" \
  --snapshot /path/to/private/before.json -- --format markdown
```

After updating the skills, compare the current environment with the saved snapshot.

```sh
scout snapshot compare --snapshot /path/to/private/before.json --format markdown
```

Use a new snapshot file in a private directory outside the project and the agent's directories. Snapshots include the captured source bytes. See the guide for Claude Code and for selecting other components. [Environment snapshots](docs/user/environment-snapshots.md)

An exit code of `1` means the completed scan requires review or blocks the selected content. The snapshot can still be saved with that decision.

## Use Scout in your workflow

- [CLI commands and flags](docs/reference/cli.md) and [configuration examples](examples/configs/README.md)
- [Go API](docs/development/go-api.md) and [Go API example](examples/go-api/README.md)
- [MCP and agent integrations](docs/user/integrations.md)
- [Documentation](docs/README.md), [contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)
