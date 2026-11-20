# Native build

English · [Русский](native-build.ru.md)

Requires Go 1.26+, a C compiler, `make` and `pkg-config`. Automatic preparation supports
macOS 15+ on Apple Silicon and GNU/Linux on ARM64 or x86-64. Rust and Homebrew are not required.

## Build and acceptance

```sh
make deps
make build
./bin/scout doctor --format json
make releasecheck
```

Make downloads the pinned YARA-X C API 1.22.0 package, verifies SHA-256 and stores it
in the user cache. Tree-sitter and Go bindings come from pinned Go modules.
`releasecheck` checks linkage, module metadata and fixed native self-tests for the built binary.

`make build-core` creates a reduced binary without the native backends. Select an
explicit custom profile when using it; standard requires the full backends.

## Installation and output paths

`make build` writes to `bin/` by default. Set `BIN_DIR` to any relative or absolute
directory; `build-core`, `build-dev`, `host-test`, `evaluate` and `releasecheck` use
the same setting. No build directory is required at runtime.

To install Scout for your user:

```sh
make install
export PATH="$HOME/.local/bin:$PATH"
scout doctor
```

Add the installation directory to your shell's `PATH` once. The default prefix is
`~/.local`; use `make install PREFIX=/opt/scout` to install into `/opt/scout/bin`
when that directory is writable. `DESTDIR` supports staging for packaging without
changing the installation prefix. Installation copies only the Scout executable.

In a GitHub Actions shell step, build directly into a runner-selected directory:

```sh
make build BIN_DIR="$RUNNER_TEMP/scout-bin"
export PATH="$RUNNER_TEMP/scout-bin:$PATH"
scout doctor
scout scan --format json ./my-skill
```

For use in later steps, also add the directory to `GITHUB_PATH`.
For an existing binary, add its directory to `PATH` or invoke its full path.

## Cache and offline builds

Prepare dependencies before disconnecting:

```sh
make deps native-deps
```

Subsequent builds reuse them. The default native cache is
`~/Library/Caches/scout/native/` on macOS and `${XDG_CACHE_HOME:-~/.cache}/scout/native/`
on Linux. Override it with `SCOUT_NATIVE_CACHE`. `make clean` removes the three
Scout binaries from `BIN_DIR` and temporary `.work/` data, preserving dependencies
and installed copies. Pass the same `BIN_DIR` when cleaning a custom build.

## External installation

For native Go commands on supported platforms, use the same dependency wrapper
as Make. Run it from the repository root:

```sh
go run -mod=readonly ./internal/dev/builddeps -- \
  go test -mod=readonly -tags=static_link ./...
```

Use `PKG_CONFIG_PATH` to select a trusted YARA-X C API 1.22.0 installation containing
`libyara_x_capi.a`, `yara_x.h` and its pkg-config file. This is required on platforms
without a pinned prepared package, or when bypassing both Make and the wrapper.
See [upstream C API instructions](https://virustotal.github.io/yara-x/docs/api/c/c-/)
for source builds.

## Build version

For release archives without Git metadata, supply a tag or commit SHA:

```sh
make build VERSION="$GITHUB_SHA"
```

All build targets accept `VERSION` and extra `LDFLAGS`. `scout version` reports the
resulting version. See [validation](validation.md) for test and acceptance commands.

## GitHub Actions releases

Branch pushes and pull requests run lint, core and Linux native tests with race
checks, recorded-evidence integrity checks and host adapter boundary tests.
Full macOS/Linux/Windows validation and release candidate builds run on version
tags or an explicit manual workflow run.

The **Scout release** workflow builds three full native distributions:

- `scout-vX.Y.Z-macos-arm64.tar.gz`: Apple Silicon, macOS 15+.
- `scout-vX.Y.Z-linux-amd64.tar.gz`: GNU/Linux x86-64, tested on Ubuntu 24.04.
- `scout-vX.Y.Z-windows-amd64.zip`: Windows x64, tested on Windows Server 2025.

Each archive contains only `scout` or `scout.exe` at its root.
`SHA256SUMS` is published separately and covers the archives available in the release. macOS builds are unsigned
and are not notarized; Windows binaries are not Authenticode-signed.

Commit and push the workflow and sources before creating a release tag:

```sh
git tag v1.2.3
git push origin v1.2.3
```

Tags with a numeric major, minor and patch version trigger publication. A tag such as `v1.2.3-rc.1` produces a prerelease. When the shared checks pass, the workflow publishes every platform archive that passed its own validation. At least one verified archive is required. A new release starts as a draft while its assets are uploaded.

Retrying failed jobs can add missing platform archives to the same release and update `SHA256SUMS`. The workflow preserves published archives and verifies any archive that is also present in the new build byte for byte. A mismatch requires a new tag.

Use **Actions → Scout release → Run workflow** for a trial build with packaged
archives. Choose `all` (the default), `linux-amd64`, `macos-arm64`, or
`windows-amd64` in the `platform` field. **Native engine validation** accepts
the same choice and runs the selected native jobs without the shared release
checks or packaging. Manual runs never publish a GitHub Release.

The workflow retains `release-assets` for 14 days. If a platform fails during
an all-platform run and the shared checks pass, the run retains the
remaining verified archives and their checksums in `release-assets-partial-<attempt>`.
The publish job uses the built-in `GITHUB_TOKEN` with `contents: write`;
no personal access token is required, subject to repository/organization policies.

The Windows job builds YARA-X 1.22.0 from pinned upstream commit
`e27597f2c05e13fe1c2bb459781aef8899afc485`, with Rust 1.95.0, its `Cargo.lock`
and the UCRT64 GNU Windows toolchain used by CGO. The release verifier rejects external
YARA-X and compiler-runtime DLLs and runs native selftests in a private environment.
Use the PowerShell scripts in `.github/scripts/` to build on Windows.
