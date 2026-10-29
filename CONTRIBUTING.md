# Contributing to Scout

Report reproducible bugs and propose changes through
[GitHub issues](https://github.com/skarm/scout/issues). For vulnerabilities, follow
[the security policy](SECURITY.md) before sharing details publicly.

## Development

Use Go 1.26+, a C compiler, Make, pkg-config and Node.js 24 for adapter tests.
Prepare dependencies with `make deps native-deps`; see the
[build guide](docs/development/native-build.md) for supported platforms.

Keep changes focused and add regression coverage for behavior changes. Never
execute captured payloads in `testdata/`: they are scanner inputs. Use synthetic
credentials and remove private data from reports and fixtures.

Before opening a pull request, run:

```sh
make lint
make test-core test race host-test releasecheck acceptance
```

Acceptance checks the integrity of recorded measurements independently of the
current checkout. Editing code or comments does not require refreshing receipts.
Use [the provenance commands](docs/development/commands.md#source-bound-provenance)
when intentionally recording a new measurement; `provenance verify --current-sources`
explicitly audits whether a receipt describes the current checkout.

## Pull requests

Describe the problem, resulting behavior and validation. Record checks you could
not run, including platform limitations. Update matching English and Russian
guides when commands or behavior change. Preserve source attribution and include
the applicable license for new third-party material.

Original contributions are provided under the project's [MIT license](LICENSE).
Existing third-party material keeps its own license and notices.
