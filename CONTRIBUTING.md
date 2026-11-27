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

The **PR quality changes** check compares the PR head with its merge base
and reports potential regressions in annotations and in its job summary.
It looks for removed or relabelled benign
cases and removed forbidden-rule expectations in the tracked regression corpora,
removed named Go negative controls, deleted or skipped Go tests, and changes to
literal test selections in workflows or the Makefile. It flags removed assertions
and common exact-to-coarse replacements in existing Go tests, and new or broadened
lint suppressions. Supported directives include `nolint`, Staticcheck and gosec
ignores in Go, `@ts-ignore` and ESLint disable comments in JavaScript and TypeScript,
and inline `# noqa` in Python. It also flags looser or removed literal jq
evaluation thresholds and `scout-dev evaluate` quality flags. Warnings are
advisory. Review renamed tests, changed build constraints and rewritten commands
in context.

Run the same check locally against committed revisions.

```sh
CGO_ENABLED=1 go run ./internal/dev/prquality origin/master HEAD
```

The check models literal Bash and Make commands, workflow conditions and Go
test declarations. It recognizes test-selection flags, Go platform suffixes,
guarded `testing.T` failure calls, package-level `testify` assertions and literal
jq comparisons. Review custom assertion helpers, shell expansion, computed
thresholds, generated jobs and dynamically named test cases in context.
JavaScript, TypeScript and Python comments use the native parsers. A candidate
source file that cannot be parsed produces an incomplete-check warning.
The approach is based on [Constraint-Driven Development](https://github.com/addyosmani/agent-skills/blob/main/skills/constraint-driven-development/SKILL.md).

Describe the problem, resulting behavior and validation. Record checks you could
not run, including platform limitations. Update matching English and Russian
guides when commands or behavior change. Preserve source attribution and include
the applicable license for new third-party material.

Original contributions are provided under the project's [MIT license](LICENSE).
Existing third-party material keeps its own license and notices.
