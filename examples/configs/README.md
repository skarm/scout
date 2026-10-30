# Ready-to-use configurations

English · [Русский](README.ru.md)

Choose a file with `--config`. These are ordinary `scout.config/v1` files;
the inspection profiles remain `standard`, `review` and `custom`.
Examples below run from the repository root with `scout` in `PATH`.

- [standard.json](standard.json): everyday offline static review; default coverage
  and budgets, blocking threshold `high`.
- [ci.json](ci.json): stricter offline policy; block at `medium` and require review
  for lower-severity findings.
- [batch.json](batch.json): offline review of several inputs, with four concurrent
  targets and larger shared budgets.
- [core.json](core.json): built-in checks and adapted patterns, for the core build
  or an explicitly reduced selection.
- [vuln.json](vuln.json): standard static checks plus network OSV queries, with an
  explicit permission flag at launch.
- [review.template.json](review.template.json): template for standard static checks
  plus an operator-configured Chat Completions reviewer. Fill in endpoint and model.

## Select and validate a configuration

```sh
scout config validate --config examples/configs/standard.json
scout scan --config examples/configs/standard.json --format markdown ./my-skill
scout compare --config examples/configs/standard.json --format markdown ./previous ./candidate
```

Keep the config outside every scanned target. To scan this checkout itself, first
copy a config to an operator-owned location outside the checkout:

```sh
mkdir -p "$HOME/.config/scout"
cp examples/configs/standard.json "$HOME/.config/scout/standard.json"
scout scan --config "$HOME/.config/scout/standard.json" --format markdown .
```

Use an absolute config path when running from another directory. Explicit flags
override the selected file, for example `--timeout 4m` or `--harness claude-code`.
Only one `--config` is accepted; copy a preset and edit it to combine settings.
Relative baseline, rules and cache paths inside a config resolve from the current
working directory.

All shipped configurations use the conservative coverage policy. Declared
language limitations can require review even with zero findings. If your policy
accepts the selected language-analysis scope, explicitly add `--scope selected`;
execution failures and coverage gaps still prevent a complete allow.

## Strict CI policy

```sh
scout scan --config examples/configs/ci.json --format json \
  --report sarif=/tmp/scout.sarif ./my-skill
```

`medium`, `high` and `critical` findings block. `low` and `info` findings require
review. The blocking threshold alone does not determine the exit code:

- `0`: complete and allowed by policy.
- `1`: complete, but review or block required.
- `2`: incomplete, cancelled, invalid request or report-publication failure.

This preset adds no baseline approvals. Keep the original exit code and retain
reports in CI. See [report output](../../docs/user/usage.md#save-reports).

## Several inputs

```sh
scout scan --config examples/configs/batch.json --format markdown ./skills ./plugins
```

This preset uses four target workers, four analyzer workers shared by the run,
and a five-minute operation deadline. Shared budgets are 128 MiB captured,
64 MiB extracted, 16384 files, 32768 inventory entries, 67108864 analysis operations
and 4096 retained findings. Per-target capture/extraction ceilings keep their
standard defaults. The run divides shared budgets among the actual input count;
four workers does not mean a separate full budget for every input.

## Core build

```sh
make build-core
./bin/scout-core scan --config examples/configs/core.json --format markdown ./my-skill
```

The `custom` profile enables built-in checks and `patterns`. Python AST, YAML/TOML
parsers and YARA are explicitly disabled. The same file also works with a full
binary as `scout scan --config examples/configs/core.json ...`. This selection has narrower
coverage than `standard`; unsupported analysis remains visible in the report.
See [build variants](../../docs/development/native-build.md).

## Vulnerability queries

```sh
scout config validate --config examples/configs/vuln.json --allow-vulnerability-network
scout scan --config examples/configs/vuln.json --allow-vulnerability-network \
  --format markdown ./my-skill
```

The config enables exact-coordinate OSV queries with a 32-request ceiling per
target, also bounded by the shared service budget. Queries require the grant at
each invocation, including validation. Downloads and source upload have separate
permissions. For offline advisory lookup, supply your own exact-query cache using
the [cache workflow](../../docs/user/usage.md#network-services-and-extra-rules).

## LLM review template

```sh
mkdir -p "$HOME/.config/scout"
cp examples/configs/review.template.json "$HOME/.config/scout/review.json"
```

Edit `review.endpoint` and `review.model` for your selected Chat Completions service.
The `.invalid` address and `REPLACE_ME` model are placeholders. Set the API key in
`SCOUT_REVIEW_API_KEY` using your shell or secret manager; `key_env` stores only the
variable name.

```sh
scout config validate --config "$HOME/.config/scout/review.json" --allow-source-upload
scout scan --config "$HOME/.config/scout/review.json" --allow-source-upload \
  --format markdown ./my-skill
```

The preset allows up to 32 review requests and 2 MiB of serialized user-request
bytes, with a 30-second request timeout and five-minute operation deadline.
Quality review is optional; add `--quality-review` to select it. Source upload
consent is required on each invocation because excerpts can contain secrets.
Validation checks settings and local backends; provider availability is checked
when scanning. See [review setup](../../docs/user/semantic-review.md) for other transports.

Output formats, destinations and targets are selected by command-line arguments.
Download/network/upload grants are always explicit flags. See the
[complete CLI reference](../../docs/reference/cli.md) for all controls and defaults.
