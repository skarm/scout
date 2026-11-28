# Examples

English · [Русский](README.ru.md)

- [Configurations](configs/README.md): standard checks, CI, batch scans, core build,
  vulnerability queries and an LLM review template, with launch commands.
- [Go API example](go-api/README.md).
- [GitHub Actions package review](scout-package-review.yml) with a PR summary and
  [hash-based approval setup](../docs/user/update-review.md#pull-request-summary-and-package-approval).
- [GitLab CI package review](scout-package-review.gitlab-ci.yml) with an exposed
  [merge request artifact](../docs/user/update-review.md#gitlab-merge-requests).

Run commands from the repository root. Replace `./my-skill` with your local skill
or plugin path. Keep configuration and report files outside the inspected target.

See [CLI usage](../docs/user/usage.md) for scanning, comparison, stdin, report files
and baselines, and the [CLI reference](../docs/reference/cli.md) for every flag.
