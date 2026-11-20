# CLI usage

[Русский](usage.ru.md)

Scan a local skill, save the report and apply reviewed exceptions. For options and limits, see the [CLI reference](../reference/cli.md) or run `scout scan -h`.

## First scan

Use `scout` from `PATH`, or replace it with the path to your binary. The examples
work from any directory; target paths are relative to your current directory.
For installation, see the [build guide](../development/native-build.md#installation-and-output-paths).

```sh
scout doctor
scout scan ./my-skill
scout scan --format markdown --output /tmp/scout-report.md ./my-skill
scout compare ./previous ./candidate
```

Replace the example paths with your local skill or plugin directories. The default
scan needs no configuration or API keys and makes no network requests. Scout
analyzes the package without executing its code. Keep report files outside the
inspected directories.

Read `Findings` for detected issues, `Completeness` for whether the checks finished,
and `Decision` for the policy result: `allow`, `review` or `block`. `review` can
occur with zero findings when the analysis has limitations requiring manual review.

Place flags before positional targets. `--` ends flag parsing and is optional for
ordinary paths. Keep it before a path from a variable or one beginning with `-`:

```sh
scout scan --format json -- "$target"
```

`scan` accepts up to 32 targets; `batch` is an alias. `--target-workers` controls
target concurrency, `--workers` analyzer concurrency, and `--timeout` the entire operation.

## Configuration

Choose a [configuration example](../../examples/configs/README.md). Pass it explicitly with `--config`. From the repository root, you can validate and use the standard preset.

```sh
scout config validate --config examples/configs/standard.json
scout scan --config examples/configs/standard.json ./my-plugin
```

Flags override configuration. Omitted fields use defaults. Scout rejects unknown and duplicate keys. Keep configuration, baselines, rules and caches outside inspected inputs.

## Save reports

```sh
scout scan --format json \
  --report json=/ci-results/scout.json \
  --report sarif=/ci-results/scout.sarif \
  --fail-on high --timeout 2m ./skills ./plugins
scout scan --format markdown --output /ci-results/scout.md ./my-plugin
```

Formats are `text`, `json`, `sarif` and `markdown`. Without `--output`, the primary
report goes to stdout. Repeat `--report FORMAT=PATH` for additional representations.
Diagnostics go to stderr. Create output directories before running the command.

Text and Markdown show the decision, findings, coverage gaps and inspection details. Comparisons list the candidate first and count its findings separately. JSON and SARIF retain stable identifiers and machine-readable evidence.

For UTF-8 files with a byte order mark (BOM), SARIF excludes it from text columns and uses byte offsets for regions that include it. Scout retains the original evidence coordinates and records `utf8_bom: true` in file metadata.

Scout prepares each report in a private temporary file, then replaces its destination
by rename. Preparation failure preserves the previous file. Symlinks, directories
and destinations inside inspected inputs are rejected. A report also cannot occupy
an absent input's name, including case and Unicode aliases on its filesystem.
Several files are published independently.

Exit codes:

- `0`: complete run, policy allows admission, all reports written.
- `1`: complete run, policy requires review or blocks admission.
- `2`: incomplete, failed or cancelled run; invalid request; or report write failure.

Preserve reports and the original exit code in CI. Default conservative scope also
requires review for declared language limitations. See [scope selection](inspection-profiles.md#scope).

## Baseline

Create a baseline from a single-target JSON report, review its entries, then approve it:

```sh
scout baseline create --from /ci-results/scout.json \
  --output /ci-results/pending-baseline.json \
  --reason 'Manual triage required' --expires '2099-01-01T00:00:00Z'
scout baseline approve --from /ci-results/pending-baseline.json \
  --output /ci-results/reviewed-baseline.json \
  --reason 'Reviewed by operator' --expires '2099-01-01T00:00:00Z'
scout scan --baseline /ci-results/reviewed-baseline.json ./my-plugin
```

Set a future RFC3339 expiry. `create` writes pending entries. `approve` accepts all entries unless you select specific entries with repeatable `--fingerprint SHA256`. Use `--dry-run` to preview approval or renewal. `renew` extends approved entries and preserves their reasons by default. Identity changes require new review. Glob exceptions require `--allow-baseline-globs`. Findings stay in reports, and baselines leave coverage gaps and semantic proposals visible. [Baseline flags](../reference/cli.md#baseline)

## Network services and extra rules

Remote scans require `--allow-download`. GitHub repository roots also require
`--revision` with a full commit SHA. See [external sources](../reference/external-sources.md).

```sh
scout scan --osv --allow-osv-network \
  --format json ./my-plugin
scout scan --osv --osv-cache /ci/osv-cache.json \
  --osv-cache-max-age 168h --format json ./my-plugin
```

OSV checks exact captured package coordinates. Offline caches are operator-supplied;
missing or stale records leave gaps. An advisory does not establish reachability.

### Known malicious dependencies

A trusted cache with `"version": 2` enables `MAL001`. An exact dependency coordinate classified as `malicious-package` yields a Critical finding, with evidence from the captured manifest or lockfile. Ordinary advisories use `OSV001` (High). The `MAL-` ID prefix alone does not classify an advisory.

Use `--osv --osv-cache FILE` and keep the cache outside the target. Replace the sample data and timestamps with verified intelligence and actual query times.

```json
{
  "version": 2,
  "queried_at": "2026-11-03T12:00:00Z",
  "records": [{
    "ecosystem": "npm",
    "name": "sample",
    "version": "1.2.3",
    "vulnerabilities": [{
      "id": "MAL-fixture",
      "kind": "malicious-package",
      "modified": "2026-11-03T11:00:00Z",
      "source": {
        "name": "operator-intel",
        "url": "https://example.invalid/intel/MAL-fixture",
        "revision": "snapshot-1"
      }
    }]
  }]
}
```

The producer verifies classifications and materializes exact ecosystem, name and version records. Each malicious advisory needs `source.name`, `source.url`, `source.revision` and an RFC3339 `modified` time no later than `queried_at`. Name and revision are bounded ASCII tokens. Use an HTTPS URL without credentials, a query or a fragment. Scout records the operator's provenance assertion without fetching or authenticating it.

An empty `vulnerabilities` array records a checked negative for both advisory kinds. Missing or stale answers and unresolved versions leave coverage gaps. With network permission, fresh version-2 answers take precedence. Ordinary network answers for missing records can still report vulnerabilities, but leave a `classification_not_cached` gap and are not exported as completed classifications.

The cache allows 256 KiB, 4,096 coordinates and 4,096 advisories per coordinate. Reports retain advisory provenance and the cache SHA-256. `osv.Export` preserves version, checked negatives and query time. [OSV flags](../reference/cli.md#vulnerabilities)

### Versioned rulepacks

Use a trusted local `scout.rulepack/v1` artifact to add YARA source. The artifact records its ID, version, ABI and source digest. Keep it outside the inspected roots.

```sh
scout rules pack create --id team/agent --version 1.2.3 \
  --yara /ci/agent.yar --output /ci/agent-1.2.3.rulepack.json
scout rules pack inspect --sha256 "$trusted_sha256" /ci/agent-1.2.3.rulepack.json
scout scan --rulepack /ci/agent-1.2.3.rulepack.json \
  --rulepack-sha256 "$trusted_sha256" --format json ./my-plugin
```

Set `trusted_sha256` to the lowercase artifact digest from your release process. The pin checks all artifact bytes. Publisher trust comes from the release process. To upgrade or roll back, change the path and pin together. An open Scanner keeps its loaded source.

Configuration uses `signatures.rulepack_file` and `signatures.rulepack_sha256`. Standard and review select YARA. In custom, add `--checks yara`. Use either `--rulepack` or `--yara`.

Creation and inspection work without YARA-X. Scanning compiles the source before capture. Unsupported syntax, duplicate rule names, includes and console usage fail the operation. Both artifact and source have a 256 KiB limit. Reports retain package metadata and hashes. [Rulepack flags](../reference/cli.md#rulepack-artifacts)
