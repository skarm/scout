# CLI usage

Contents

- [First scan](#first-scan)
- [Configuration](#configuration)
- [Save reports](#save-reports)
- [Baseline](#baseline)
- [Network services and extra rules](#network-services-and-extra-rules)

English · [Русский](usage.ru.md)

See the [complete command and flag reference](../reference/cli.md) for every
parameter, default and limit scope. `scout -h` prints the full list in the terminal;
`scout scan -h` shows scan flags.

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

Start with a [ready-to-use configuration](../../examples/configs/README.md): standard,
strict CI, batch, core, OSV or the LLM review template. Each file has a launch
example and its required permission flags.

Scout reads configuration only from an explicit `--config` path. Example `/ci/scout.json`:

```json
{
  "schema": "scout.config/v1",
  "profile": "standard",
  "concurrency": {"targets": 1, "workers": 4},
  "timeout": "2m",
  "policy": {"fail_at": "high", "scope": "conservative"}
}
```

```sh
scout config validate --config /ci/scout.json
scout scan --config /ci/scout.json --format json ./my-plugin
```

Explicit flags override configuration. Omitted fields use defaults; unknown and
duplicate keys are rejected. Keep configuration, baseline, extra rules and caches
outside inspected inputs. See [profiles](inspection-profiles.md).

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

Text and Markdown start with the decision, execution state, severity counts and
explained policy reasons. Findings come before inspection metadata. Coverage gaps
include affected paths, explanations and unfinished required tasks; analysis notes
are listed separately. Captured files and extracted objects have separate counts.
Markdown uses ordinary headings for inspection details and general limitations,
and backtick code spans for values, without embedded HTML formatting.
Comparison reports show the candidate first and count its findings separately
from the previous version.
JSON and SARIF retain the full machine-readable evidence and stable identifiers.

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

Choose a suitable future RFC3339 expiry. `create` writes pending entries; `approve`
approves every entry unless repeated `--fingerprint SHA256` selectors narrow it.
Preview the exact changes without writing a file:

```sh
scout baseline approve --from /ci-results/pending-baseline.json \
  --fingerprint "$finding_fingerprint" --reason 'Reviewed this occurrence' \
  --expires '2099-01-01T00:00:00Z' --dry-run
scout baseline renew --from /ci-results/reviewed-baseline.json \
  --output /ci-results/renewed-baseline.json \
  --fingerprint "$finding_fingerprint" --expires '2099-06-01T00:00:00Z'
```

`renew` extends already approved entries and preserves their reasons by default;
it cannot approve pending entries or shorten their expiry. Identity changes require new review.
Glob exceptions require `--allow-baseline-globs`. Findings stay in reports;
inspection gaps and semantic proposals cannot be suppressed.

## Network services and extra rules

Remote scans require `--allow-download`. GitHub repository roots also require
`--revision` with a full commit SHA. See [external sources](../reference/external-sources.md).

```sh
scout scan --vuln --allow-vulnerability-network \
  --format json ./my-plugin
scout scan --vuln --osv-cache /ci/osv-cache.json \
  --osv-cache-max-age 168h --format json ./my-plugin
```

OSV checks exact captured package coordinates. Offline caches are operator-supplied;
missing or stale records leave gaps. An advisory does not establish reachability.

### Known malicious dependencies

An operator-supplied cache with `"version": 2` additionally selects `MAL001`.
An exact coordinate explicitly classified as `malicious-package` produces a Critical
finding with evidence from the captured manifest or lockfile. Version 1 and
unclassified advisories continue to use `OSV001` (High). An ID beginning with
`MAL-` does not select `MAL001`.

Use the same `--vuln --osv-cache FILE` command above. Store the trusted cache outside
the inspected target. This fictitious example illustrates the schema; replace it
with verified intelligence and the actual query time before use:

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

A producer must verify the upstream classification and affected versions, then
materialize exact ecosystem/name/version answers. For example,
[OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) publishes
malicious-package reports in [OSV format](https://ossf.github.io/osv-schema/).
Scout does not download that dataset or import its version ranges. Package names,
age and publisher reputation alone do not establish malware.

For every malicious record, `source.name`, `source.url`, `source.revision` and an
RFC3339 `modified` time are required. The modification time cannot exceed
`queried_at`. Source names and revisions are bounded ASCII tokens; URLs require
HTTPS and cannot contain credentials, a query or a fragment. Provenance is the
operator's assertion; Scout does not authenticate it or fetch these URLs.
JSON and SARIF retain the metadata, query time and supplied cache SHA-256; human
reports show the source and revision. Export through `osv.Export` preserves version
2, negative answers and the original query time. Classified-cache query times are
bound to the sealed run digest. Sealing and export reject inconsistent classified
coverage or malicious matches without an associated cached coordinate. Sealing also
checks that queries cover and match the captured dependency inventory. In `compare`,
cached answers establish completed coverage only when every matching file check
succeeded; an incomplete check cannot be masked by a successful one.

An empty `vulnerabilities` array explicitly asserts a checked negative for that
exact coordinate and both advisory kinds. Missing records, unresolved versions,
future or stale caches remain gaps; they cannot yield a complete clean scan.
The cache is bounded to 256 KiB, 4096 coordinates and 4096 advisory entries per
coordinate. Conflicting metadata for one advisory ID in a coordinate is rejected.
This is a bounded query cache, not a bundled or complete malware database.

If network access is also granted, fresh version-2 cache answers take precedence.
OSV querybatch responses can retain ordinary vulnerability matches for missing
coordinates, but leave a `classification_not_cached` gap for malware coverage.
Those incomplete coordinates are excluded from cache export. A match identifies
a captured declaration; it does not prove installation or execution.

### Versioned rulepacks

A `scout.rulepack/v1` artifact carries additional YARA source, a package ID, a
release label, ABI `scout.yara-source/v1` and a source SHA-256. Built-in checks
remain selected by the profile. This format carries data rules; adding native
Go analyzers requires a scanner release. Artifacts are explicitly selected local
operator files outside the inspected roots.

```sh
scout rules pack create --id team/agent --version 1.2.3 \
  --yara /ci/agent.yar --output /ci/agent-1.2.3.rulepack.json
scout rules pack inspect /ci/agent-1.2.3.rulepack.json
scout scan --rulepack /ci/agent-1.2.3.rulepack.json \
  --rulepack-sha256 <trusted-64-digit-sha256> --format json ./my-plugin
```

Use a hash obtained through your trusted release process. `inspect --sha256 HASH`
can verify the pin before a scan. The pin covers the entire artifact, including
ID, version, ABI, source checksum and JSON whitespace. The embedded source checksum
alone detects corruption; an editor who can replace the artifact can also replace
that checksum. Neither checksum authenticates a publisher.

Equivalent configuration:

```json
{
  "schema": "scout.config/v1",
  "signatures": {
    "rulepack_file": "/ci/agent-1.2.3.rulepack.json",
    "rulepack_sha256": "<trusted-64-digit-sha256>"
  }
}
```

Replace the placeholder with the actual lowercase digest. Standard and review
profiles already select YARA. Custom profiles must include `--checks yara`.
`--yara-rules` and `--rulepack` cannot be combined. Packages never grant network
access or change the selected profile. The scanner does not discover packages
in targets or download updates.

To update, publish a new versioned artifact and explicitly change both its path
and pin. To roll back, select the previous artifact and its trusted pin. A running
Scanner owns its loaded source; changing the file or caller buffers does not
update that instance. There is no global installation state.

JSON/SARIF and human reports retain package ID, version, ABI, artifact hash and
source hash under signature metadata. The selected package also contributes to
`RulepackDigest`; changing the version changes that fingerprint even when source
is identical. The combined signature-source hash remains separately visible.
Package source is not copied into scan reports.

Creation and inspection work without the native backend and do not compile YARA.
Scanning compiles the package with the selected backend before capturing input;
unsupported syntax, duplicate rule names, includes and console usage fail the
operation. Existing YARA-X budgets and timeout limitations apply. Both encoded
artifact and raw source are bounded to 256 KiB; metadata and JSON escaping consume
artifact space. The format does not load compiled YARA binaries or executable plugins.

`--yara-rules` adds trusted operator rules. Includes and console access are prohibited;
invalid rules fail the operation. LLM review requires separate
[source-upload consent](semantic-review.md).
