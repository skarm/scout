# Built-in checks, extensions and profiles

Contents

- [Built-in checks](#built-in-checks)
- [Optional extensions](#optional-extensions)
- [Standard](#standard)
- [Custom](#custom)
- [Review](#review)
- [Scope](#scope)

English · [Русский](inspection-profiles.ru.md)

Use `scout profiles` to list profiles and `scout capabilities` to check available
backends. `scout config validate` resolves configuration before reading a target.

## Built-in checks

A full build with the `standard` profile runs the following checks offline,
without installing additional scanners:

- **Agent instructions:** attempts to override system rules, conceal actions from
  the user, disclose privileged prompts, transfer secrets or persist instructions
  in memory for future sessions.
- **Skill, plugin and MCP configuration:** approval and sandbox bypasses, broad
  permissions, lifecycle hook commands, unpinned launcher packages, plaintext HTTP
  and sensitive data in declarations.
- **Code and data flows:** selected command execution, `eval`, secret reads,
  network transfers, unsafe deserialization, SQL construction and TLS verification
  bypasses. Go, Shell, JavaScript/TypeScript, Python and SQL have different coverage.
- **Dependencies and package contents:** redirected package sources, local Go module
  replacements, automatic installation entry points, uninspected local components
  and opaque executable attachments.
- **Hidden content:** HTML instructions, selected Unicode controls and confusables,
  NUL bytes and content that conflicts with filename hints. Supported attachments
  are unpacked or decoded within limits and inspected too.
- **Tools:** identifier collisions, suspicious descriptions and parameters, and
  combinations of sensitive-data access and outbound network capabilities.
- **Adapted SkillSpector rules:** supplemental pattern and structural checks for
  prompt injection, secret access, permissions, tools and supply-chain risks.
- **Embedded YARA-X signatures:** malware, webshells, cryptominers, hacktools,
  agent skill threats and compound rules adapted from Cisco skill-scanner.

JSON parsing is built in; the full build also includes Tree-sitter for Python and
JS/TS, YAML/TOML parsers and YARA-X. The reduced core build lacks the full set of
native backends and requires an explicit `custom` profile. Parsing syntax alone
does not check every possible program behavior.

Inspect rule identifiers, descriptions, methods and limitations:

```sh
scout rules list
scout rules list --all
scout capabilities
```

`rules list` shows the base catalog; `--all` adds adapted, Python and YARA check
descriptors. This is a capabilities catalog, not a list of checks actually run:
the report records the selected plan, applicability and outcomes.
See [language support](../reference/languages.md) for analysis boundaries and
[adaptation sources](../reference/port-manifest.md) for rule provenance.

## Optional extensions

### Custom and third-party YARA rules

`--yara-rules` adds one file containing one or more YARA-X-compatible rules to the
embedded signatures. For example, save a trusted rule in `/etc/scout/organization.yar`:

```yara
rule organization_review_marker {
    strings:
        $marker = "SCOUT_REVIEW_REQUIRED"
    condition:
        $marker
}
```

```sh
scout scan --yara-rules /etc/scout/organization.yar --fail-on medium -- ./my-plugin
```

No rebuild is needed. Keep the rules file outside the inspected package.
`include` directives and the `console` module are forbidden; invalid rules fail
the operation. A signature match remains a finding to assess in context.
In this example it appears as `YR5` with `medium` severity; `--fail-on medium`
sets the corresponding blocking threshold. A finding and the policy decision
are separate parts of the report.

### Known-vulnerability lookup with OSV

```sh
scout scan --vulnerability-check --allow-vulnerability-network -- ./my-plugin
```

Lookup by exact captured dependency coordinates is enabled separately. Select a
compatible service with `--osv-endpoint`, or use a trusted offline cache with
`--osv-cache`. Scout does not embed an up-to-date CVE database. See
[CLI usage](usage.md#network-services-and-extra-rules) for examples and limitations.

### LLM review

The `review` profile adds a configured LLM provider to static checks. Supported
protocols are Chat Completions, Anthropic Messages, `anthropic-proxy` and Bedrock;
`--quality-review` enables additional quality review. Explicit service settings
and `--allow-source-upload` are required. See the [example below](#review) and
[semantic review](semantic-review.md) for details.

These are the supported extension paths without source changes. The CLI does not
load arbitrary third-party analysis engines as plugins. New static analyzers are
added to Scout's source. `--follow-external --allow-download` expands the external
source inputs inspected by the existing checks; see
[external sources](../reference/external-sources.md).

## Standard

```sh
scout scan --profile standard -- ./my-plugin
```

The default profile selects built-ins, adapted patterns, Python, YAML, TOML and YARA-X.
It does not enable downloads, OSV or LLM review. Missing required backends fail preflight;
required checks cannot be disabled within a named profile.

## Custom

```bash
scout scan --profile custom --python-ast=false --yaml-parser=false \
  --toml-parser=false --yara=false --skillspector-patterns=false \
  --format markdown -- ./my-skill
```

This example selects built-ins only. CLI custom selection starts with all checks
and applies explicit flags. In Go, set `Profile = scout.Custom` and supply a non-nil
`Checks` value. See [API configuration](../development/go-api.md#construct-and-close-a-scanner).

## Review

```bash
scout scan --profile review --semantic --allow-source-upload \
  --llm-provider chat-completions \
  --llm-endpoint https://trusted.example/v1/chat/completions \
  --llm-model YOUR_MODEL --llm-api-key-env REVIEW_API_KEY -- ./my-plugin
```

Review adds an operator-configured provider to standard checks. The operator supplies
the endpoint, model, credentials and upload consent. Quality review and OSV remain
separate options. See [semantic review](semantic-review.md).

The CLI also accepts aliases: `basic` for built-ins-only custom, `extended` for
standard and `semantic` for review. Configuration files and Go use the full profile names.

## Scope

`complete` means the selected checks finished. Default conservative policy also
requires review for declared language-analysis limitations. Explicit `--scope selected`
accepts those limitations but does not waive parser failures, unfinished work or
exhausted budgets. See [language support](../reference/languages.md).
