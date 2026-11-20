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
- **Credential literals:** private-key markers and selected GitHub, GitLab, Slack,
  Stripe, OpenAI and Anthropic token shapes in all captured files, including hidden
  files, documentation and binary byte streams. These checks run offline and do
  not verify whether a credential is live.
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

### Provider token checks

These built-in checks also run in the reduced core build:

- `SE002`: selected GitHub PAT, OAuth, user, refresh and legacy installation tokens.
- `SE003`: GitLab tokens with the default `glpat-` prefix.
- `SE004`: selected Slack bot and user tokens.
- `SE005`: Stripe live/test secret and restricted keys; publishable keys are excluded.
- `SE006`: selected OpenAI project, service-account, admin and legacy key shapes.
- `SE007`: selected Anthropic `api03` and `admin01` key shapes.

Rules check token boundaries and filter recognized placeholders. They inspect raw bytes and supported decoded views. The candidate limit is 65,536 per rule per text representation. Exceeding it leaves a coverage gap. Findings retain coordinates and hashes without copying credential values.

### MCP schema references

`MC004` is a Medium signal for `$ref` or the initial target of `$dynamicRef` outside a tool schema's captured resources. It inspects tool lists, JSON-RPC `result.tools` and imported snapshots. Fragment references and embedded resources in the same schema are local. Example and extension values are outside the check.

The check uses selected [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core) keywords. Invalid or unresolved resource identities, unsupported dialects and URI lengths over 4096 bytes can leave coverage gaps. Other schemas remain in scope. Scout reports the source coordinates and hash without fetching the reference or validating the client at runtime.

## Optional extensions

### Custom and third-party YARA rules

`--yara` adds one file containing one or more YARA-X-compatible rules to the
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
scout scan --yara /etc/scout/organization.yar --fail-on medium ./my-plugin
```

Keep the trusted rules file outside the target. This example produces `YR5` at Medium severity and sets the policy threshold to Medium. For release artifacts and rollback, use [versioned rulepacks](usage.md#versioned-rulepacks).

### Known-vulnerability lookup with OSV

OSV uses exact captured dependency coordinates. Enable it separately with an explicit network grant or a trusted offline cache. [OSV setup and cache format](usage.md#network-services-and-extra-rules)

### LLM review

The `review` profile adds a configured provider and requires explicit source-upload consent. Use `--quality-review` for an additional quality pass. [Provider setup and review modes](semantic-review.md)

New static analyzers ship in scanner builds. [External traversal](../reference/external-sources.md) expands the inputs for existing checks.

## Standard

```sh
scout scan --profile standard ./my-plugin
```

The default profile selects built-ins, adapted patterns, Python, YAML, TOML and YARA-X.
It does not enable downloads, OSV or LLM review. Missing required backends fail preflight;
required checks cannot be disabled within a named profile.

## Custom

```bash
scout scan --profile custom --checks none --format markdown ./my-skill
scout scan --profile custom --checks python,yaml,toml,patterns ./my-skill
```

The first example selects built-ins only; the second selects optional checks without
YARA. CLI custom starts with all optional checks, and `--checks` replaces that list.
In Go, set `Profile = scout.Custom` and supply a non-nil
`Checks` value. See [API configuration](../development/go-api.md#construct-and-close-a-scanner).

## Review

Review adds an operator-selected LLM to standard checks. Configure the endpoint, model, credentials and upload consent. OSV and quality review remain separate options. [Enable semantic review](semantic-review.md#enable-review)

The CLI also accepts `basic` for built-ins-only custom, `extended` for standard and `semantic` for review. Configuration and Go use full names.

## Scope

`complete` means the selected checks finished. Default conservative policy also
requires review for declared language-analysis limitations. Explicit `--scope selected`
accepts those limitations but does not waive parser failures, unfinished work or
exhausted budgets. See [language support](../reference/languages.md).
