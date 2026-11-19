# Hidden content, data flows and tools

[Русский](hardening-2026-10-29.ru.md)

Use `scout rules list --all` for rule descriptors and [profiles](../user/inspection-profiles.md) for check selection.

## Hidden content

Scout decodes supported Unicode Tag and variation-selector payloads and maps findings to the original carrier bytes. Repeated selectors can trigger `NV-AE7` even when decoding fails. A single emoji selector is insufficient.

`HI001` checks hidden HTML and comments for instruction overrides, secret transfer or execution. `RX001` checks sensitive substitutions in Markdown and HTML link or image URLs. Labels and code fences provide context without suppressing evidence.

## Data flows

- `SH001` connects selected curl and wget downloads to execution through a pipe, command string or saved file. The check tracks supported copies, moves and redirects. A known local overwrite clears the saved-file provenance.
- `XF001` connects sensitive reads to network APIs and downloaded bodies to execution APIs. It follows selected captured imports, functions and string transformations in Python, JavaScript, TypeScript and Go.
- `DNS001` connects sensitive values to DNS query names in those languages and selected shell commands. It covers known hostname arguments of standard resolvers, selected resolver instances and bounded single queries via `dig`, `host` and `nslookup`. Cross-file DNS flows retain `XF001` evidence.

Supported provider-token literals follow the `SE002`–`SE007` rules and retain source spans across aliases and selected transformations. Scout keeps the literal out of finding messages and does not contact providers to validate it.

Each Markdown fence has independent bindings. Explicit local imports can resolve captured modules in the same namespace. Findings retain file identities, hashes and original spans. Recursion, unresolved imports or call targets, conditional results and exhausted budgets can leave coverage gaps. Dynamic DNS names can leave a gap even when Scout identifies the source flow. The scanner does not execute the inspected code or issue DNS queries on its behalf.

## Network and capability checks

- `NET001` compares selected HTTP hosts and literal DNS names with visible declarations in the nearest `SKILL.md` scope. It normalizes case, trailing dots and IP addresses. Comments, hidden HTML and frontmatter do not declare hosts.
- `SC004` flags npm lifecycle hooks and Python build or setup entry points. Reports cite captured local handlers when resolved.
- `TC001` flags colliding identifiers in captured JSON tool collections. `TC002` flags combinations of sensitive access and network capabilities within one skill scope. A declaration alone provides no evidence of execution or transfer.

## Bundled signatures

Scout derives YARA-X severity from retained evidence. It prioritizes strong witnesses, and truncated signature analysis leaves a coverage gap. [Adaptation sources and licenses](port-manifest.md)
