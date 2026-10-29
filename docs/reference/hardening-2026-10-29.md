# Hidden content, data flows and tools

English · [Русский](hardening-2026-10-29.ru.md)

Check selection depends on the [profile](../user/inspection-profiles.md).
Use `scout rules list --all` for descriptors.

## Hidden content

Unicode Tags and supported variation-selector payloads are decoded and checked with
carrier coordinates. Raw bytes remain available. Repeated selectors can trigger
`NV-AE7` even when decoding fails; a single emoji selector is insufficient.

`HI001` links hidden HTML/comments to override, secret-transfer or execution instructions.
`RX001` checks sensitive substitutions in Markdown and HTML image/link URLs.
Documentation labels and fences do not suppress evidence.

## Data flows

`SH001` links curl/wget downloads to pipe/string execution or later saved-file execution.
It considers selected redirects, cp/mv, cat/stdin, shell/source and Python/Node forms.
Known unconditional local overwrites remove prior provenance; `bash -n` is not execution.

`XF001` links sensitive reads to network APIs and downloaded bodies to execution APIs
through selected Python, JS/TS and Go imports/functions. It considers parameters,
returns, assignments, globals and selected transforms. Required related evidence
retains file identities and source spans.

Recursion, depth limits, ambiguous/unresolved exports and quota exhaustion leave gaps.
The bounded resolver does not resolve ES arrow/default exports for XF001.

## Network and capability checks

`NET001` compares selected network-call hosts with visible declarations in the nearest
SKILL.md namespace. Matching normalizes case, trailing dots and IPs; unrelated suffixes
do not match. Comments, hidden HTML and frontmatter do not declare hosts.
Unresolved dynamic destinations leave gaps.

`SC004` flags npm lifecycle hooks and Python build/setup entry points, retaining
related evidence for captured local handlers. Separate supply-chain checks cover
mutable sources and registry overrides.

`TC001` flags colliding names in captured JSON tool collections. `TC002` flags
sensitive-access and network capabilities within one nearest-skill scope.
These declarations require interpretation; they do not prove execution or data transfer.

## Bundled signatures

YARA-X includes adapted SkillSpector and Cisco rules. Scout assigns severity from
evidence and retains strong witnesses before weak hits. Truncation leaves incompleteness.
Mentions, individual risky actions and supported execution chains receive different levels.
See [sources and adaptation details](port-manifest.md).
