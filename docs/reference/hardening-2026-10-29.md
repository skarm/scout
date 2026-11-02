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

`DNS001` (High) links sensitive environment values or credential-file reads to a DNS
query name, within one file or through the same captured local call chains as `XF001`.
Selected string concatenation, templates and encodings retain provenance. The bundle
projection uses JS/TS, Python and Go source-file units; shell also covers captured code
fences. It covers
Node `dns`/`dns/promises` lookup and resolve APIs, Python `socket.getaddrinfo` (including
`host=`), `gethostbyname`/`gethostbyname_ex`, Go `net.Lookup*` and `net.DefaultResolver`
name lookups, and bounded single-query `dig`, `host` and `nslookup` commands.
Go SRV service/protocol/name components all contribute to the queried name.
Shell supports selected stdin-only `base64` forms; file operands are unresolved.
Ordinary resolution and sensitive data in unrelated API arguments do not establish
this flow. Cross-file DNS flows also retain `XF001` evidence.

Python helper binding respects positional-only, keyword-only and required parameters;
invalid or expanded calls leave a gap. Omitted default values remain unknown;
dynamic default expressions also leave an explicit bundle-analysis gap.
`Buffer.from` propagates its data argument, not its encoding/offset controls.
Shell retains supported `printf`/single-argument `echo` option and server prefixes
through command substitution so those values are not invented query names.

Resolver instances, shell batch/reverse/multiple-query forms and unknown options
remain outside this DNS model. Dynamic query names retain an incomplete result even
when the sensitive-data flow is found. No resolver is called during scanning.
The finding does not prove execution, valid DNS encoding, transmission or malicious
intent: OS resolver APIs may use caches or local host files.
Argument positions follow the [Node DNS API](https://nodejs.org/api/dns.html),
[Python socket API](https://docs.python.org/3/library/socket.html),
[Go net API](https://pkg.go.dev/net) and [BIND command manuals](https://bind9.readthedocs.io/en/v9.20.0/manpages.html).

Recursion, depth limits, ambiguous/unresolved exports and quota exhaustion leave gaps.
The bounded resolver supports module-level JS/TS arrow functions with simple identifier
parameters, block or expression bodies, named/default exports, local export aliases and
namespace imports. Default expressions retain their value at the export statement;
export clauses and named default declarations follow the local binding. Nested closures,
parameter defaults/destructuring/rest patterns, re-exports and class/generator values
remain unresolved. Conditional/compound function values and cyclic module initialization
also leave gaps, as do spread call arguments, function members such as call/bind and
dynamic namespace members. Parentheses, await and selected TS assertions preserve the
projected value without type checking. This is static flow analysis, not module execution.

JS/TS declarations mask built-in API candidates before initialization and when their
values are unresolved. Block bindings remain local; function-local declarations shadow module bindings,
and an uninitialized `var` does not erase a parameter. Sequence expressions retain only
their last value. Constructor results, block-captured closures, block function declarations,
destructured bindings, method bodies, callable container members and conditional/nested-block
returns remain unresolved. A called function's non-local write stops that bundle evaluation
before another frame can read stale global state; earlier observations remain available.
Standalone hypothetical function inspection retains this gap without stopping independent
module inspection. Binding or projection/expression depth exhaustion stops further evaluation; replacing an existing binding
does not require an extra slot.
Simple catch parameters, switch blocks and lexical `for` initializers have their own scope. Iterator
values in `for-in`/`for-of` remain unresolved and do not reuse a shadowed outer value.
Uncertain callable/module values cannot retain a previous namespace for member resolution.
Unknown receivers do not become global API names through property access; selected
sensitive-file reader methods retain their original source provenance.
Unresolved/empty module specifiers retain unknown import bindings instead of inventing
global API names from their local aliases.
Failed module initialization remains sticky: partial globals and exports cannot later
be reused as completed state when independent function inspection continues.
After a terminal child error, its parent call cannot emit a flow from partially evaluated
arguments. Observations completed before the stop remain available.

## Network and capability checks

`NET001` compares selected HTTP hosts and literal DNS query names with visible declarations in the nearest
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
