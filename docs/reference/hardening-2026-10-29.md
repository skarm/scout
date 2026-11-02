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

Selected provider-token-shaped string literals are also sensitive sources for
`XF001` and `DNS001` in JS/TS, Python and Go source files and Markdown fences.
They share the `SE002`–`SE007` grammars, token boundaries, placeholder exclusions
and payload-entropy filter. Values retain their literal's original carrier span,
including supported string escapes, through aliases, local calls and selected
transforms. A known unconditional public overwrite clears the overwritten binding;
independent aliases retain their own provenance. Transformation methods preserve
provenance without claiming a computed destination value. Classification is charged
by decoded literal size and performed once per source node under the shared quota.
Only explicit returns and JS/TS arrow expression bodies supply function results.
Declarations, assertions, annotations, discarded expressions and Python docstrings
do not become return values. Unconditional returns in supported nested blocks stop
that function path; observations already collected remain available.
Conditional returns remain unresolved: the function result is unknown and the
analysis retains an explicit gap. Joined bindings retain a known string only when
all observed alternatives agree; differing strings do not preserve a stale hostname.
An overwrite that discards provenance inside flattened conditional alternatives
also leaves an explicit gap instead of claiming a complete negative result.
Conditional API aliases with differing symbolic names remain unresolved rather
than retaining a stale API candidate.
Extending a call trace creates an independent slice, so later calls or merges of
cached values cannot rewrite the evidence of an earlier value.
Separately constructed token fragments and decoding an unrecognized encoded token
into a credential remain outside this source model. Values are never validated
against providers or included in finding messages.

`DNS001` (High) links sensitive environment values, credential-file reads or selected
provider-token literals to a DNS
query name, within one file or through the same captured local call chains as `XF001`.
Selected string concatenation, templates and encodings retain provenance. The bundle
projection covers JS/TS, Python and Go source files and Markdown fences, alongside shell.
Each fence has independent bindings and functions; fences do not join source-file Go
packages. Explicit local imports may resolve captured source-file modules in the same
namespace. Evidence retains the original Markdown byte coordinates and hashes. It covers
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

Selected instances are recognized from Node `new dns.Resolver()` / promises constructors,
Go `new(net.Resolver)`, value/pointer literals and zero-value declarations, and dnspython
`dns.resolver.Resolver` / `dns.asyncresolver.Resolver`. Simple aliases and local factory
returns retain their identity. Query methods select only the hostname components;
configuration and record-type arguments do not become query data. Simple Go parallel
binding assignments evaluate all right-hand values before updating bindings. Supported instance
queries also work inside isolated Markdown fences.

Method replacement through an alias invalidates that resolver identity. Dynamic members,
uncertain receiver values and unbound Node methods leave gaps. Go/Python bound method
values retain their receivers. Selected configuration setters/fields are recognized;
custom Go dialers remain unresolved. Complex chained/destructured Python writes,
JS/TS destructuring assignments and iterator patterns, and JS/TS/Python deletion stop
that evaluation before later calls can use stale bindings, retaining prior observations.
JS/TS declaration patterns clear their bindings to unknown values.
Python member writes preserve right-hand-side-first evaluation for plain assignments;
annotation-only statements do not overwrite bindings or methods.
Simple function-local annotations still mask outer bindings throughout their scope.
Python global/nonlocal declarations and Go resolver rebinding also stop unsupported
state changes across copied frames. Changes to resolver classes/prototypes are unresolved.
Imported module runtime state and Go's default resolver are reset for each fence under
the shared operation quota; an unsupported write in one fence does not poison another.
No resolver library or utility is loaded or called by the scanner.

Shell batch/reverse/multiple-query forms and unknown options remain outside this DNS
model. Dynamic query names retain an incomplete result even
when the sensitive-data flow is found. No resolver is called during scanning.
The finding does not prove execution, valid DNS encoding, transmission or malicious
intent: OS resolver APIs may use caches or local host files.
Argument positions follow the [Node DNS API](https://nodejs.org/api/dns.html),
[Python socket API](https://docs.python.org/3/library/socket.html),
[Go net API](https://pkg.go.dev/net) and [BIND command manuals](https://bind9.readthedocs.io/en/v9.20.0/manpages.html).
The selected dnspython methods follow its [resolver](https://dnspython.readthedocs.io/en/stable/resolver-class.html)
and [async resolver](https://dnspython.readthedocs.io/en/stable/async-resolver-class.html) documentation.

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
Selected credential literals also contribute sensitive-material observations.
These declarations require interpretation; they do not prove execution or data transfer.

## Bundled signatures

YARA-X includes adapted SkillSpector and Cisco rules. Scout assigns severity from
evidence and retains strong witnesses before weak hits. Truncation leaves incompleteness.
Mentions, individual risky actions and supported execution chains receive different levels.
See [sources and adaptation details](port-manifest.md).
