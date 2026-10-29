# Architecture and trust boundaries

English · [Русский](architecture.ru.md)

The Go API, CLI and MCP share one pipeline:

```text
operator options → bounded capture → immutable inventory
→ extraction/source maps → component graph → checks
→ optional semantic review → coverage/validation → sealed Run
→ policy evaluation → prepared report
```

## Capture and source mapping

Target bytes, filenames, manifests and instructions are untrusted. Only operator
configuration selects policy, providers, credentials and network permissions.
The pipeline never executes target hooks, installers or servers.

Capture retains immutable bytes and inventory hashes, including unread entries
as gaps. Root-relative no-follow reads do not provide a transactional filesystem
snapshot. Extraction retains original containers and creates bounded virtual children.
Source maps preserve exact byte correspondence where possible and enclosing
provenance for nonlinear transforms.

## Analysis

The trusted registry selects parsers and analyzers. Language packages implement
`check.Analyzer`; shared immutable facts avoid repeated observations while keeping
independent rule budgets and outcomes. See [language scope](../reference/languages.md).

The component graph records declarations, references and inferred host activation.
A fixed task plan and outcome ledger expose omitted, failed and unfinished work.
Evidence already collected survives later failures.

Optional semantic review uses bounded source excerpts and request-scoped citations.
Model hypotheses and assessments remain separate from static findings.

## Public boundaries

Scanner owns native resources. `Close` stops admission and waits for active calls.
Runs contain observations; a separate trusted `policy.Gate` applies policy.
`report.Prepare` validates run/evaluation binding and creates an independent snapshot
for all output formats. See [API contracts](go-api.md).

A baseline applies operator approvals without deleting observations or closing gaps.
Downloads, advisory networking and source uploads use separate permissions.
Native engines execute in-process with cooperative limits and cancellation.

## Package boundaries

`report` is independent of the runtime. Language packages do not import each other
or the analyzer registry. Product and developer command adapters remain separate.
`internal/architecture` tests these boundaries. See [repository layout](layout.md).
