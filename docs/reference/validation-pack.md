# Review instructions and guidance

English · [Русский](validation-pack.ru.md)

Assets under `knowledge/` are embedded at build time. Inspected packages cannot
replace instructions or select their own policy. See [review modes](../user/semantic-review.md#review-modes).

## Protocol

Wire protocol is 5; prompt version is `scout-curated-review-instructions-v4`.
`review.PromptForRequest` checks mode, schema and prompt identity before egress.
Target bytes remain user data, separate from trusted system instructions.

Responses use mode-specific compiled reasons and request-scoped citations.
`prompt_sha256` is required. The report-level digest identifies the instruction pack;
each task records its own instruction digest and size.

`MaxInputBytes` and `RequestBytes` count serialized user requests. System instructions,
schema and provider envelopes are separate. Both review passes share the budget.

## Static guidance

`knowledge/data/patterns.json` records supplemental expressions and adaptation sources.
Executable recognizers belong to the analyzers; asset hashes do not identify their
complete implementation.

Guidance includes explanations, remediation, review questions, benign considerations
and source relationships. Context hints aid interpretation without suppressing findings.
Original rules identify local sources; adapted rules retain provenance.

JSON includes complete guidance. Terminal/Markdown show explanation and remediation;
SARIF includes help and source properties. Guidance comes from Scout's compiled pack.
See [source manifest](port-manifest.md) and [runtime checks](knowledge-runtime.md).
