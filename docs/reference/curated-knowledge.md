# Knowledge topics

English · [Русский](curated-knowledge.ru.md)

The embedded pack supplies review criteria, rule guidance, remediation and source
references. Topics inform LLM review and enrich existing rule explanations;
they do not add static detectors.

## Inspect the pack

```sh
scout knowledge
scout knowledge --mode discovery
scout knowledge --mode assessment
scout integrations export --bundle review-materials --output /tmp/scout-review-materials.zip
```

CLI and export expose the compiled topics, sources, guidance and supplemental patterns.
Topic areas cover Go, JS/TS, Python, Shell and SQL, plus prompt injection, tool
composition, permissions, persistence, secrets and dependency provenance.

## Use in review

Discovery, assessment and proposal assessment receive relevant review criteria.
Intent/tool consistency use purpose and authority topics; quality has separate criteria.
Full scenarios and source snapshots are not included in system instructions.

Discovery can select compiled `knowledge:<topic ID>` reasons. Follow-up review
receives original evidence and the selected guide. Reports retain the topic and
Scout-authored guidance; the result remains a semantic hypothesis.

## Verify sources

`knowledge/data/review_sources.json` records pinned revisions and inspected-file
hashes. The sources inform authored criteria without importing their detector engines.
Adapted materials have separate [provenance](port-manifest.md).

```sh
go run -tags=coreonly ./cmd/scout-dev verify-knowledge-sources --cache /absolute/source-cache
go run -tags=coreonly ./cmd/scout-dev verify-knowledge-sources --cache /absolute/source-cache --download
```

`--download` permits fetching missing pinned files. See
[runtime verification](knowledge-runtime.md) for instruction delivery tests.
