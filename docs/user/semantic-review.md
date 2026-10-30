# Semantic review

English · [Русский](semantic-review.ru.md)

Semantic review sends selected source excerpts to a configured LLM provider.
It adds hypotheses and assessments while preserving static findings.

## Enable review

For file-based setup, copy and customize
[review.template.json](../../examples/configs/review.template.json) using the
[preset instructions](../../examples/configs/README.md#llm-review-template).

```bash
scout scan --profile review --semantic --allow-source-upload \
  --llm-provider chat-completions \
  --llm-endpoint https://trusted.example/v1/chat/completions \
  --llm-model YOUR_MODEL --llm-api-key-env REVIEW_API_KEY \
  --timeout 3m --format json ./my-plugin
```

Supply a trusted endpoint, model and credential variable. The example endpoint is
a placeholder. Upload requires explicit consent; source may contain secrets and
complete redaction is unavailable. HTTP requires numeric loopback and
`--llm-allow-loopback`. A local service may forward requests elsewhere.

Supported transports are Chat Completions, Anthropic Messages, `anthropic-proxy`
for Vertex-shaped requests and selected Bedrock Messages requests. Bedrock requires
explicit region and AWS credential variables. Credentials are not discovered from
the host or inspected package. Redirects, retries and provider fallback are disabled.

## Review modes

- `discovery`: independent search in source excerpts.
- `intent`: compare declared purpose with observed capabilities.
- `tool_consistency`: compare tool declarations with code in the same namespace.
- `assessment`: assess each retained static finding.
- `proposal_assessment`: recheck hypotheses against original evidence.
- `quality`: optional quality/policy criteria, enabled by `--quality-review`.

Both review passes share the request and input budgets. Defaults are 64 requests,
2 MiB aggregate user-request bytes and 30 seconds per request; relevant `--llm-*`
flags adjust them. `--timeout` bounds the entire scan. Omitted or invalid tasks remain gaps.

## Results

Responses must cite scanner-issued excerpts from the current request. Local validation
rejects unknown reasons, foreign citations and malformed responses. Reports retain
validated classifications, hashes and source coordinates, without publishing arbitrary
model prose or excerpts. Model agreement does not authorize installation.

See [review instructions](../reference/validation-pack.md) for protocol details and
[knowledge verification](../reference/knowledge-runtime.md) for integration tests.
