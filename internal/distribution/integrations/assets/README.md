# Scout reviewer bundle

English · [Русский](README.ru.md)

Install a trusted Scout binary separately, then choose a bundle layout below.
The bundle contains the adapted NVIDIA Skill Inspector workflow and does not run
an installer or the inspected package.

## Choose a layout

- `agent-skill`: copy `skill-inspector` into a host-supported skill directory.
- `claude-code`: load the trusted skill-only plugin containing `.claude-plugin/plugin.json`.
- `codex`: load the trusted skill-only plugin containing `.codex-plugin/plugin.json`.
- `pi`: run `pi install /absolute/trusted/bundle`, then reload Pi.
- `opencode`: copy `.opencode` into the intended trusted configuration/project directory.
- `review-materials`: inspect embedded prompts and guidance offline.

Preserve `references/`, LICENSE and NOTICE. Install integrations outside the
untrusted package. Use the host's existing SDK; do not run npm install in a scanned target.

## Operator configuration

```sh
export SCOUT_BIN=/absolute/trusted/scout
export SCOUT_TARGETS='{"candidate":{"path":"/absolute/review/candidate","harness":"claude-code"}}'
```

The model passes `{"target":"candidate","semantic":false}` to `scout_scan`.
OpenCode also offers `/scout candidate`. Arguments cannot choose arbitrary paths,
executables or flags. Keep target roots stable during review.

The default profile is standard. Missing required backends fail preflight.
`SCOUT_REDUCED_CORE=1` explicitly selects reduced custom checks.
The tool returns a bounded summary and omitted-record counts; rerun the CLI with
an approved `--output` for a full report. The wrapper does not create a baseline,
query OSV, add custom YARA rules or install the target.

## Semantic review

```sh
export SCOUT_REVIEWER='{"provider":"chat-completions","endpoint":"https://review.example/v1/chat/completions","model":"YOUR_MODEL","keyEnv":"REVIEW_API_KEY"}'
```

The endpoint is a placeholder. Supported wrapper providers are chat-completions,
anthropic and anthropic-proxy. Numeric loopback HTTP requires `allowLoopback:true`.
`semantic:true` also requires a separate upload grant. Source may contain secrets;
complete redaction is unavailable. Credentials are read only after grants and are
never taken from the target or returned to the model.

## Permissions and verification

Pi requires interactive confirmation; OpenCode uses `context.ask`. Denial starts
no subprocess. The scanner runs through argv without a shell, in a temporary directory
with bounded time and output. Cancellation kills it. Valid reports with exit 1/2
remain available. This does not sandbox the host's other tools.

`.scout-bundle.json` records packaged file sizes and hashes. Keep LICENSE/NOTICE
when redistributing. SDK-fixture tests check adapter contracts; test compatibility
with the real host separately.
