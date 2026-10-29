# Knowledge runtime verification

English · [Русский](knowledge-runtime.ru.md)

These checks verify instruction delivery and source-citation binding using a local
scripted provider. They do not measure a real model's classification quality.

## What is checked

- Static findings receive the expected compiled guidance.
- The scan/provider/validator/assessment/report pipeline preserves topic and evidence.
- Unknown topics, invalid modes and forged citations are rejected.
- Report formats retain guidance without copying source secrets into semantic output.

The [fixture corpus](../../testdata/knowledge-runtime/README.md) contains risky and
benign examples, including SQL topics. Their code is never executed.

## Run

```sh
go test -mod=readonly -tags=coreonly -run 'TestKnowledge' -v ./tests/scan
go test -mod=readonly -tags=static_link -run 'TestKnowledge' -v ./tests/scan
go test -mod=readonly -tags=coreonly ./internal/analysis/semantic ./knowledge ./review
```

HTTP fixtures require loopback access. To preserve binary-generated JSON reports:

```sh
go run -tags=coreonly ./cmd/scout-dev check-knowledge-runtime --binary "$(command -v scout)" --output /tmp/new-native-runtime-run
go run -tags=coreonly ./cmd/scout-dev check-knowledge-runtime --binary "$(command -v scout-core)" --output /tmp/new-core-runtime-run
```

Use a new output directory. The tool sends inputs only to the local fixture server.
Run full core/native suites and race checks separately without filters.
