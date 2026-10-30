# Go API example

English · [Русский](README.ru.md)

[main.go](main.go) demonstrates scanning a local skill or plugin, evaluating policy
and writing a JSON report with the public `scout`, `policy` and `report` packages.
The example writes the report to stdout and diagnostics to stderr. Downloads,
advisory networking and source uploads are disabled.

Run the commands below from the repository root. Replace `./my-skill` with an
existing local path.

## Full build

Use the same native dependency wrapper as the Scout CLI:

```sh
go run -mod=readonly ./internal/dev/builddeps -- \
  go build -mod=readonly -tags=static_link -o /tmp/scout-go-api ./examples/go-api
/tmp/scout-go-api ./my-skill
```

The example selects `scout.DefaultOptions()` and the `standard` profile.
See the [build guide](../../docs/development/native-build.md) for prerequisites.

## Core build

Build without optional native backends and explicitly select the reduced checks
with `-core`:

```sh
go build -mod=readonly -tags=coreonly -o /tmp/scout-go-api-core ./examples/go-api
/tmp/scout-go-api-core -core ./my-skill
```

`-core` selects `custom` with built-in checks and adapted patterns. Without this
flag, the core binary fails scanner construction because the default profile
requires unavailable backends. The reduced selection also works in the full build.

## Result and exit status

Policy blocks at `high` severity and uses conservative scope. Analysis limitations
can require review even with no findings.

- `0`: complete run, policy allows admission.
- `1`: complete run, policy requires review or blocks admission.
- `2`: invalid arguments, construction or scan error, incomplete run or output failure.

The example handles Ctrl+C through context cancellation and closes the Scanner
before exiting. If scanning returns an error with an available sealed Run, it
still evaluates and writes that evidence before returning `2`. A failure before
a Run exists produces only a diagnostic. Treat the exit status and JSON report
together; an empty findings list alone does not establish an allow.

See [Go API contracts](../../docs/development/go-api.md) for concurrency, ownership,
budgets and report validation.
