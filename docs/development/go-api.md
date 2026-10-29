# Go API contracts

English · [Русский](go-api.ru.md)

Import `github.com/skarm/scout`. Use `go doc` for individual types and fields.

## Construct and close a Scanner

Start with `scout.DefaultOptions()`; zero options are invalid. Standard and Review
require nil `Checks`; Custom requires an explicit value. Unavailable selected
backends fail construction.

```go
options := scout.DefaultOptions()
scanner, err := scout.New(ctx, options)
if err != nil {
    return err
}
defer scanner.Close()
```

Scanner supports concurrent scans and must not be copied. `Close` rejects new work,
waits for active calls and releases native resources. It is idempotent and accepts
nil, but does not cancel active work. Cancel scan contexts when needed.
Custom review providers must support concurrent calls and honor cancellation.

## Inputs and incomplete results

`Path` selects local input. `Remote` validates an address without downloading it;
scanning also requires enabled download options. `Compare` rescans two local paths.
`ScanMany` preserves input order and shares aggregate budgets.

`Reader` and `ReaderContext` borrow single-use streams without closing them.
`ReadContext` must stop promptly on cancellation. Ordinary `Read` calls must return
independently because the adapter cannot interrupt them.

Preflight errors may return no run. With `ErrIncomplete`, preserve an available Run
and its evidence. Use `errors.Is` for wrapped sentinel errors.

## Evaluate and render

A Run stores observations. `policy.New` copies trusted settings and approvals;
`Gate.Evaluate(run, now)` applies them at an explicit time.
`report.NewDocument` combines values without validation. `report.Prepare` validates
the binding and owns an independent snapshot for repeated output.

```go
document := report.NewDocument(run, gate.Evaluate(run, time.Now().UTC()))
prepared, err := report.Prepare(document)
if err != nil {
    return err
}
if err := prepared.Write(output, report.JSON); err != nil {
    return err
}
```

The example assumes an existing run, Gate and writer. Handle scan and writer errors
separately from `policy.PreparedCode(prepared)`. `Snapshot` returns an independent copy; rendering
does not close the writer.

## Coordinates, limits and trust

Byte spans are zero-based and half-open. Text coordinates use one-based Unicode
code points. Binary locations have zero line/column values. Derived offsets refer
to the child's bytes; `ParentRange` is an enclosing representation, not an exact
map through compression or decoding.

Capture and extraction limits apply per target. Aggregate limits and retained
findings apply across the run. Native limits and cancellation are cooperative.
Downloads, advisory networking and source uploads require separate permissions.

MCP borrows its Scanner and Gate. Its `Serve` method owns the input `io.ReadCloser`
and closes it on cancellation; that reader must unblock when closed.
