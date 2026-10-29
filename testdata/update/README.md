# Update-review fixtures

These are scanner inputs, not plugins to install or execute. The previous tree
contains an instruction-only skill and a dependency declaration. The candidate
adds a startup-hook/Go-handler chain and changes the source of a Go dependency.

Run from the repository root:

```bash
go run -mod=readonly ./cmd/scout compare --harness claude-code --format markdown ./testdata/update/previous ./testdata/update/candidate
```

Only the scanner is run. It does not run the hook, the handler, the Go toolchain
from the inspected package, or the declared dependency. The expected update
verdict is block/partial, exit 2; the instruction body has not changed.
