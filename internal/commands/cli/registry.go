package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/internal/distribution/registry"
)

func registryCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "registry requires fetch or compare")
	}

	switch args[0] {
	case "fetch":
		return fetchRegistry(ctx, args[1:], stdout, stderr)
	case "compare":
		return compareRegistry(ctx, args[1:], stdout, stderr)
	}

	return usageError(stderr, "unknown registry operation")
}

func fetchRegistry(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o := registry.DefaultOptions()
	fs := flag.NewFlagSet("registry fetch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.Endpoint, "endpoint", o.Endpoint, "explicit registry servers endpoint")
	fs.StringVar(&o.Name, "name", "", "exact server name; empty captures all records")
	fs.BoolVar(&o.LatestOnly, "latest", false, "select registry-asserted latest records per name")
	fs.BoolVar(&o.Download.Enabled, "allow-download", false, "explicitly authorize registry HTTP requests")
	fs.BoolVar(&o.Download.AllowLoopback, "allow-loopback", false, "allow numeric loopback fixture endpoint")
	fs.IntVar(&o.MaxPages, "max-pages", o.MaxPages, "maximum registry pages")
	fs.Int64Var(&o.MaxBytes, "max-bytes", o.MaxBytes, "maximum aggregate response bytes")

	path := fs.String("output", "", "snapshot output file; default stdout")
	if err := fs.Parse(args); err != nil {
		return requestError(err, stderr)
	}

	if fs.NArg() != 0 {
		return usageError(stderr, "registry fetch takes no positional arguments")
	}

	call, cancel := context.WithTimeout(ctx, o.Download.Timeout)
	defer cancel()

	snapshot, err := registry.Fetch(call, o)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if err := writeOperatorJSON(ctx, *path, nil, snapshot, stdout); err != nil {
		return usageError(stderr, "cannot publish registry snapshot")
	}

	return 0
}

func compareRegistry(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("registry compare", flag.ContinueOnError)
	fs.SetOutput(stderr)

	path := fs.String("output", "", "comparison output file; default stdout")
	if err := fs.Parse(args); err != nil {
		return requestError(err, stderr)
	}

	if fs.NArg() != 2 {
		return usageError(stderr, "registry compare requires previous and current snapshots")
	}

	a, err := readRegistrySnapshot(fs.Arg(0))
	if err != nil {
		return usageError(stderr, "cannot read previous registry snapshot")
	}

	b, err := readRegistrySnapshot(fs.Arg(1))
	if err != nil {
		return usageError(stderr, "cannot read current registry snapshot")
	}

	diff, err := registry.Compare(ctx, a, b)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if err := writeOperatorJSON(ctx, *path, fs.Args(), diff, stdout); err != nil {
		return usageError(stderr, "cannot publish registry comparison")
	}

	return 0
}

func readRegistrySnapshot(path string) (registry.Snapshot, error) {
	var out registry.Snapshot

	data, err := readTrusted(path, nil, 32<<20)
	if err != nil {
		return out, err
	}

	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()

	if err := d.Decode(&out); err != nil {
		return out, err
	}

	if err := d.Decode(new(any)); err != io.EOF {
		return out, errors.New("trailing registry snapshot data")
	}

	return out, nil
}

func writeOperatorJSON(ctx context.Context, path string, inputs []string, value any, stdout io.Writer) error {
	write := func(w io.Writer) error { return json.NewEncoder(w).Encode(value) }
	if path == "" {
		return write(stdout)
	}

	return output.Write(ctx, path, inputs, write)
}
