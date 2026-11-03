package cli

import (
	"context"
	"flag"
	"io"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/mcpsnapshot"
)

func mcpSnapshotCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source-id", "", "operator-chosen stable server/source identity")

	output := fs.String("output", "", "snapshot output file; default stdout")
	if err := fs.Parse(args); err != nil {
		return requestError(err, stderr)
	}

	if fs.NArg() != 1 {
		return usageError(stderr, "mcp snapshot requires one local capture JSON file")
	}

	capture, err := readTrusted(fs.Arg(0), nil, jsonconfig.MaxBytes)
	if err != nil {
		return usageError(stderr, "cannot read MCP capture")
	}

	snapshot, err := mcpsnapshot.Create(ctx, *source, capture)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if err := writeOperatorJSON(ctx, *output, fs.Args(), snapshot, stdout); err != nil {
		return usageError(stderr, "cannot publish MCP snapshot")
	}

	return 0
}
