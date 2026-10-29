package devcli

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/internal/dev/replay"
)

type replayInvocation struct {
	input, destination string
	analyzerWorkers    int
	options            replay.Options
}

func replayCommand(ctx context.Context, args []string, out, diag io.Writer) int {
	command, err := parseReplay(args, diag)
	if err != nil {
		return failure(diag, err)
	}

	file, err := os.Open(command.input)
	if err != nil {
		return failure(diag, err)
	}
	defer func() { _ = file.Close() }() // The input file is read-only; read failures are handled separately.

	var source io.Reader = file
	if strings.HasSuffix(command.input, ".gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return failure(diag, err)
		}
		defer func() { _ = gz.Close() }() // The gzip reader owns no writer or underlying file.

		source = gz
	}

	opts := scout.DefaultOptions()
	opts.Concurrency.Workers = command.analyzerWorkers

	scanner, err := scout.New(ctx, opts)
	if err != nil {
		return failure(diag, err)
	}
	defer func() { _ = scanner.Close() }() // Detector resources are released after their result is consumed.

	var summary replay.Summary

	err = output.Write(ctx, command.destination, []string{command.input}, func(w io.Writer) error {
		var err error

		summary, err = replay.Run(ctx, scanner, source, w, command.options)

		return err
	})
	if err != nil {
		return failure(diag, err)
	}

	if err = json.NewEncoder(out).Encode(summary); err != nil {
		return failure(diag, err)
	}

	return 0
}

func parseReplay(args []string, diag io.Writer) (replayInvocation, error) {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(diag)
	input := fs.String("input", "", "saved captured JSONL or JSONL.gz")
	destination := fs.String("output", "", "atomic result JSONL destination")
	workers := fs.Int("workers", 6, "parallel captured inputs, 1..8")
	timeout := fs.Duration("case-timeout", 5*time.Second, "per input timeout, 1s..1m")

	analyzerWorkers := fs.Int("analyzer-workers", 1, "workers in each scan")
	if err := fs.Parse(args); err != nil {
		return replayInvocation{}, err
	}

	if fs.NArg() != 0 || *input == "" || *destination == "" {
		return replayInvocation{}, errors.New("replay requires --input and --output")
	}

	return replayInvocation{
		input:           *input,
		destination:     *destination,
		analyzerWorkers: *analyzerWorkers,
		options: replay.Options{
			Workers: *workers,
			Timeout: *timeout,
		},
	}, nil
}
