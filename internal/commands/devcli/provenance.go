package devcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/internal/dev/provenance"
)

type provenanceInvocation struct {
	operation, destination, before, manifest string
	options                                  provenance.Options
	verification                             provenance.Verification
}

func provenanceCommand(ctx context.Context, args []string, out, diag io.Writer) int {
	command, err := parseProvenance(args, diag)
	if err != nil {
		return failure(diag, err)
	}

	value, err := command.execute(ctx)
	if err != nil {
		return failure(diag, err)
	}

	if err := command.publish(ctx, value, out); err != nil {
		return failure(diag, err)
	}

	return 0
}

func parseProvenance(args []string, diag io.Writer) (provenanceInvocation, error) {
	c := provenanceInvocation{
		options: provenance.Options{Version: scout.Version()},
	}
	if len(args) == 0 {
		return c, errors.New("provenance requires compare, generate or verify")
	}

	c.operation = args[0]
	fs := flag.NewFlagSet("provenance "+c.operation, flag.ContinueOnError)
	fs.SetOutput(diag)
	fs.StringVar(&c.options.Root, "root", ".", "trusted project root")
	fs.StringVar(&c.destination, "output", "", "atomic evidence destination")
	fs.StringVar(&c.before, "before", "", "baseline replay")
	fs.StringVar(&c.options.Input, "input", "", "raw captured input")
	fs.StringVar(&c.options.Replay, "replay", "", "current replay JSONL or JSONL.gz")
	fs.StringVar(&c.options.Summary, "summary", "", "replay summary JSON")
	fs.StringVar(&c.options.Releasecheck, "releasecheck", "", "release acceptance JSON")
	fs.StringVar(&c.options.Comparison, "comparison", "", "adjudicated comparison JSON")
	fs.StringVar(&c.manifest, "manifest", "", "provenance manifest")
	fs.StringVar(&c.verification.Version, "expected-version", "", "optional expected measured build identifier for verification")
	fs.BoolVar(&c.verification.CurrentSources, "current-sources", false, "also require the current checkout to match the recorded source inventory")
	mode := fs.String("input-mode", "file", "file or explicitly pinned capture verification")
	fs.StringVar(&c.verification.InputPin.SHA256, "input-sha256", "", "trusted capture digest for pinned verification")
	fs.StringVar(&c.verification.IDsSHA256, "input-ids-sha256", "", "trusted sorted capture IDs digest")

	if err := fs.Parse(args[1:]); err != nil {
		return c, err
	}

	if fs.NArg() != 0 {
		return c, errors.New("provenance has no positional arguments")
	}

	c.verification.InputMode = provenance.InputMode(*mode)
	c.verification.InputPin.Path = c.options.Input

	return c, nil
}

func (c provenanceInvocation) execute(ctx context.Context) (any, error) {
	switch c.operation {
	case "compare":
		return provenance.Compare(ctx, c.options.Root, c.before, c.options.Replay)
	case "generate":
		return provenance.Generate(ctx, c.options)
	case "verify":
		manifest, err := provenance.Read(c.options.Root, c.manifest)
		if err != nil {
			return nil, err
		}

		if c.verification.Version == "" {
			c.verification.Version = manifest.Version
		}

		if err := provenance.Verify(ctx, c.options.Root, manifest, c.verification); err != nil {
			return nil, err
		}

		return struct {
			Passed                bool `json:"passed"`
			CurrentSourcesChecked bool `json:"current_sources_checked"`
		}{Passed: true, CurrentSourcesChecked: c.verification.CurrentSources}, nil
	default:
		return nil, errors.New("unknown provenance operation")
	}
}

func (c provenanceInvocation) publish(ctx context.Context, value any, out io.Writer) error {
	if c.destination == "" {
		return encodeProvenance(out, value)
	}

	inputs := make([]string, 0)

	for _, path := range []string{c.before, c.options.Input, c.options.Replay, c.options.Summary, c.options.Releasecheck, c.options.Comparison, c.manifest} {
		if path != "" {
			inputs = append(inputs, c.projectPath(path))
		}
	}

	return output.Write(ctx, c.projectPath(c.destination), inputs, func(w io.Writer) error { return encodeProvenance(w, value) })
}

func (c provenanceInvocation) projectPath(path string) string {
	if !filepath.IsAbs(path) {
		return filepath.Join(c.options.Root, path)
	}

	return path
}

func encodeProvenance(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")

	return encoder.Encode(value)
}
