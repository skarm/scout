// Package devcli contains developer maintenance commands, separate from Scout's
// input inspection CLI.
package devcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/skarm/scout/internal/dev/maintenance"
	"github.com/skarm/scout/internal/dev/releasecheck"
)

func Run(ctx context.Context, args []string, out, diag io.Writer) int {
	if len(args) == 0 {
		return failure(diag, errors.New("usage: scout-dev evaluate|releasecheck|<maintenance-command> [flags]"))
	}

	switch args[0] {
	case "provenance":
		return provenanceCommand(ctx, args[1:], out, diag)
	case "replay":
		return replayCommand(ctx, args[1:], out, diag)
	case "evaluate":
		return evaluate(ctx, args[1:], out, diag)
	case "releasecheck":
		return release(ctx, args[1:], out, diag)
	}

	if err := maintenance.Run(ctx, args, out, diag); err != nil {
		return failure(diag, err)
	}

	return 0
}
func failure(w io.Writer, err error) int { _, _ = fmt.Fprintln(w, err); return 2 }
func release(ctx context.Context, args []string, out, diag io.Writer) int {
	fs := flag.NewFlagSet("releasecheck", flag.ContinueOnError)
	fs.SetOutput(diag)
	binary := fs.String("binary", "", "trusted Scout build artifact")

	inspect := fs.Bool("inspect-only", false, "inspect linkage without execution")
	if err := fs.Parse(args); err != nil {
		return failure(diag, err)
	}

	if *binary == "" || fs.NArg() != 0 {
		return failure(diag, errors.New("--binary required"))
	}

	var (
		r   releasecheck.Report
		err error
	)
	if *inspect {
		r, err = releasecheck.Inspect(*binary)
	} else {
		r, err = releasecheck.Verify(ctx, *binary)
	}

	if err != nil {
		r.Issues = append(r.Issues, err.Error())
	}

	if err = json.NewEncoder(out).Encode(r); err != nil {
		return failure(diag, err)
	}

	if !r.Passed {
		return 2
	}

	return 0
}
