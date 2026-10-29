// Package devcli contains developer maintenance commands, separate from Scout's
// input inspection CLI. External upstream oracles are always explicit tools.
package devcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/dev/evaluation"
	"github.com/skarm/scout/internal/dev/maintenance"
	"github.com/skarm/scout/internal/dev/releasecheck"
)

type evaluationInvocation struct {
	path    string
	profile scout.Profile
	timeout time.Duration
}

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
func evaluate(ctx context.Context, args []string, out, diag io.Writer) int {
	command, err := parseEvaluation(args, diag)
	if err != nil {
		return failure(diag, err)
	}

	f, err := os.Open(command.path)
	if err != nil {
		return failure(diag, err)
	}

	data, readErr := io.ReadAll(io.LimitReader(f, evaluation.MaxCorpusBytes+1))

	err = errors.Join(readErr, f.Close())
	if err != nil {
		return failure(diag, err)
	}

	opts := scout.DefaultOptions()

	opts.Profile = command.profile
	if opts.Profile == scout.Custom {
		opts.Checks = &scout.Checks{}
	}

	call, cancel := context.WithTimeout(ctx, command.timeout)
	defer cancel()

	scanner, err := scout.New(call, opts)
	if err != nil {
		return failure(diag, err)
	}
	defer func() { _ = scanner.Close() }() // Detector resources are released after their result is consumed.

	r, err := evaluation.Measure(call, scanner, data)
	if err != nil {
		return failure(diag, err)
	}

	if err = json.NewEncoder(out).Encode(r); err != nil {
		return failure(diag, err)
	}

	return 0
}

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

func parseEvaluation(args []string, diag io.Writer) (evaluationInvocation, error) {
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	fs.SetOutput(diag)
	profile := fs.String("profile", "standard", "standard or custom (builtins only)")

	timeout := fs.Duration("timeout", 2*time.Minute, "whole corpus deadline")
	if err := fs.Parse(args); err != nil {
		return evaluationInvocation{}, err
	}

	if fs.NArg() != 1 || *timeout <= 0 || *timeout > 10*time.Minute {
		return evaluationInvocation{}, errors.New("evaluate requires one corpus and bounded timeout")
	}

	return evaluationInvocation{path: fs.Arg(0), profile: scout.Profile(*profile), timeout: *timeout}, nil
}
