// Command go-api demonstrates scanning, policy evaluation and report publication
// using only Scout's public Go packages.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

func main() {
	flags := flag.NewFlagSet("go-api", flag.ContinueOnError)

	core := flags.Bool("core", false, "select built-in checks and patterns without optional native backends")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		os.Exit(2)
	}

	if flags.NArg() != 1 {
		_, _ = fmt.Fprintln(os.Stderr, "usage: go-api [-core] <local-target>")

		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code, err := scan(ctx, flags.Arg(0), *core, os.Stdout)

	stop()

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
	}

	os.Exit(code)
}

func scan(ctx context.Context, path string, core bool, output io.Writer) (int, error) {
	options := scout.DefaultOptions()
	if core {
		options.Profile = scout.Custom
		options.Checks = &scout.Checks{Patterns: true}
	}

	scanner, err := scout.New(ctx, options)
	if err != nil {
		return 2, err
	}
	defer func() { _ = scanner.Close() }()

	gate, err := policy.New(policy.Options{FailAt: report.High, Scope: policy.ConservativeScope})
	if err != nil {
		return 2, err
	}

	run, scanErr := scanner.Scan(ctx, scout.Path(path))
	if run.Digest == "" {
		return 2, scanErr
	}

	// An incomplete scan can still provide a sealed run. Publish that evidence
	// before returning its failure status to the caller.
	document := report.NewDocument(run, gate.Evaluate(run, time.Now().UTC()))

	prepared, err := report.Prepare(document)
	if err != nil {
		return 2, err
	}

	if err := prepared.Write(output, report.JSON); err != nil {
		return 2, err
	}

	if scanErr != nil {
		return 2, scanErr
	}

	return policy.PreparedCode(prepared), nil
}
