package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/skarm/scout/internal/nativecheck"
)

func selftest(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "terminal", "terminal or json")

	timeout := fs.Duration("timeout", 90*time.Second, "cooperative total selftest deadline, <=2m")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	if !validSelftestRequest(ctx, fs, *format, *timeout) {
		return usageError(stderr, "invalid selftest arguments")
	}

	call, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	r := nativecheck.Run(call)
	if err := writeSelftest(stdout, r, *format); err != nil {
		return 2
	}

	if !r.Passed {
		return 2
	}

	return 0
}

func validSelftestRequest(ctx context.Context, fs *flag.FlagSet, format string, timeout time.Duration) bool {
	return fs.NArg() == 0 && (format == "json" || format == "terminal" || format == "text") && timeout > 0 && timeout <= 2*time.Minute && ctx != nil
}

func writeSelftest(stdout io.Writer, r nativecheck.Report, format string) error {
	if format == "json" {
		if e := json.NewEncoder(stdout).Encode(r); e != nil {
			return e
		}
	} else {
		if _, e := fmt.Fprintf(stdout, "Native selftest: passed=%v (%s, %s)\n", r.Passed, r.Version, r.Platform); e != nil {
			return e
		}

		for _, c := range r.Checks {
			if _, e := fmt.Fprintf(stdout, "%-26s %-12s %s\n", c.ID, c.Status, c.Reason); e != nil {
				return e
			}
		}
	}

	return nil
}
