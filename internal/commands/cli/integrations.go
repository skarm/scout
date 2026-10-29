package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/internal/distribution/integrations"
)

func integrationCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || len(args) == 1 && args[0] == "list" {
		return integrationList(stdout, stderr)
	}

	if args[0] != "export" {
		return usageError(stderr, "integrations supports list or export")
	}

	return integrationExport(ctx, args[1:], stdout, stderr)
}

func integrationExport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("integrations export", flag.ContinueOnError)
	f.SetOutput(stderr)
	name := f.String("bundle", "", "agent-skill, claude-code, codex, pi, opencode, review-materials")

	dest := f.String("output", "", "NEW ZIP path; never overwrites or installs")
	if e := f.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	if f.NArg() != 0 || *dest == "" {
		return usageError(stderr, "explicit bundle and new output path required; no installation is performed")
	}

	m, e := integrations.Inventory(*name)
	if e != nil {
		return usageError(stderr, "unknown bundle")
	}

	e = output.CreateNew(ctx, *dest, func(w io.Writer) error { return integrations.WriteZIP(w, *name) })
	if e != nil {
		_, _ = fmt.Fprintln(stderr, "integration export failed; existing files are never replaced")
		return 2
	}

	if e = json.NewEncoder(stdout).Encode(m); e != nil {
		return 2
	}

	return 0
}

func integrationList(stdout, stderr io.Writer) int {
	var list []integrations.Manifest

	for _, name := range integrations.Names() {
		m, e := integrations.Inventory(name)
		if e != nil {
			_, _ = fmt.Fprintln(stderr, "integration inventory unavailable")
			return 2
		}

		list = append(list, m)
	}

	if e := json.NewEncoder(stdout).Encode(list); e != nil {
		return 2
	}

	return 0
}
