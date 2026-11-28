package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/discovery"
)

type checkpointRootSummary struct {
	ID    string `json:"id"`
	Path  string `json:"path"`
	Files int    `json:"files"`
	Bytes int    `json:"bytes"`
}

const checkpointSummarySchema = "scout.environment-checkpoint-summary/v1"

type checkpointSummary struct {
	Schema    string                  `json:"schema"`
	Digest    string                  `json:"content_sha256"`
	State     string                  `json:"inspection_state"`
	Decision  string                  `json:"historical_decision"`
	Roots     []checkpointRootSummary `json:"roots"`
	Discovery []string                `json:"discovery_arguments,omitempty"`
	Bindings  []discovery.RootBinding `json:"discovery_root_bindings,omitempty"`
}

func inspectEnvironmentSnapshot(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("snapshot inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String(flagSnapshot, "", "required operator-selected checkpoint")

	format := fs.String(flagFormat, "text", "output format: text or json; no source bytes")
	if err := parseFlags(fs, args); err != nil {
		return requestError(err, stderr)
	}

	if *path == "" || fs.NArg() != 0 || *format != "text" && *format != "json" {
		return usageError(stderr, "snapshot inspect requires --snapshot FILE and --format text|json")
	}

	saved, err := readEnvironmentCheckpoint(*path, nil)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	summary := checkpointSummary{Schema: checkpointSummarySchema, Digest: saved.Snapshot.Digest, State: string(saved.Inspection.Run.State), Decision: string(saved.Inspection.Evaluation.Decision), Roots: []checkpointRootSummary{}}
	for _, root := range saved.Snapshot.Roots {
		item := checkpointRootSummary{ID: root.ID, Path: root.Source}
		for _, entry := range root.Entries {
			if !entry.Directory {
				item.Files++
				item.Bytes += len(entry.Data)
			}
		}

		summary.Roots = append(summary.Roots, item)
	}

	if saved.Discovery != nil {
		summary.Discovery = saved.Discovery.Arguments
		summary.Bindings = saved.Discovery.RootBindings
	}

	if ctx.Err() != nil {
		return 2
	}

	if *format == "json" {
		if json.NewEncoder(stdout).Encode(summary) != nil {
			return 2
		}

		return 0
	}

	if _, err = fmt.Fprintf(stdout, "Saved environment: %s\nHistorical inspection: %s; decision: %s (not approval for current content).\n", summary.Digest, summary.State, summary.Decision); err != nil {
		return 2
	}

	for _, root := range summary.Roots {
		if _, err = fmt.Fprintf(stdout, "Root %q: %q; %d files, %d bytes.\n", root.ID, root.Path, root.Files, root.Bytes); err != nil {
			return 2
		}
	}

	if len(summary.Discovery) > 0 {
		quoted := make([]string, len(summary.Discovery))
		for i, arg := range summary.Discovery {
			quoted[i] = strconv.QuoteToASCII(arg)
		}

		_, err = fmt.Fprintf(stdout, "Saved discovery arguments: %s\nCompare without --root to repeat this discovery context.\n", strings.Join(quoted, " "))
	} else {
		_, err = fmt.Fprintln(stdout, "Compare without --root to recheck these saved paths; missing roots are reported as removed.")
	}

	if err != nil || writeDiscoveryBindings(stdout, summary.Bindings) != nil {
		return 2
	}

	return 0
}

func writeDiscoveryBindings(w io.Writer, bindings []discovery.RootBinding) error {
	for _, binding := range bindings {
		if _, err := fmt.Fprintf(w, "Saved discovery path %q resolves to %q.\n", binding.Path, binding.Resolved); err != nil {
			return err
		}

		if binding.ProjectBoundary != "" {
			if _, err := fmt.Fprintf(w, "Project search stops at %q.\n", binding.ProjectBoundary); err != nil {
				return err
			}
		}
	}

	return nil
}
