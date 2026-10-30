package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/internal/discovery"
	"github.com/skarm/scout/report"
)

type discoveryArguments struct {
	options         discovery.Options
	format, output  string
	projects        repeated
	scan, noProject bool
	timeout         time.Duration
	scanArgs        []string
	explicitHome    bool
	explicitOutput  bool
}

func discoverCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	a, err := parseDiscoveryArguments(args, stderr)
	if err != nil {
		return requestError(err, stderr)
	}

	call, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	snapshot, err := discovery.Discover(call, a.options)
	if snapshot.Schema == "" {
		return usageError(stderr, "cannot discover selected environment")
	}

	if a.scan {
		if err != nil || !snapshot.Complete {
			_, _ = fmt.Fprintln(stderr, "discovery incomplete; automatic scan refused")
			_ = writeInventory(stderr, snapshot, "text")

			return 2
		}

		return scanDiscovered(ctx, a.scanArgs, snapshot, stdout, stderr)
	}

	return a.publishInventory(ctx, snapshot, err, stdout, stderr)
}

func (a discoveryArguments) publishInventory(ctx context.Context, snapshot discovery.Snapshot, discoveryErr error, stdout, stderr io.Writer) int {
	if discoveryErr != nil {
		snapshot.Complete = false
	}

	publish, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer stop()

	write := func(w io.Writer) error { return writeInventory(w, snapshot, a.format) }

	var err error
	if a.output == "" {
		err = write(stdout)
	} else {
		err = output.Write(publish, a.output, snapshot.ProtectedInputs(), write)
	}

	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cannot publish environment inventory")
		return 2
	}

	if !snapshot.Complete {
		return 2
	}

	return 0
}

func parseDiscoveryArguments(args []string, stderr io.Writer) (discoveryArguments, error) {
	a := discoveryArguments{options: discovery.DefaultOptions(""), timeout: 10 * time.Second, format: "text"}
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&a.options.Agent, "agent", a.options.Agent, "agent to inventory: all, codex or claude-code")
	fs.StringVar(&a.options.Home, "home", "", "selected user home; default current user's home")
	fs.StringVar(&a.options.CodexHome, "codex-home", "", "explicit Codex configuration directory")
	fs.StringVar(&a.options.ClaudeHome, "claude-home", "", "explicit Claude Code configuration directory")
	fs.Var(&a.projects, "project", "selected project directory; repeatable; default current directory")
	fs.BoolVar(&a.noProject, "no-project", false, "omit project discovery")
	fs.BoolVar(&a.options.System, "system", true, "include known system configuration locations")
	fs.IntVar(&a.options.MaxEntries, "max-entries", a.options.MaxEntries, "aggregate discovery entry/probe budget")
	fs.IntVar(&a.options.MaxDepth, "max-depth", a.options.MaxDepth, "maximum skill/plugin traversal depth")
	fs.Int64Var(&a.options.MaxBytes, "max-bytes", a.options.MaxBytes, "aggregate configuration and manifest byte budget")
	fs.DurationVar(&a.timeout, "timeout", a.timeout, "discovery deadline; maximum 2m")
	fs.StringVar(&a.format, "format", a.format, "inventory format: text or json")
	fs.StringVar(&a.output, "output", "", "inventory destination outside selected configuration locations; default stdout")
	fs.BoolVar(&a.scan, "scan", false, "scan discovered roots; pass ordinary scan flags after --")

	if err := fs.Parse(args); err != nil {
		return a, err
	}

	fs.Visit(func(f *flag.Flag) {
		a.explicitHome = a.explicitHome || f.Name == "home"
		a.explicitOutput = a.explicitOutput || f.Name == "format" || f.Name == "output"
	})

	a.scanArgs = fs.Args()
	if a.timeout <= 0 || a.timeout > 2*time.Minute || a.format != "text" && a.format != "json" ||
		a.noProject && len(a.projects) > 0 || !a.scan && len(a.scanArgs) > 0 || a.scan && a.explicitOutput {
		return a, errors.New("invalid discovery arguments; scan options belong after --")
	}

	return a, a.resolve()
}

func (a *discoveryArguments) resolve() error {
	if a.options.Home == "" {
		if a.explicitHome {
			return errors.New("home must not be empty")
		}

		var err error

		a.options.Home, err = os.UserHomeDir()
		if err != nil {
			return errors.New("cannot determine user home; set --home")
		}
	}

	if !a.explicitHome {
		if a.options.CodexHome == "" {
			a.options.CodexHome = os.Getenv("CODEX_HOME")
		}

		if a.options.ClaudeHome == "" {
			a.options.ClaudeHome = os.Getenv("CLAUDE_CONFIG_DIR")
		}
	}

	a.options.Projects = a.projects
	if !a.noProject && len(a.projects) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return errors.New("cannot determine project directory; set --project or --no-project")
		}

		a.options.Projects = []string{cwd}
	}

	return nil
}

func scanDiscovered(ctx context.Context, args []string, snapshot discovery.Snapshot, stdout, stderr io.Writer) int {
	r, err := parseRequest("scan", args, stderr)
	if err != nil {
		return requestError(err, stderr)
	}

	if len(r.targets) != 0 || r.input != "" || r.name != "" {
		return usageError(stderr, "discovered scan accepts scan flags only, without positional targets or stdin")
	}

	r.targets = snapshot.Targets

	targets, err := r.scanTargets(nil)
	if err != nil {
		return usageError(stderr, "discovery must yield 1..32 scan roots; use discover to select smaller groups")
	}

	return executeRequest(ctx, r, targets, report.ScanOperation, stdout, stderr)
}

func writeInventory(w io.Writer, snapshot discovery.Snapshot, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(snapshot)
	}

	if _, err := fmt.Fprintf(w, "Environment: complete=%t, components=%d, scan roots=%d\n", snapshot.Complete, len(snapshot.Components), len(snapshot.Targets)); err != nil {
		return err
	}

	for _, c := range snapshot.Components {
		if _, err := fmt.Fprintf(w, "%s %s %q [%s; %s]\n  path=%q source=%q key=%q\n", c.Agent, c.Kind, c.Name, c.Scope, c.State, c.Path, c.Source, c.Key); err != nil {
			return err
		}
	}

	for _, e := range snapshot.Enablement {
		if _, err := fmt.Fprintf(w, "Setting: %s %s %q=%s [%s] source=%q key=%q\n", e.Agent, e.Kind, e.Selector, e.State, e.Scope, e.Source, e.Key); err != nil {
			return err
		}
	}

	for _, issue := range snapshot.Issues {
		if _, err := fmt.Fprintf(w, "Incomplete: %s %q\n", issue.Code, issue.Path); err != nil {
			return err
		}
	}

	for _, limitation := range snapshot.Limitations {
		if _, err := fmt.Fprintln(w, limitation); err != nil {
			return err
		}
	}

	return nil
}
