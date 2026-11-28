package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/internal/discovery"
	"github.com/skarm/scout/report"
)

const (
	flagExcludePath = "exclude-path"
	flagHome        = "home"
	flagIncludePath = "include-path"
	flagMaxDepth    = "max-depth"
	flagNoProject   = "no-project"
	flagProject     = "project"
	flagScan        = "scan"
	flagSystem      = "system"
)

const (
	defaultDiscoveryTimeout = 10 * time.Second
	maxDiscoveryTimeout     = 2 * time.Minute
)

type discoveryArguments struct {
	options         discovery.Options
	format, output  string
	snapshot        string
	projects        repeated
	kinds           repeated
	includePaths    repeated
	excludePaths    repeated
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

	var rootBindings []discovery.RootBinding
	if a.snapshot != "" {
		rootBindings, err = a.pinRoots(nil)
		if err != nil {
			return usageError(stderr, err.Error())
		}
	}

	call, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	snapshot, err := discovery.Discover(call, a.options)
	if snapshot.Schema == "" {
		return usageError(stderr, "cannot discover selected environment")
	}

	if err == nil {
		var selectionErr error

		snapshot, selectionErr = discovery.Select(call, snapshot, discovery.Filters{Kinds: a.kinds, IncludePaths: a.includePaths, ExcludePaths: a.excludePaths})
		if selectionErr != nil {
			return usageError(stderr, selectionErr.Error())
		}
	}

	if a.scan || a.snapshot != "" {
		if err != nil || !snapshot.Complete {
			_, _ = fmt.Fprintln(stderr, "discovery incomplete; automatic scan refused")
			_ = writeInventory(stderr, snapshot, "text")

			return 2
		}

		if a.snapshot != "" {
			return snapshotDiscovered(ctx, a, snapshot, rootBindings, stdout, stderr)
		}

		return scanDiscovered(ctx, a, snapshot, stdout, stderr)
	}

	return a.publishInventory(ctx, snapshot, err, stdout, stderr)
}

func (a discoveryArguments) publishInventory(ctx context.Context, snapshot discovery.Snapshot, discoveryErr error, stdout, stderr io.Writer) int {
	if discoveryErr != nil {
		snapshot.Complete = false
	}

	publish, stop := context.WithTimeout(context.WithoutCancel(ctx), reportPublicationTimeout)
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
	a := discoveryArguments{options: discovery.DefaultOptions(""), timeout: defaultDiscoveryTimeout, format: "text"}
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&a.options.Agent, flagAgent, a.options.Agent, "agent to inventory: "+strings.Join(discovery.AgentSelectors(), ", "))
	fs.StringVar(&a.options.Home, flagHome, "", "selected user home; default current user's home")

	for _, override := range a.options.HomeOverrides() {
		fs.StringVar(override.Path, override.Flag, "", "explicit "+override.Label+" configuration directory")
	}

	fs.Var(&a.projects, flagProject, "selected project directory; repeatable; default current directory")
	fs.BoolVar(&a.noProject, flagNoProject, false, "omit project discovery")
	fs.BoolVar(&a.options.System, flagSystem, true, "include known system configuration locations")
	fs.IntVar(&a.options.MaxEntries, flagMaxEntries, a.options.MaxEntries, "aggregate discovery entry/probe budget")
	fs.IntVar(&a.options.MaxDepth, flagMaxDepth, a.options.MaxDepth, "maximum skill/plugin traversal depth")
	fs.Int64Var(&a.options.MaxBytes, flagMaxBytes, a.options.MaxBytes, "aggregate configuration and manifest byte budget")
	fs.DurationVar(&a.timeout, flagTimeout, a.timeout, "discovery deadline; maximum 2m")
	fs.StringVar(&a.format, flagFormat, a.format, "inventory format: text or json")
	fs.StringVar(&a.output, flagOutput, "", "inventory destination outside selected configuration locations; default stdout")
	fs.StringVar(&a.snapshot, flagSnapshot, "", "save discovered environment and inspection; scanner flags follow --")
	fs.BoolVar(&a.scan, flagScan, false, "scan discovered roots; pass ordinary scan flags after --")
	fs.Var(&a.kinds, flagKind, "select skill, plugin, mcp-server, lsp-server, command, hook, agent, rule, tool, workflow or channel scan roots; repeatable")
	fs.Var(&a.includePaths, flagIncludePath, "narrow discovered scan roots to this path; repeatable; cannot expand discovery")
	fs.Var(&a.excludePaths, flagExcludePath, "omit scan roots overlapping this path; repeatable; use --kind for component-level roots")

	if err := parseFlags(fs, args); err != nil {
		return a, err
	}

	fs.Visit(func(f *flag.Flag) {
		switch canonicalFlagName(f.Name) {
		case flagHome:
			a.explicitHome = true
		case flagFormat, flagOutput:
			a.explicitOutput = true
		}
	})

	a.scanArgs = fs.Args()
	if a.timeout <= 0 || a.timeout > maxDiscoveryTimeout || a.format != "text" && a.format != "json" ||
		a.noProject && len(a.projects) > 0 || !a.scan && a.snapshot == "" && len(a.scanArgs) > 0 || (a.scan || a.snapshot != "") && a.explicitOutput || a.scan && a.snapshot != "" {
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
		for _, override := range a.options.HomeOverrides() {
			if override.Env != "" && *override.Path == "" {
				*override.Path = os.Getenv(override.Env)
			}
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

func scanDiscovered(ctx context.Context, a discoveryArguments, snapshot discovery.Snapshot, stdout, stderr io.Writer) int {
	r, err := parseRequest("scan", a.scanArgs, stderr)
	if err != nil {
		return requestError(err, stderr)
	}

	if len(r.targets) != 0 || r.stdinName != "" {
		return usageError(stderr, "discovered scan accepts scan flags only, without positional targets or stdin")
	}

	if len(r.skillExcludes) != 0 {
		return usageError(stderr, "--exclude requires an explicitly selected skill directory with scout scan")
	}

	if r.environment && (a.options.Agent == discovery.AllAgents || len(a.options.Projects) > 1) {
		return usageError(stderr, "environment analysis requires one --agent and at most one --project; split independent environments")
	}

	r.targets = snapshot.Targets
	r.publicationInputs = snapshot.ProtectedInputs()
	r.useDiscoveryHarness(selectedDiscoveryHarness(a.options.Agent, snapshot))

	targets, err := r.scanTargets(nil)
	if err != nil {
		return usageError(stderr, "discovery must yield 1..32 selected scan roots; narrow with --kind, --include-path or --exclude-path")
	}

	return executeRequest(ctx, r, targets, report.ScanOperation, stdout, stderr)
}

func (r *request) useDiscoveryHarness(agent string) {
	if r.harnessExplicit || r.settings.Scanner.Harness.Host != report.HostAuto {
		return
	}

	if agent != discovery.AllAgents && discovery.ValidAgent(agent) {
		r.settings.Scanner.Harness.Host = agent
	}
}

func selectedDiscoveryHarness(agent string, snapshot discovery.Snapshot) string {
	// The cache location supplies Codex context even when a portable package
	// uses native defaults without declaring a Codex overlay in its manifest.
	if agent == report.HostCodex && snapshot.HasSelectedPlugin(agent) {
		return agent
	}

	return discoveryHarness(agent, snapshot.Targets)
}

func discoveryHarness(agent string, targets []string) string {
	// Preserve ordinary skill and manifestless package scans for the two
	// original discovery layouts. Standalone configs need the selected host
	// because capture retains only their basenames.
	switch agent {
	case report.HostCodex:
		for _, target := range targets {
			if filepath.Base(target) == artifact.CodexConfig {
				return agent
			}
		}
	case report.HostClaudeCode:
		for _, target := range targets {
			switch filepath.Base(target) {
			case artifact.ClaudeSettings, artifact.ClaudeLocalSettings, artifact.ClaudeManagedSettings,
				artifact.ClaudeGlobalConfig, artifact.ClaudeManagedMCP, artifact.MCPConfig:
				return agent
			}
		}
	default:
		return agent
	}

	return report.HostAuto
}

func writeInventory(w io.Writer, snapshot discovery.Snapshot, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(snapshot)
	}

	if _, err := fmt.Fprintf(w, "Environment: complete=%t, components=%d, scan roots=%d\n", snapshot.Complete, len(snapshot.Components), len(snapshot.Targets)); err != nil {
		return err
	}

	if snapshot.Selection != nil {
		if _, err := fmt.Fprintf(w, "Explicit selection: %d original scan roots; inventory and issues remain unfiltered.\n", snapshot.Selection.OriginalTargets); err != nil {
			return err
		}

		for _, target := range snapshot.Targets {
			if _, err := fmt.Fprintf(w, "Selected scan root: %q\n", target); err != nil {
				return err
			}
		}
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
