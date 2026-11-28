package cli

import (
	"flag"
	"fmt"
	"strings"
)

const (
	flagAgent       = "agent"
	flagConfig      = "config"
	flagDryRun      = "dry-run"
	flagEnvironment = "environment"
	flagFormat      = "format"
	flagHelp        = "help"
	flagKind        = "kind"
	flagMaxBytes    = "max-bytes"
	flagOSVCache    = "osv-cache"
	flagOutput      = "output"
	flagReport      = "report"
	flagReview      = "review"
	flagSnapshot    = "snapshot"
	flagStdin       = "stdin"
	flagVersion     = "version"
)

type flagShortcut struct{ name, alias string }

func flagShortcuts() []flagShortcut {
	return []flagShortcut{
		{flagAgent, "-a"},
		{flagBaseline, "-b"},
		{flagChecks, "--chk"},
		{flagConfig, "-c"},
		{flagDryRun, "-d"},
		{flagEnvironment, "--env"},
		{flagFailOn, "--fo"},
		{flagFormat, "-f"},
		{flagHelp, "-h"},
		{flagKind, "-k"},
		{flagOutput, "-o"},
		{flagProfile, "-p"},
		{flagReport, "-r"},
		{flagReview, "--llm"},
		{flagSnapshot, "-s"},
		{flagStdin, "-i"},
		{flagTargetWorkers, "--tw"},
		{flagTimeout, "-t"},
		{flagVersion, "-v"},
		{flagWorkers, "-w"},
		{flagYARA, "-y"},
	}
}

func shortFlagName(name string) string {
	for _, shortcut := range flagShortcuts() {
		if shortcut.name == name {
			return shortcut.alias
		}
	}

	return ""
}

func canonicalFlagName(name string) string {
	for _, shortcut := range flagShortcuts() {
		if strings.TrimLeft(shortcut.alias, "-") == name {
			return shortcut.name
		}
	}

	return name
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	// Share each flag.Value so the parser handles both spellings in argument
	// order, including repeated values, booleans, and duplicate checks.
	for _, shortcut := range flagShortcuts() {
		if f := fs.Lookup(shortcut.name); f != nil {
			fs.Var(f.Value, strings.TrimLeft(shortcut.alias, "-"), f.Usage)
		}
	}

	fs.Usage = func() {
		var text strings.Builder

		_, _ = fmt.Fprintf(&text, "Usage of %s:\n", fs.Name())

		fs.VisitAll(func(f *flag.Flag) {
			if canonicalFlagName(f.Name) == f.Name {
				appendFlagHelp(&text, f)
			}
		})

		_, _ = fmt.Fprint(fs.Output(), text.String())
	}

	return fs.Parse(args)
}
