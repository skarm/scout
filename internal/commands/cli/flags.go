package cli

import (
	"flag"
	"fmt"
	"strings"
)

type flagShortcut struct{ name, alias string }

func flagShortcuts() []flagShortcut {
	return []flagShortcut{
		{"agent", "-a"},
		{"baseline", "-b"},
		{"checks", "--chk"},
		{"config", "-c"},
		{"dry-run", "-d"},
		{"environment", "--env"},
		{"fail-on", "--fo"},
		{"format", "-f"},
		{"help", "-h"},
		{"kind", "-k"},
		{"output", "-o"},
		{"profile", "-p"},
		{"report", "-r"},
		{"review", "--llm"},
		{"snapshot", "-s"},
		{"stdin", "-i"},
		{"target-workers", "--tw"},
		{"timeout", "-t"},
		{"version", "-v"},
		{"workers", "-w"},
		{"yara", "-y"},
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
