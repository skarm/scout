package cli

import (
	"flag"
	"fmt"
	"strings"
)

var shortFlagNames = map[string]string{
	"agent":          "-a",
	"baseline":       "-b",
	"checks":         "--chk",
	"config":         "-c",
	"dry-run":        "-d",
	"environment":    "--env",
	"fail-on":        "--fo",
	"format":         "-f",
	"help":           "-h",
	"kind":           "-k",
	"output":         "-o",
	"profile":        "-p",
	"report":         "-r",
	"review":         "--llm",
	"snapshot":       "-s",
	"stdin":          "-i",
	"target-workers": "--tw",
	"timeout":        "-t",
	"version":        "-v",
	"workers":        "-w",
	"yara":           "-y",
}

var longFlagNames = func() map[string]string {
	names := make(map[string]string, len(shortFlagNames))
	for name, short := range shortFlagNames {
		names[strings.TrimLeft(short, "-")] = name
	}

	return names
}()

func canonicalFlagName(name string) string {
	if long, ok := longFlagNames[name]; ok {
		return long
	}

	return name
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	// Share each flag.Value so the parser handles both spellings in argument
	// order, including repeated values, booleans, and duplicate checks.
	for short, long := range longFlagNames {
		if f := fs.Lookup(long); f != nil {
			fs.Var(f.Value, short, f.Usage)
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
