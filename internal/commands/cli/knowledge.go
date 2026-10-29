package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/skarm/scout/knowledge"
)

func knowledgeCommand(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("knowledge", flag.ContinueOnError)
	f.SetOutput(stderr)

	mode := f.String("mode", "", "print the exact trusted runtime prompt for a mode; default prints pack/catalog JSON")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	if f.NArg() != 0 {
		return usageError(stderr, "knowledge accepts no paths; pack is compiled in")
	}

	if *mode != "" {
		p, e := knowledge.Prompt(*mode)
		if e != nil {
			return usageError(stderr, "unknown review mode")
		}

		if _, e = fmt.Fprint(stdout, p); e != nil {
			return 2
		}

		return 0
	}

	result := knowledge.Export()
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")

	if e := enc.Encode(result); e != nil {
		return 2
	}

	return 0
}
