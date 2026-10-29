// Command releasepack packages verified native candidates without rebuilding them.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "release packaging:", err)

		os.Exit(1)
	}
}

func run(args []string, diag io.Writer) error {
	flags := flag.NewFlagSet("releasepack", flag.ContinueOnError)
	flags.SetOutput(diag)
	version := flags.String("version", "", "tag or commit SHA for archive names")
	candidates := flags.String("candidates", "", "directory containing the three native-candidate artifacts")
	output := flags.String("output", "", "new directory for release archives and SHA256SUMS")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if flags.NArg() != 0 || *candidates == "" || *output == "" {
		return errors.New("--version, --candidates and --output are required; positional arguments are not supported")
	}

	return packageRelease(*version, *candidates, *output)
}
