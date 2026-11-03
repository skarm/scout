package cli

import (
	"bytes"
	"context"
	"flag"
	"io"

	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/rulepack"
)

func rulepackCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		return requestError(err, stderr)
	}

	if len(args) == 0 {
		return usageError(stderr, "rules pack requires create or inspect")
	}

	switch args[0] {
	case "create":
		return createRulepack(ctx, args[1:], stdout, stderr)
	case "inspect":
		return inspectRulepack(ctx, args[1:], stdout, stderr)
	default:
		return usageError(stderr, "unknown rules pack operation")
	}
}

func createRulepack(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules pack create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "", "required package identifier")
	version := fs.String("version", "", "required package release label")
	yara := fs.String("yara", "", "trusted UTF-8 YARA source file")

	path := fs.String("output", "", "artifact destination; default stdout")
	if err := fs.Parse(args); err != nil {
		return requestError(err, stderr)
	}

	if fs.NArg() != 0 || *id == "" || *version == "" || *yara == "" {
		return usageError(stderr, "rules pack create requires --id, --version and --yara")
	}

	rules, err := readTrusted(*yara, nil, rulepack.MaxRulesBytes)
	if err != nil {
		return usageError(stderr, "cannot read trusted rulepack source")
	}

	data, err := rulepack.Create(*id, *version, rules)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	write := func(w io.Writer) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
			return err
		}

		return ctx.Err()
	}
	if *path == "" {
		err = write(stdout)
	} else {
		err = output.Write(ctx, *path, []string{*yara}, write)
	}

	if err != nil {
		return usageError(stderr, "cannot publish rulepack artifact")
	}

	return 0
}

func inspectRulepack(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules pack inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)

	pin := fs.String("sha256", "", "expected lowercase SHA-256 of the entire artifact")
	if err := fs.Parse(args); err != nil {
		return requestError(err, stderr)
	}

	if fs.NArg() != 1 {
		return usageError(stderr, "rules pack inspect requires one artifact path")
	}

	data, err := readTrusted(fs.Arg(0), nil, rulepack.MaxBytes)
	if err != nil {
		return usageError(stderr, "cannot read rulepack artifact")
	}

	selection, err := rulepack.Parse(data, *pin)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if ctx.Err() != nil {
		return 2
	}

	if err := writeOperatorJSON(ctx, "", nil, selection.Identity, stdout); err != nil || ctx.Err() != nil {
		return 2
	}

	return 0
}
