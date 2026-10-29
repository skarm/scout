// Command treeparsecheck builds and runs the native Tree-sitter lifecycle harness.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
)

type options struct {
	sanitizer, output, adapter, compiler string
	rounds                               int
}

type buildPlan struct {
	Commands  [][]string `json:"commands"`
	Sanitizer string     `json:"sanitizer"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)

	stop()

	if err != nil && !errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprintln(os.Stderr, "treeparsecheck:", err)

		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	opts, err := parseOptions(args, stderr)
	if err != nil {
		return err
	}

	gomod, err := query(ctx, "go", "env", "GOMOD")
	if err != nil {
		return err
	}

	if gomod == "" || gomod == os.DevNull {
		return errors.New("run this command inside the Scout module")
	}

	root := filepath.Dir(gomod)

	plan, err := makePlan(ctx, root, opts)
	if err != nil {
		return err
	}

	for _, command := range plan.Commands {
		if err := execute(ctx, root, command, stdout, stderr); err != nil {
			return err
		}
	}

	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}

	//nolint:gosec // G703: output is an explicit developer-selected artifact path.
	if err := os.WriteFile(opts.output+"-build.json", append(data, '\n'), 0o600); err != nil {
		return err
	}

	return execute(ctx, root, []string{opts.output, strconv.Itoa(opts.rounds)}, stdout, stderr)
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var opts options

	compiler := os.Getenv("CC")
	if compiler == "" {
		compiler = "clang"
	}

	flags := flag.NewFlagSet("treeparsecheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.sanitizer, "sanitizer", "", "address (with UBSan), thread, or none")
	flags.StringVar(&opts.output, "output", "", "output executable path")
	flags.StringVar(&opts.adapter, "adapter", "", "alternate native.c for detector positive controls")
	flags.StringVar(&opts.compiler, "cc", compiler, "C compiler executable (defaults to CC or clang)")
	flags.IntVar(&opts.rounds, "rounds", 500, "lifecycle rounds per grammar (1..100000)")

	if err := flags.Parse(args); err != nil {
		return opts, err
	}

	if flags.NArg() != 0 {
		return opts, errors.New("unexpected positional arguments")
	}

	if opts.sanitizer != "address" && opts.sanitizer != "thread" && opts.sanitizer != "none" {
		return opts, errors.New("--sanitizer must be address, thread, or none")
	}

	if opts.output == "" || opts.compiler == "" || opts.rounds < 1 || opts.rounds > 100000 {
		return opts, errors.New("--output and --cc are required; --rounds must be 1..100000")
	}

	output, err := filepath.Abs(opts.output)
	opts.output = output

	return opts, err
}

func makePlan(ctx context.Context, root string, opts options) (buildPlan, error) {
	plan := buildPlan{Sanitizer: opts.sanitizer}
	module := func(name string) (string, error) {
		return query(ctx, "go", "list", "-mod=readonly", "-m", "-f", "{{.Dir}}", "github.com/tree-sitter/"+name)
	}

	engine, err := module("go-tree-sitter")
	if err != nil {
		return plan, err
	}

	adapter := filepath.Join(root, "internal", "syntax", "treeparse")
	sources := []string{filepath.Join(engine, "src", "lib.c"), filepath.Join(adapter, "testdata", "lifecycle.c")}

	for _, grammar := range []struct{ module, path string }{
		{"tree-sitter-python", "src"},
		{"tree-sitter-javascript", "src"},
		{"tree-sitter-typescript", "typescript/src"},
		{"tree-sitter-typescript", "tsx/src"},
	} {
		dir, err := module(grammar.module)
		if err != nil {
			return plan, err
		}

		dir = filepath.Join(dir, filepath.FromSlash(grammar.path))
		sources = append(sources, filepath.Join(dir, "parser.c"), filepath.Join(dir, "scanner.c"))
	}

	flags := []string{"-std=c11", "-D_POSIX_C_SOURCE=200112L", "-D_DEFAULT_SOURCE", "-g", "-O1", "-fno-omit-frame-pointer", "-pthread"}

	if opts.adapter != "" {
		path, err := filepath.Abs(opts.adapter)
		if err != nil {
			return plan, err
		}

		flags = append(flags, "-DSCOUT_TREEPARSE_ADAPTER="+strconv.Quote(path))
	}

	if opts.sanitizer != "none" {
		sanitizer := "-fsanitize=thread"
		if opts.sanitizer == "address" {
			sanitizer = "-fsanitize=address,undefined"
		}

		flags = append(flags, sanitizer, "-fno-sanitize-recover=all")
	}

	build := opts.output + "-objects"
	if err := os.MkdirAll(build, 0o700); err != nil {
		return plan, err
	}

	objects := make([]string, 0, len(sources))
	for i, source := range sources {
		object := filepath.Join(build, strconv.Itoa(i)+".o")

		command := append([]string{opts.compiler}, flags...)
		for _, dir := range []string{adapter, filepath.Join(engine, "include"), filepath.Join(engine, "src"), filepath.Dir(source)} {
			command = append(command, "-I"+dir)
		}

		command = append(command, "-c", source, "-o", object)
		plan.Commands = append(plan.Commands, command)
		objects = append(objects, object)
	}

	link := append([]string{opts.compiler}, flags...)
	link = append(link, objects...)
	plan.Commands = append(plan.Commands, append(link, "-o", opts.output))

	return plan, nil
}

func query(ctx context.Context, name string, args ...string) (string, error) {
	//nolint:gosec // G204: fixed Go module queries, never scanned input.
	output, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %v: %w", name, args, err)
	}

	return strings.TrimSpace(string(output)), nil
}

func execute(ctx context.Context, root string, command []string, stdout, stderr io.Writer) error {
	//nolint:gosec // G204: developer-selected compiler and locally built test harness.
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)

	cmd.Dir, cmd.Stdout, cmd.Stderr = root, stdout, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", command[0], err)
	}

	return nil
}
