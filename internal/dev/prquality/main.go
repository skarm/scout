// The prquality command reports test and evaluation regressions in a Git diff.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type location struct {
	path string
	line int
}

type warning struct {
	location
	base             bool
	category, detail string
}

func main() {
	const runTimeout = time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)

	err := run(ctx, os.Args[1:], os.Stdout)

	cancel()

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)

		os.Exit(2)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("prquality", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	github := flags.Bool("github", false, "write GitHub Actions warnings")

	summary := flags.String("summary", "", "append a Markdown check summary to this file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if flags.NArg() != 2 {
		return errors.New("usage: prquality [-github] [-summary FILE] BASE HEAD")
	}

	warnings, err := reviewDiff(ctx, flags.Arg(0), flags.Arg(1))
	if err != nil {
		return err
	}

	if err := writeWarnings(out, warnings, *github); err != nil {
		return err
	}

	if *summary != "" {
		return appendSummary(*summary, warnings)
	}

	return nil
}

func reviewDiff(ctx context.Context, baseRef, headRef string) ([]warning, error) {
	base, err := commit(ctx, baseRef)
	if err != nil {
		return nil, err
	}

	head, err := commit(ctx, headRef)
	if err != nil {
		return nil, err
	}

	rawBase, err := git(ctx, "merge-base", base, head)
	if err != nil {
		return nil, err
	}

	base = string(bytes.TrimSpace(rawBase))

	raw, err := git(ctx, "diff", "--no-ext-diff", "--no-renames", "--raw", "--no-abbrev", "-z", "--diff-filter=ADMT", base, head, "--",
		"Makefile", ".github/workflows", "testdata/security-corpus", "testdata/knowledge-runtime/cases.json",
		"testdata/production-replay/cases.json", ":(glob)**/*.go",
		":(glob)**/*.js", ":(glob)**/*.jsx", ":(glob)**/*.mjs", ":(glob)**/*.cjs",
		":(glob)**/*.ts", ":(glob)**/*.tsx", ":(glob)**/*.mts", ":(glob)**/*.cts", ":(glob)**/*.py", ":(glob)**/*.pyi")
	if err != nil {
		return nil, err
	}

	if len(raw) == 0 {
		return nil, nil
	}

	fields := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	if len(fields)%2 != 0 {
		return nil, errors.New("unexpected Git raw diff output")
	}

	before, after := newInventory(), newInventory()

	if err := readGitBlobs(ctx, func(read blobReader) error {
		return readDiffFiles(ctx, fields, before, after, read)
	}); err != nil {
		return nil, err
	}

	return compareInventories(before, after), nil
}

func readDiffFiles(ctx context.Context, fields []string, before, after inventory, read blobReader) error {
	for i := 0; i < len(fields); i += 2 {
		if err := ctx.Err(); err != nil {
			return err
		}

		header := strings.Fields(strings.TrimPrefix(fields[i], ":"))
		if len(header) != 5 {
			return errors.New("unexpected Git raw diff entry")
		}

		path := fields[i+1]
		if regularGitMode(header[0]) {
			if err := before.read(ctx, read, header[2], path); err != nil {
				return err
			}
		}

		if regularGitMode(header[1]) {
			if err := after.read(ctx, read, header[3], path); err != nil {
				return err
			}
		}
	}

	return nil
}

func regularGitMode(mode string) bool {
	return mode == "100644" || mode == "100755"
}

func commit(ctx context.Context, ref string) (string, error) {
	raw, err := git(ctx, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	return string(bytes.TrimSpace(raw)), err
}

func git(ctx context.Context, args ...string) ([]byte, error) {
	// Git receives separate arguments. Revisions for object and diff access
	// have already been resolved to immutable commit IDs.
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // Arguments are Git options and object selectors, never shell code.

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", args[0], err)
	}

	return out, nil
}

func writeWarnings(out io.Writer, warnings []warning, github bool) error {
	sort.Slice(warnings, func(i, j int) bool {
		a, b := warnings[i], warnings[j]
		if a.path != b.path {
			return a.path < b.path
		}

		if a.line != b.line {
			return a.line < b.line
		}

		if a.category != b.category {
			return a.category < b.category
		}

		return a.detail < b.detail
	})

	for _, item := range warnings {
		if err := writeWarning(out, item, github); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(out, "PR quality review: %d warning(s).\n", len(warnings))

	return err
}

func writeWarning(out io.Writer, item warning, github bool) error {
	detail := item.detail
	if item.base && item.line > 0 {
		detail = fmt.Sprintf("Base revision line %d. %s", item.line, detail)
	} else if item.base {
		detail = "Base revision. " + detail
	}

	if !github {
		_, err := fmt.Fprintf(out, "%s: %s: %s\n", warningPath(item), item.category, detail)
		return err
	}

	properties := "file=" + annotationEscape(item.path, true) + ",title=" + annotationEscape(item.category, true)
	if !item.base && item.line > 0 {
		properties += fmt.Sprintf(",line=%d", item.line)
	}

	_, err := fmt.Fprintf(out, "::warning %s::%s\n", properties, annotationEscape(detail, false))

	return err
}

func appendSummary(path string, warnings []warning) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:gosec // The caller explicitly selects a CI summary destination.
	if err != nil {
		return err
	}

	var out strings.Builder
	fmt.Fprintf(&out, "## PR quality review\n\n%d advisory warning(s).\n\n", len(warnings))

	for _, item := range warnings {
		revision := "head"
		if item.base {
			revision = "base"
		}

		at := warningPath(item) + " (" + revision + ")"
		fmt.Fprintf(&out, "- **%s** at <code>%s</code>. %s\n", html.EscapeString(item.category), html.EscapeString(at), html.EscapeString(item.detail))
	}

	_, err = io.WriteString(f, out.String())

	return errors.Join(err, f.Close())
}

func warningPath(item warning) string {
	if item.line > 0 {
		return fmt.Sprintf("%q:%d", item.path, item.line)
	}

	return fmt.Sprintf("%q", item.path)
}

func annotationEscape(value string, property bool) string {
	value = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(value)
	if property {
		value = strings.NewReplacer(",", "%2C", ":", "%3A").Replace(value)
	}

	return value
}
