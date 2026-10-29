// Package maintenance implements source verification and developer runtime checks.
package maintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	maxJSONLine   = 64 << 20
	decisionAllow = "allow"
	findingsKey   = "findings"
	coverageKey   = "coverage"
	decisionKey   = "decision"
	errorKey      = "error"
)

type object map[string]any

type options struct {
	root     string
	values   map[string]*string
	download *bool
}

// Run executes a source verification or Scout runtime check.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: scout-dev <verify-knowledge-sources|check-knowledge-runtime> [flags]")
	}

	command := args[0]

	args = args[1:]

	if command != "verify-knowledge-sources" && command != "check-knowledge-runtime" {
		return fmt.Errorf("unknown maintenance command %q", command)
	}

	opts, err := parseOptions(command, args, stderr)
	if err != nil {
		return err
	}

	return execute(ctx, command, opts, stdout)
}

func parseOptions(command string, args []string, stderr io.Writer) (options, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)

	opts := options{values: map[string]*string{}}
	for name := range strings.FieldsSeq("cache binary output") {
		opts.values[name] = flags.String(name, "", name+" path")
	}

	opts.download = flags.Bool("download", false, "download missing pinned knowledge sources")

	root := flags.String("root", "", "Scout project root (defaults to nearest go.mod)")
	if err := flags.Parse(args); err != nil {
		return opts, err
	}

	if flags.NArg() != 0 {
		return opts, errors.New("unexpected positional arguments")
	}

	opts.root = *root
	if opts.root == "" {
		var err error

		opts.root, err = projectRoot()
		if err != nil {
			return opts, err
		}
	}

	return opts, nil
}

func execute(ctx context.Context, command string, opts options, stdout io.Writer) error {
	switch command {
	case "verify-knowledge-sources":
		return verifyKnowledgeSources(ctx, opts, stdout)
	case "check-knowledge-runtime":
		return checkKnowledgeRuntime(ctx, opts, stdout)
	default:
		return fmt.Errorf("unknown maintenance command %q", command)
	}
}

func (o options) require(names ...string) error {
	for _, name := range names {
		if o.get(name) == "" {
			return fmt.Errorf("--%s is required", name)
		}
	}

	return nil
}

func (o options) get(name string) string {
	if p := o.values[name]; p != nil {
		return *p
	}

	return ""
}

func projectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err = os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("scout project root not found; use --root")
		}

		dir = parent
	}
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func fileDigest(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: explicit caller-selected maintenance input.
	if err != nil {
		return "", err
	}

	return digest(b), nil
}

func readJSON(path string, value any) error {
	b, err := os.ReadFile(path) //nolint:gosec // G304: caller-selected local JSON input to an offline maintenance command.
	if err != nil {
		return err
	}

	return json.Unmarshal(b, value)
}

func writeJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func printJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(value)
}
func array(v any) []any { out, _ := v.([]any); return out }
func obj(v any) object {
	switch x := v.(type) {
	case map[string]any:
		return x
	case object:
		return x
	}

	return nil
}
func text(v any) string  { out, _ := v.(string); return out }
func number(v any) int   { out, _ := v.(float64); return int(out) }
func boolean(v any) bool { out, _ := v.(bool); return out }
func at(v any, keys ...string) any {
	for _, key := range keys {
		v = obj(v)[key]
	}

	return v
}

func stringsOf(v any) []string {
	values := array(v)
	out := make([]string, 0, len(values))

	for _, item := range values {
		out = append(out, text(item))
	}

	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}

	slices.Sort(out)

	return out
}

func newOutput(path string) error {
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("output must be a new directory")
	}

	return os.MkdirAll(path, 0o700)
}

func safeJoin(root, name string) (string, error) {
	if !filepath.IsLocal(name) || strings.ContainsAny(name, "\\\x00") {
		return "", errors.New("invalid relative artifact path")
	}

	return filepath.Join(root, name), nil
}
