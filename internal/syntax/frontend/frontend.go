// Package frontend wraps embedded syntax libraries. It never starts Python,
// imports inspected modules, or resolves libraries from the inspected artifact.
package frontend

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/report"
)

const (
	// AdapterVersion identifies Scout's projection of embedded parser output.
	AdapterVersion = "5"

	MaxBytes  = 256 << 10
	maxOutput = 2 << 20
	maxNodes  = 8192
	MaxDepth  = 32
)

// Options enable independent compiled parser capabilities.
type Options struct {
	Python, YAML, TOML bool
	Timeout            time.Duration
}

// Backend identifies the compiled adapter, not a dynamically discovered runtime.
type Backend struct {
	Format    string `json:"format"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type ConfigNode struct {
	Kind     string        `json:"kind"`
	Start    int           `json:"start"`
	End      int           `json:"end"`
	Text     string        `json:"text,omitempty"`
	Bool     bool          `json:"bool,omitempty"`
	Members  []Member      `json:"members,omitempty"`
	Elements []*ConfigNode `json:"elements,omitempty"`
}

type Member struct {
	Key   string      `json:"key"`
	Start int         `json:"start"`
	End   int         `json:"end"`
	Value *ConfigNode `json:"value"`
}

type Result struct {
	Protocol int         `json:"protocol"`
	Format   string      `json:"format"`
	Version  string      `json:"version"`
	Status   string      `json:"status"`
	AST      *Node       `json:"ast,omitempty"`
	Config   *ConfigNode `json:"config,omitempty"`
}

type Failure struct{ Category string }

type treeValidator struct{ size, count int }

func DefaultOptions() Options { return Options{Timeout: 3 * time.Second} }

func Backends() []Backend {
	return []Backend{BackendFor(language.Python), BackendFor(language.YAML), BackendFor(language.TOML)}
}

func Parse(ctx context.Context, o Options, format, text string) (Result, error) {
	if err := validateInput(ctx, o, format, text); err != nil {
		return Result{}, err
	}

	b := BackendFor(format)
	if !b.Available {
		return Result{}, &Failure{Category: "unavailable"}
	}

	call, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	r := Result{Protocol: 2, Format: format, Version: b.Version, Status: "ok"}

	var err error

	switch format {
	case language.Python:
		r.AST, err = parsePython(call, text)
	case language.YAML:
		r.Config, err = parseYAML(call, text)
	case language.TOML:
		r.Config, err = parseTOML(call, text)
	}

	return completeParse(call, r, err, len(text))
}

func (o Options) Validate() error {
	if o.Timeout <= 0 || o.Timeout > 10*time.Second {
		return errors.New("invalid embedded parser timeout")
	}

	return nil
}

func (o Options) enables(format string) bool {
	switch format {
	case language.Python:
		return o.Python
	case language.YAML:
		return o.YAML
	case language.TOML:
		return o.TOML
	default:
		return false
	}
}

func (r Result) RuntimeIdentity() string {
	return fmt.Sprintf("%s-%s-adapter-v%s", BackendFor(r.Format).Name, r.Version, AdapterVersion)
}

func (e *Failure) Error() string { return "embedded syntax parser: " + e.Category }

func validateInput(ctx context.Context, o Options, format, text string) error {
	if ctx == nil {
		return errors.New("nil parser context")
	}

	if err := o.Validate(); err != nil {
		return err
	}

	if !o.enables(format) {
		return &Failure{Category: "not_enabled"}
	}

	if len(text) > MaxBytes {
		return &Failure{Category: "input_limit"}
	}

	if !utf8.ValidString(text) {
		return &Failure{Category: "invalid_utf8"}
	}

	return ctx.Err()
}

func completeParse(ctx context.Context, r Result, parseErr error, size int) (Result, error) {
	var failure *Failure

	partial := errors.As(parseErr, &failure) && failure.Category == "unsupported_projection" && r.AST != nil
	if parseErr != nil && !partial {
		return Result{}, parseErr
	}

	if partial {
		r.Status = report.OutcomePartial
	}

	if ctx.Err() != nil {
		return Result{}, &Failure{Category: "deadline"}
	}

	if err := validateTree(r, size); err != nil {
		return Result{}, err
	}

	return r, parseErr
}

// validateTree validates every serialized field, including previously unfamiliar
// Python node fields. Analysis may cover fewer semantics than syntax validation.
func validateTree(r Result, size int) error {
	v := treeValidator{size: size}

	if r.Format != language.Python {
		if r.AST != nil {
			return &Failure{Category: "invalid_tree"}
		}

		return v.config(r.Config, 0)
	}

	if r.AST == nil || r.AST.Kind() != Module || r.Config != nil {
		return &Failure{Category: "invalid_tree"}
	}

	return v.python(r.AST, 0)
}

func (v *treeValidator) validRange(start, end int) bool {
	return start >= 0 && end >= start && end <= v.size
}

func (v *treeValidator) config(n *ConfigNode, depth int) error {
	v.count++
	if n == nil || v.count > maxNodes || depth > MaxDepth {
		return &Failure{Category: "invalid_tree"}
	}

	if !v.validRange(n.Start, n.End) {
		return &Failure{Category: "invalid_tree"}
	}

	switch n.Kind {
	case jsonconfig.KindObject:
		return v.members(n.Members, depth)
	case jsonconfig.KindArray:
		return v.configElements(n.Elements, depth)

	case jsonconfig.KindString, jsonconfig.KindBool, jsonconfig.KindNumber, jsonconfig.KindNull:
	default:
		return &Failure{Category: "invalid_tree"}
	}

	return nil
}

func (v *treeValidator) members(members []Member, depth int) error {
	seen := make(map[string]bool, len(members))
	for _, m := range members {
		if seen[m.Key] || !v.validRange(m.Start, m.End) {
			return &Failure{Category: "ambiguous_key"}
		}

		seen[m.Key] = true
		if err := v.config(m.Value, depth+1); err != nil {
			return err
		}
	}

	return nil
}

func (v *treeValidator) python(n *Node, depth int) error {
	v.count++
	if n == nil || n.Kind().String() == "" || depth > MaxDepth || v.count > maxNodes || !v.validRange(n.Start, n.End) {
		return &Failure{Category: "invalid_tree"}
	}

	for _, field := range n.fields {
		if _, err := n.fieldIndex(field.kind, field.value); err != nil {
			return &Failure{Category: "invalid_tree"}
		}

		if err := v.pythonField(field.value, depth+1); err != nil {
			return err
		}
	}

	return nil
}

func (v *treeValidator) pythonField(value Value, depth int) error {
	if child := value.node(); child != nil {
		return v.python(child, depth)
	}

	if children := value.nodeSlice(); children != nil {
		for _, child := range children {
			if child == nil {
				continue
			}

			if err := v.python(child, depth); err != nil {
				return err
			}
		}
	}

	return nil
}

func (v *treeValidator) configElements(elements []*ConfigNode, depth int) error {
	for _, child := range elements {
		if err := v.config(child, depth+1); err != nil {
			return err
		}
	}

	return nil
}
