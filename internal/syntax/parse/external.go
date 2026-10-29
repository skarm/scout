package parse

import (
	"context"
	"errors"

	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/source"
)

//nolint:gochecknoglobals // Read-only frontend failure classifications shared by parser projections.
var frontendFailureCategories = map[string]string{
	"unavailable":   "backend_unavailable",
	"ambiguous_key": "ambiguous_configuration",
	"input_limit":   "parser_limit",
	"output_limit":  "parser_limit",
	"limit":         "parser_limit",
	"deadline":      "parser_limit",
}

type embeddedBackend struct {
	lang    string
	options frontend.Options
}

type PythonTree struct {
	Root    *frontend.Node
	Runtime string
}

// WithFrontends keeps every default backend. Optional parsers are compiled
// capabilities; no source file can start an interpreter or choose a library path.
func WithFrontends(o frontend.Options) (Registry, error) {
	if err := o.Validate(); err != nil {
		return Registry{}, err
	}

	backends := languageBackends()

	for _, item := range []struct {
		language string
		enabled  bool
	}{
		{language: language.Python, enabled: o.Python},
		{language: language.YAML, enabled: o.YAML},
		{language: language.TOML, enabled: o.TOML},
	} {
		if item.enabled {
			backends = append(backends, embeddedBackend{lang: item.language, options: o})
		}
	}

	return New(backends...)
}

func (b embeddedBackend) Descriptor() Descriptor {
	backend := frontend.BackendFor(b.lang)

	return Descriptor{
		ID:        backend.Name,
		Language:  b.lang,
		Version:   backend.Version + "-adapter-v" + frontend.AdapterVersion,
		UnitBytes: MaxUnitBytes,
		ScanBytes: MaxScanBytes,
	}
}

func (b embeddedBackend) Parse(ctx context.Context, v source.View) (any, error) {
	r, err := frontend.Parse(ctx, b.options, b.lang, v.Text())
	if err != nil {
		var f *frontend.Failure
		if b.lang == language.Python && r.AST != nil && errors.As(err, &f) && f.Category == "unsupported_projection" {
			return PythonTree{Root: r.AST, Runtime: r.RuntimeIdentity()}, &Failure{Category: "unsupported_syntax"}
		}

		return nil, frontendFailure(err)
	}

	if b.lang == language.Python {
		return PythonTree{Root: r.AST, Runtime: r.RuntimeIdentity()}, nil
	}

	return JSONTree{Root: convertConfigNode(r.Config), Runtime: r.RuntimeIdentity(), Format: b.lang}, nil
}

// RuntimeIdentity implements the cross-package parser identity interface.
func (t PythonTree) RuntimeIdentity() string { return t.Runtime }

func frontendFailure(err error) error {
	category := "unsupported_syntax"

	if failure, ok := errors.AsType[*frontend.Failure](err); ok {
		if known := frontendFailureCategories[failure.Category]; known != "" {
			category = known
		}
	}

	return &Failure{Category: category}
}

// Configuration projection preserves the frontend's source spans recursively;
// it does not reinterpret values or assign decoded offsets to escaped strings.
func convertConfigNode(n *frontend.ConfigNode) *jsonconfig.Node {
	if n == nil {
		return nil
	}

	out := &jsonconfig.Node{Kind: n.Kind, Span: source.Span{Start: n.Start, End: n.End}, String: n.Text, Bool: n.Bool}
	for _, m := range n.Members {
		out.Members = append(out.Members, jsonconfig.Member{
			Key:     m.Key,
			KeySpan: source.Span{Start: m.Start, End: m.End},
			Value:   convertConfigNode(m.Value),
		})
	}

	for _, v := range n.Elements {
		out.Elements = append(out.Elements, convertConfigNode(v))
	}

	return out
}
