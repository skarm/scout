// Package parse dispatches trusted, language-specific parsers. Registration is
// immutable and local to a preparation pass, not a dynamically loaded plugin API.
package parse

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/skarm/scout/internal/buildinfo"
	"github.com/skarm/scout/internal/syntax/gobind"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/modconfig"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

const (
	goModAdapterVersion = "1"

	// MaxUnitBytes bounds the maximum accepted byte ceiling declared by one parser
	// backend.
	MaxUnitBytes = 256 << 10
	// MaxScanBytes bounds the maximum aggregate scan-byte ceiling declared by a
	// parser backend.
	MaxScanBytes = 2 << 20
)

// Descriptor identifies a trusted parser and its per-unit and aggregate byte
// ceilings.
type Descriptor struct {
	// ID identifies the trusted parser adapter.
	ID string
	// Language is the normalized language key used by Registry.
	Language string
	// Version identifies the parser adapter revision.
	Version string
	// UnitBytes limits one parser input in bytes.
	UnitBytes int
	// ScanBytes limits selected bytes across source units.
	ScanBytes int
}

// Backend parses immutable source views without executing inspected content.
// Implementations must honor cancellation and support their registry's
// concurrent use.
type Backend interface {
	// Descriptor returns stable parser identity and byte ceilings.
	Descriptor() Descriptor
	// Parse returns a backend-specific immutable tree for the source view. An
	// error may accompany a usable partial tree. Callers must classify errors
	// rather than publish raw parser prose that may contain source contents.
	Parse(context.Context, source.View) (any, error)
}

// Registry holds an immutable set of trusted backends keyed by normalized
// language name.
type Registry struct{ backends map[string]Backend }

// New validates trusted descriptors and builds a registry, rejecting nil
// backends and duplicate languages.
func New(backends ...Backend) (Registry, error) {
	r := Registry{backends: make(map[string]Backend, len(backends))}
	for _, b := range backends {
		if b == nil {
			return Registry{}, errors.New("nil parser backend")
		}

		d := b.Descriptor()
		if !d.valid() {
			return Registry{}, errors.New("invalid parser descriptor")
		}

		if _, ok := r.backends[d.Language]; ok {
			return Registry{}, errors.New("duplicate language backend")
		}

		r.backends[d.Language] = b
	}

	return r, nil
}

// Defaults returns the parser registry selected by this build's constraints.
func Defaults() Registry {
	r, _ := New(languageBackends()...)
	return r
}

// Lookup returns the backend registered for the normalized language key and
// whether it exists.
func (r Registry) Lookup(id string) (Backend, bool) { b, ok := r.backends[id]; return b, ok }

const (
	// CodeLimit indicates that parsing hit its work or size budget.
	CodeLimit = "parser_limit"
	// CodeUnsupportedSyntax indicates the parser could not handle the syntax.
	CodeUnsupportedSyntax = "unsupported_syntax"
	// CodeBackendUnavailable indicates the selected backend is unavailable.
	CodeBackendUnavailable     = "backend_unavailable"
	codeAmbiguousConfiguration = "ambiguous_configuration"
)

// Failure gives preparation a finite, source-free classification. Arbitrary
// parser error strings are never forwarded into reports.
type Failure struct {
	// Category is the finite classification used instead of arbitrary parser error
	// prose.
	Category string
}

// Error returns a constant message without source text or raw parser
// diagnostics.
func (f *Failure) Error() string { return "parser failure" }

// FailureCategory returns an allowed source-free parser classification,
// defaulting unknown errors to syntax_error.
func FailureCategory(err error) string {
	if failure, ok := errors.AsType[*Failure](err); ok {
		switch failure.Category {
		case CodeUnsupportedSyntax, CodeLimit, codeAmbiguousConfiguration, CodeBackendUnavailable:
			return failure.Category
		}
	}

	return "syntax_error"
}

func (d Descriptor) valid() bool {
	return d.ID != "" && d.Version != "" && language.Normalize(d.Language) == d.Language && language.Structured(d.Language) &&
		d.UnitBytes >= 1 && d.UnitBytes <= MaxUnitBytes && d.ScanBytes >= d.UnitBytes && d.ScanBytes <= MaxScanBytes
}

// GoTree retains a standard-library Go AST and its token positions over
// captured bytes.
type GoTree struct {
	// Tree contains the parsed Go AST, which may be partial when parsing failed.
	Tree *ast.File
	// Tokens maps AST token positions to offsets in the captured analysis view.
	Tokens *token.FileSet
	// Bindings supplies immutable lexical declaration identities.
	Bindings gobind.Bindings
}
type goBackend struct{}

func (goBackend) Descriptor() Descriptor {
	return Descriptor{ID: "go-stdlib", Language: language.Go, Version: "2", UnitBytes: MaxUnitBytes, ScanBytes: MaxScanBytes}
}

func (goBackend) Parse(ctx context.Context, v source.View) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fs := token.NewFileSet()
	tree, err := parser.ParseFile(fs, "", v.Text(), parser.AllErrors|parser.SkipObjectResolution)

	bindings, bindingErr := gobind.Resolve(ctx, tree)
	if bindingErr != nil {
		if ctx.Err() != nil {
			return GoTree{Tokens: fs}, ctx.Err()
		}

		return GoTree{Tokens: fs}, &Failure{Category: CodeLimit}
	}

	return GoTree{Tree: tree, Tokens: fs, Bindings: bindings}, err
}

// ShellTree is a native bounded grammar, not a full POSIX/Bash compatibility claim.
type (
	ShellTree struct {
		// Tree contains the bounded execution-grammar projection.
		Tree *shellsyntax.File
		// Declarations contains the separate bounded command/source declaration
		// projection.
		Declarations *shellsyntax.File
		// DeclarationError records failure of the declaration projection independently
		// of execution parsing.
		DeclarationError error
		// ExecutionError records failure of the execution-grammar projection.
		ExecutionError error
		// DeclarationView retains the source mapping used for a selected declaration
		// candidate when present.
		DeclarationView *source.View
	}
	shellBackend struct{}
)

func (shellBackend) Descriptor() Descriptor {
	return Descriptor{
		ID:        "shell-native-subset",
		Language:  language.Shell,
		Version:   "8",
		UnitBytes: shellsyntax.MaxBytes,
		ScanBytes: MaxScanBytes,
	}
}

func (shellBackend) Parse(ctx context.Context, v source.View) (any, error) {
	tree, err := shellsyntax.Parse(ctx, v.Text())
	declarations, declarationErr := shellsyntax.ParseDeclarations(ctx, v.Text())
	err, declarationErr = shellFailure(err), shellFailure(declarationErr)

	return ShellTree{Tree: tree, Declarations: declarations, DeclarationError: declarationErr, ExecutionError: err}, err
}

// Both shell grammar projections report the same bounded failure vocabulary.
// Candidate preparation can distinguish rejected prose from unfinished work.
func shellFailure(err error) error {
	if syntaxErr, ok := errors.AsType[*shellsyntax.Error](err); ok {
		category := "syntax_error"
		if strings.HasPrefix(syntaxErr.Code, "unsupported_") {
			category = CodeUnsupportedSyntax
		}

		if strings.HasSuffix(syntaxErr.Code, "_limit") {
			category = CodeLimit
		}

		return &Failure{Category: category}
	}

	return err
}

// JSONTree uses a strict bounded standard-library token decoder, not a runtime
// config loader. No key can change scanner policy or enable tools.
type JSONTree struct {
	// Root contains the strictly decoded configuration tree.
	Root *jsonconfig.Node
	// Runtime identifies the configuration adapter.
	Runtime string
	// Format identifies the parsed configuration representation.
	Format string
}

// RuntimeIdentity returns the configuration adapter identity retained with the
// parsed tree.
func (t JSONTree) RuntimeIdentity() string { return t.Runtime }

type jsonBackend struct{ comments, trailingCommas, json5, bom bool }

// WithJSONComments selects a known JSON dialect for a physical file.
// A caller-supplied JSON backend retains its own format policy.
func WithJSONComments(backend Backend, trailingCommas bool) Backend {
	if _, ok := backend.(jsonBackend); ok {
		return jsonBackend{comments: true, trailingCommas: trailingCommas}
	}

	return backend
}

// WithJSONCommentsAndBOM accepts comments and an initial UTF-8 BOM.
func WithJSONCommentsAndBOM(backend Backend) Backend {
	if _, ok := backend.(jsonBackend); ok {
		return jsonBackend{comments: true, bom: true}
	}

	return backend
}

// WithJSON5 selects the bounded JSON5 reader for a native config file.
func WithJSON5(backend Backend) Backend {
	if _, ok := backend.(jsonBackend); ok {
		return jsonBackend{json5: true}
	}

	return backend
}

func (jsonBackend) Descriptor() Descriptor {
	return Descriptor{
		ID:        "json-stdlib-strict",
		Language:  language.JSON,
		Version:   "1",
		UnitBytes: jsonconfig.MaxBytes,
		ScanBytes: MaxScanBytes,
	}
}

func (b jsonBackend) Parse(ctx context.Context, v source.View) (any, error) {
	decode, runtime := jsonconfig.Parse, ""
	if b.json5 {
		decode, runtime = jsonconfig.ParseJSON5, "json5"
	} else if b.trailingCommas {
		decode, runtime = jsonconfig.ParseJSONC, "jsonc"
	} else if b.bom {
		decode, runtime = jsonconfig.ParseWithCommentsAndBOM, "json-with-comments-and-bom"
	} else if b.comments {
		decode, runtime = jsonconfig.ParseWithComments, "json-with-comments"
	}

	root, err := decode(ctx, v.Text())
	if err != nil {
		if e, ok := errors.AsType[*jsonconfig.Error](err); ok {
			if strings.HasSuffix(e.Code, "_limit") {
				err = &Failure{Category: CodeLimit}
			}

			if e.Code == jsonconfig.CodeDuplicateKey {
				err = &Failure{Category: codeAmbiguousConfiguration}
			}
		}

		return nil, err
	}

	return JSONTree{Root: root, Format: language.JSON, Runtime: runtime}, nil
}

// GoModTree is parsed from captured bytes, without go list, module resolution,
// downloading dependencies or executing tools/toolchains declared in the file.
type (
	GoModTree struct {
		// File contains declarations parsed from captured go.mod bytes without module
		// resolution.
		File *modfile.File
	}
	goModBackend struct{}
)

func (goModBackend) Descriptor() Descriptor {
	version := buildinfo.ModuleVersion("golang.org/x/mod")

	return Descriptor{
		ID:        "go-mod-xmod",
		Language:  language.GoMod,
		Version:   version + "-adapter" + goModAdapterVersion,
		UnitBytes: modconfig.MaxBytes,
		ScanBytes: MaxScanBytes,
	}
}

func (goModBackend) Parse(ctx context.Context, v source.View) (any, error) {
	f, err := modconfig.Parse(ctx, v.Text())
	if err != nil {
		if e, ok := errors.AsType[*modconfig.Error](err); ok {
			if strings.HasSuffix(e.Code, "_limit") {
				return nil, &Failure{Category: CodeLimit}
			}

			if strings.HasPrefix(e.Code, "duplicate_") {
				return nil, &Failure{Category: codeAmbiguousConfiguration}
			}
		}

		return nil, err
	}

	return GoModTree{File: f}, nil
}
