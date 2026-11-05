package python //nolint:testpackage // Tests exercise private preparation state and fake parser units.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func TestPythonPrepareSharesCandidateQuotaAcrossDocuments(t *testing.T) {
	registry, err := parse.New(quotaPythonBackend{})
	if err != nil {
		t.Fatal(err)
	}
	files := []artifact.File{
		artifact.NewFile("a.py", []byte("eval"), false),
		artifact.NewFile("b.py", []byte("eval;exec"), false),
		artifact.NewFile("c.py", []byte("plain"), false),
		artifact.NewFile("d.py", []byte("exec"), false),
	}
	docs := document.PrepareAllWithRegistry(context.Background(), files, registry)
	facts := Prepare(context.Background(), docs, []string{"AST1", "AST2"}, 1, 0)
	for _, tc := range []struct {
		path, id  string
		count     int
		truncated bool
	}{
		{path: "a.py", id: "AST2", count: 1, truncated: false},
		{path: "b.py", id: "AST2", count: 0, truncated: true},
		{path: "b.py", id: "AST1", count: 1, truncated: false},
		{path: "c.py", id: "AST2", count: 0, truncated: false},
		{path: "d.py", id: "AST1", count: 0, truncated: true},
	} {
		got, err := facts[tc.path].result(tc.id, 1)
		if err != nil || len(got.Matches) != tc.count || got.Truncated != tc.truncated {
			t.Fatalf("%s/%s: matches=%d truncated=%v err=%v", tc.path, tc.id, len(got.Matches), got.Truncated, err)
		}
	}
}

// Explicit synthetic IR checks collection ownership in core-only builds; it is
// not evidence that a native Python grammar accepted a source program.
type quotaPythonBackend struct{}

func (quotaPythonBackend) Descriptor() parse.Descriptor {
	return parse.Descriptor{
		ID:        "quota-python-fixture",
		Language:  "python",
		Version:   "1",
		UnitBytes: parse.MaxUnitBytes,
		ScanBytes: parse.MaxScanBytes,
	}
}

func (quotaPythonBackend) Parse(_ context.Context, view source.View) (any, error) {
	var statements []*frontend.Node
	for word := range strings.SplitSeq(view.Text(), ";") {
		if word != "eval" && word != "exec" {
			continue
		}
		start := strings.Index(view.Text(), word)
		name, _ := frontend.NewNode(frontend.Name, start, start+len(word), frontend.TextField(frontend.ID, word))
		call, _ := frontend.NewNode(frontend.Call, start, start+len(word), frontend.ChildField(frontend.Func, name))
		expression, _ := frontend.NewNode(frontend.Expr, start, start+len(word), frontend.ChildField(frontend.FieldValue, call))
		statements = append(statements, expression)
	}
	root, err := frontend.NewNode(frontend.Module, 0, len(view.Text()), frontend.NodesField(frontend.Body, statements))
	return parse.PythonTree{Root: root, Runtime: "quota-fixture"}, err
}

// Synthetic IR isolates absent annotation handling. It does not claim that a
// native grammar accepted the fixture; the ordinary-definition benchmark below
// separately exercises the native projection and complete Python evaluator.
func BenchmarkDefinitionAnnotationPreparation(b *testing.B) {
	for _, bindings := range []int{0, 128, 512} {
		for _, parameters := range []int{0, 8} {
			b.Run(fmt.Sprintf("bindings-%d/parameters-%d", bindings, parameters), func(b *testing.B) {
				state := newPyState()
				for i := range bindings {
					state.set(fmt.Sprintf("value_%d", i), literalValue("public", true, 2))
				}
				args := make([]*frontend.Node, parameters)
				for i := range args {
					var err error
					args[i], err = frontend.NewNode(frontend.Arg, 0, 1,
						frontend.TextField(frontend.FieldArg, fmt.Sprintf("arg_%d", i)))
					if err != nil {
						b.Fatal(err)
					}
				}
				arguments, err := frontend.NewNode(frontend.Arguments, 0, 1, frontend.NodesField(frontend.Args, args))
				if err != nil {
					b.Fatal(err)
				}
				walker := pyWalker{ctx: context.Background(), facts: newPythonFacts([]string{ruleAST2}, 16)}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					walker.definitionAnnotations(arguments, nil, state, 0)
				}
				if walker.err != nil || walker.truncated || walker.ops != 0 || len(state.names) != bindings {
					b.Fatal("absent annotations changed evaluation state or consumed expression operations")
				}
			})
		}
	}
}

// Parsing is outside the timed region. This measures real frontend-produced IR
// through Prepare, including definition creation, scope isolation and facts.
func BenchmarkOrdinaryPythonDefinitions(b *testing.B) {
	if !frontend.BackendFor("python").Available {
		b.Skip("native Python grammar required")
	}
	options := frontend.DefaultOptions()
	options.Python = true
	registry, err := parse.WithFrontends(options)
	if err != nil {
		b.Fatal(err)
	}
	for _, bindings := range []int{0, 128, 512} {
		for _, functions := range []int{16, 128} {
			b.Run(fmt.Sprintf("bindings-%d/functions-%d", bindings, functions), func(b *testing.B) {
				var text strings.Builder
				for i := range bindings {
					if _, err := fmt.Fprintf(&text, "value_%d = 'public'\n", i); err != nil {
						b.Fatal(err)
					}
				}
				for i := range functions {
					if _, err := fmt.Fprintf(&text, "def function_%d(a, b, c, d, e, f, g, h):\n    pass\n", i); err != nil {
						b.Fatal(err)
					}
				}
				docs := document.PrepareAllWithRegistry(b.Context(), []artifact.File{
					artifact.NewFile("definitions.py", []byte(text.String()), false),
				}, registry)
				units := docs[0].Units()
				if len(units) != 1 || units[0].Status != report.UnitParsedLimited {
					b.Fatal("definition fixture exceeded native parser limits")
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					facts := Prepare(b.Context(), docs, []string{ruleAST2}, 1024, 0)
					result, err := facts["definitions.py"].result(ruleAST2, 1024)
					if err != nil || result.Truncated || len(result.Matches) != 0 {
						b.Fatal("ordinary definitions did not complete without observations")
					}
				}
			})
		}
	}
}
