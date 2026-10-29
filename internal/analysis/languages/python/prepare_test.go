package python //nolint:testpackage // Tests exercise private preparation state and fake parser units.

import (
	"context"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
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
