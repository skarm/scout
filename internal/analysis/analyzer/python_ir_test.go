package analyzer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/python"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestPythonIRDefinitionInputsRetainIndependentCalls(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *frontend.Node
	}{
		{name: "function-arg", node: ir(frontend.FunctionDef, frontend.ChildField(frontend.Args,

			ir(frontend.Arguments, frontend.NodesField(frontend.Args,

				[]*frontend.Node{ir(frontend.Arg, frontend.TextField(frontend.FieldArg,

					"x"), frontend.ChildField(frontend.Annotation,

					pyEvalCall()))}))))},
		{name: "function-return", node: ir(frontend.FunctionDef, frontend.ChildField(frontend.Returns,

			pyEvalCall()))},
		{name: "vararg", node: ir(frontend.FunctionDef, frontend.ChildField(frontend.Args,

			ir(frontend.Arguments, frontend.ChildField(frontend.Vararg,

				ir(frontend.Arg, frontend.TextField(frontend.FieldArg,

					"xs"), frontend.ChildField(frontend.Annotation,

					pyEvalCall()))))))},
		{name: "kwarg", node: ir(frontend.FunctionDef, frontend.ChildField(frontend.Args,

			ir(frontend.Arguments, frontend.ChildField(frontend.Kwarg,

				ir(frontend.Arg, frontend.TextField(frontend.FieldArg,

					"xs"), frontend.ChildField(frontend.Annotation,

					pyEvalCall()))))))},
		{name: "keyword-only", node: ir(frontend.FunctionDef, frontend.ChildField(frontend.Args,

			ir(frontend.Arguments, frontend.NodesField(frontend.KWOnlyargs,

				[]*frontend.Node{ir(frontend.Arg, frontend.TextField(frontend.FieldArg,

					"x"), frontend.ChildField(frontend.Annotation,

					pyEvalCall()))}))))},
		{name: "class-decorator", node: ir(frontend.ClassDef, frontend.NodesField(frontend.DecoratorList,

			[]*frontend.Node{pyEvalCall()}))},
		{name: "class-keyword", node: ir(frontend.ClassDef, frontend.NodesField(frontend.Keywords,

			[]*frontend.Node{ir(frontend.Keyword, frontend.TextField(frontend.FieldArg,

				"metaclass"), frontend.ChildField(frontend.FieldValue,

				pyEvalCall()))}))},
		{name: "annotation-assignment", node: ir(frontend.AnnAssign, frontend.ChildField(frontend.Target,

			pyName("x")), frontend.ChildField(frontend.Annotation,

			pyEvalCall()))},
		{name: "lambda-default", node: ir(frontend.Expr, frontend.ChildField(frontend.FieldValue,

			ir(frontend.Lambda, frontend.ChildField(frontend.Args,

				ir(frontend.Arguments, frontend.NodesField(frontend.Defaults,

					[]*frontend.Node{pyEvalCall()}))), frontend.ChildField(frontend.Body,

				pyName("x")))))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := ir(frontend.Module, frontend.NodesField(frontend.Body,

				[]*frontend.Node{tc.node}))
			r := runPythonIR(t, root, "PY-AST2")
			if len(r.Matches) != 1 {
				t.Fatalf("lost definition expression: %+v", r)
			}
		})
	}
}

func TestPythonIRAnnotationDoesNotMutateOuterBindings(t *testing.T) {
	// An annotation's hypothetical named-expression must not shadow builtin eval
	// in the enclosing state. Deferred evaluation is outside the current profile.
	change := ir(frontend.NamedExpr, frontend.ChildField(frontend.Target,

		pyName("eval")), frontend.ChildField(frontend.FieldValue,

		ir(frontend.Constant, frontend.LiteralField(frontend.StringValue("not a callable")))))
	def := ir(frontend.FunctionDef, frontend.TextField(frontend.FieldName,

		"f"), frontend.ChildField(frontend.Returns,

		change))
	root := ir(frontend.Module, frontend.NodesField(frontend.Body,

		[]*frontend.Node{def, ir(frontend.Expr, frontend.ChildField(frontend.FieldValue,

			pyEvalCall()))}))
	if r := runPythonIR(t, root, "PY-AST2"); len(r.Matches) != 1 {
		t.Fatal(r)
	}
}

func TestPythonIRLambdaBodyValueIsNotDefinitionValue(t *testing.T) {
	imp := ir(frontend.Import, frontend.NodesField(frontend.Names,

		[]*frontend.Node{ir(frontend.Alias, frontend.TextField(frontend.FieldName,

			"os")), ir(frontend.Alias, frontend.TextField(frontend.FieldName,

			"requests"))}))
	env := ir(frontend.Call, frontend.ChildField(frontend.Func,

		ir(frontend.Attribute, frontend.ChildField(frontend.FieldValue,

			pyName("os")), frontend.TextField(frontend.Attr,

			"getenv"))), frontend.NodesField(frontend.Args,

		[]*frontend.Node{ir(frontend.Constant, frontend.LiteralField(frontend.StringValue("TOKEN")))}))
	def := ir(frontend.Assign, frontend.NodesField(frontend.Targets,

		[]*frontend.Node{pyName("f")}), frontend.ChildField(frontend.FieldValue,

		ir(frontend.Lambda, frontend.ChildField(frontend.Body,

			env))))
	post := ir(frontend.Expr, frontend.ChildField(frontend.FieldValue,

		ir(frontend.Call, frontend.ChildField(frontend.Func,

			ir(frontend.Attribute, frontend.ChildField(frontend.FieldValue,

				pyName("requests")), frontend.TextField(frontend.Attr,

				"post"))), frontend.NodesField(frontend.Args,

			[]*frontend.Node{pyName("f")}))))
	root := ir(frontend.Module, frontend.NodesField(frontend.Body,

		[]*frontend.Node{imp, def, post}))
	if r := runPythonIR(t, root, "PY-TT3"); len(r.Matches) != 0 {
		t.Fatalf("definition incorrectly treated as body evaluation: %+v", r)
	}
}

// This backend provides an explicit IR fixture, NOT a replacement Python parser.
// It lets core-only builds check traversal regressions without claiming native acceptance.
type pythonIRBackend struct{ root *frontend.Node }

func (pythonIRBackend) Descriptor() parse.Descriptor {
	return parse.Descriptor{
		ID:        "test-python-ir",
		Language:  "python",
		Version:   "fixture1",
		UnitBytes: parse.MaxUnitBytes,
		ScanBytes: parse.MaxScanBytes,
	}
}

func (b pythonIRBackend) Parse(context.Context, source.View) (any, error) {
	return parse.PythonTree{Root: b.root, Runtime: "fixture-only"}, nil
}

func ir(kind frontend.NodeKind, fields ...frontend.Field) *frontend.Node {
	node, err := frontend.NewNode(kind, 0, 4, fields...)
	if err != nil {
		panic(err)
	}
	return node
}

func pyName(s string) *frontend.Node {
	return ir(frontend.Name, frontend.TextField(frontend.ID,

		s))
}

func pyEvalCall() *frontend.Node {
	return ir(frontend.Call, frontend.ChildField(frontend.Func,

		pyName("eval")), frontend.NodesField(frontend.Args,

		[]*frontend.Node{ir(frontend.Constant, frontend.LiteralField(frontend.StringValue("inert text")))}))
}

func runPythonIR(t *testing.T, root *frontend.Node, rule string) analyzer.Result {
	t.Helper()
	reg, e := parse.New(pythonIRBackend{root: root})
	if e != nil {
		t.Fatal(e)
	}
	f := artifact.NewFile("sample.py", []byte(strings.Repeat(" ", 80)), false)
	docs := document.PrepareAllWithRegistry(context.Background(), []artifact.File{f}, reg)
	for _, a := range python.Rules() {
		if a.Rule().ID != rule {
			continue
		}
		r, e := a.Find(context.Background(), prepared(context.Background(), docs[0]), 100)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	t.Fatal("missing rule")
	return analyzer.Result{}
}
