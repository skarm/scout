package frontend_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/frontend"
)

func TestActualPythonAndTOML(t *testing.T) {
	o := options(t)
	for _, tc := range []struct {
		name, lang, text string
		bad              bool
	}{
		{name: "python", lang: "python", text: "import os\nx = os.getenv('TOKEN')\nprint(x)", bad: false},
		{name: "syntax", lang: "python", text: "def (", bad: true},
		{
			name: "toml",
			lang: "toml",
			text: "approval_policy='never'\n[mcp_servers.example]\ncommand='echo'\nargs=['one','two']",
			bad:  false,
		},
		{name: "toml-duplicate", lang: "toml", text: "x=1\nx=2", bad: true},
		{name: "toml-datetime", lang: "toml", text: "date=2026-10-26", bad: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := frontend.Parse(context.Background(), o, tc.lang, tc.text)
			if (e != nil) != tc.bad {
				t.Fatalf("result=%+v err=%v", r, e)
			}
			if !tc.bad && (r.Status != "ok" || r.Version == "") {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestNeverExecutesPythonSource(t *testing.T) {
	o := options(t)
	target := filepath.Join(t.TempDir(), "MUST_NOT_EXIST")
	src := "from pathlib import Path\nPath(" + `"` + target + `"` + ").write_text('executed')\nraise RuntimeError('not parse error')"
	if _, e := frontend.Parse(context.Background(), o, "python", src); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(target); !os.IsNotExist(e) {
		t.Fatalf("target executed or stat unexpected: %v", e)
	}
}

func TestLimitsAndConsent(t *testing.T) {
	o := frontend.DefaultOptions()
	o.Python = true
	if _, e := frontend.Parse(context.Background(), frontend.DefaultOptions(), "python", "pass"); e == nil {
		t.Fatal("disabled parser ran")
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := frontend.Parse(c, o, "python", "pass"); e == nil {
		t.Fatal("cancel ignored")
	}
	if _, e := frontend.Parse(context.Background(), o, "python", strings.Repeat(" ", frontend.MaxBytes+1)); e == nil {
		t.Fatal("byte limit")
	}
	o.Timeout = 0
	if e := o.Validate(); e == nil {
		t.Fatal("zero parser timeout accepted")
	}
}

func TestActualYAML(t *testing.T) {
	o := options(t)
	if !frontend.BackendFor("yaml").Available {
		t.Skip("Go YAML not linked")
	}
	o.YAML = true
	for _, tc := range []struct {
		name, text string
		bad        bool
	}{
		{
			name: "normal",
			text: "name: valid-skill\ndescription: >-\n  Длинное описание\n  второй строки\nmetadata: {author: sample}\n",
			bad:  false,
		},
		{name: "duplicate", text: "x: 1\nx: 2", bad: true},
		{name: "escaped-duplicate", text: "x: 1\n\"\\x78\": 2", bad: true},
		{name: "custom-tag", text: "x: !!python/object/apply:os.system ['touch /tmp/no-target-execution']", bad: true},
		{name: "alias", text: "x: &a [1,2]\ny: *a", bad: true},
		{name: "cycle", text: "x: &a [*a]", bad: true},
		{name: "multi", text: "---\nx: 1\n---\ny: 2", bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := frontend.Parse(context.Background(), o, "yaml", tc.text)
			if (e != nil) != tc.bad {
				t.Fatalf("result=%+v err=%v", r, e)
			}
			if !tc.bad {
				for _, m := range r.Config.Members {
					if m.Start < 0 || m.End > len(tc.text) || m.Value.End > len(tc.text) {
						t.Fatal("mapping")
					}
				}
			}
		})
	}
}

func TestSyntheticCSTNormalizationAndUnknownBarrier(t *testing.T) {
	// The test constructs a CST explicitly; it checks projection/evidence only,
	// NOT acceptance or detection quality of a real native Python parser.
	text := "exec(input())"
	call := syn("call", "", 0, len(text), syn("identifier", "function", 0, 4), syn("argument_list", "arguments", 4, len(text), syn("call", "", 5, 12, syn("identifier", "function", 5, 10), syn("argument_list", "arguments", 10, 12))))
	root := syn("module", "", 0, len(text), syn("expression_statement", "", 0, len(text), call))
	tree, err := frontend.NormalizePythonForTest(context.Background(), text, root)
	if err != nil {
		t.Fatal(err)
	}
	inner := tree.List(frontend.Body)[0].Child(frontend.FieldValue)
	if inner.Kind() != frontend.Call || inner.Child(frontend.Func).String(frontend.ID) != "exec" || inner.List(frontend.Args)[0].Child(frontend.Func).String(frontend.ID) != "input" {
		t.Fatalf("%+v", tree)
	}
	if err = frontend.ValidateTreeForTest(frontend.Result{Format: "python", AST: tree}, len(text)); err != nil {
		t.Fatal(err)
	}
	root.Children = append(root.Children, syn("unknown_statement", "", 0, len(text), call))
	tree, err = frontend.NormalizePythonForTest(context.Background(), text, root)
	var f *frontend.Failure
	if !errors.As(err, &f) || f.Category != "unsupported_projection" || tree == nil || tree.List(frontend.Body)[1].Kind() != frontend.UnsupportedStatement {
		t.Fatalf("%+v %v", tree, err)
	}
}

func TestProjectionPreservesUTF8ByteEvidence(t *testing.T) {
	text := "'секрет'"
	root := syn("module", "", 0, len(text), syn("expression_statement", "", 0, len(text), syn("string", "", 0, len(text))))
	tree, e := frontend.NormalizePythonForTest(context.Background(), text, root)
	if e != nil {
		t.Fatal(e)
	}
	c := tree.List(frontend.Body)[0].Child(frontend.FieldValue)
	if c == nil {
		t.Fatal("projection lost the expression value")
	}
	value, _ := c.Field(frontend.FieldValue).Text()
	if value != "секрет" || c.Start != 0 || c.End != len(text) {
		t.Fatal(c)
	}
}

func TestConverterRejectsLimitsAndCancellation(t *testing.T) {
	text := "x"
	root := syn("module", "", 0, 1, syn("identifier", "", 0, 2))
	if _, e := frontend.NormalizePythonForTest(context.Background(), text, root); e == nil {
		t.Fatal("out-of-range tree")
	}
	root = syn("module", "", 0, 1, syn("identifier", "", 0, 1))
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := frontend.NormalizePythonForTest(c, text, root); e == nil {
		t.Fatal("cancel ignored")
	}
	node := syn("identifier", "", 0, 1)
	for range frontend.MaxDepth + 2 {
		node = syn("parenthesized_expression", "", 0, 1, node)
	}
	if _, e := frontend.NormalizePythonForTest(context.Background(), text, syn("module", "", 0, 1, node)); e == nil {
		t.Fatal("depth ignored")
	}
}

func TestSyntheticAnnotationsAndClassKeywordsAreNotDropped(t *testing.T) {
	// Synthetic CSTs validate the projection contract, not grammar conformance.
	text := "def f(x: eval('x')) -> eval('y'): pass"
	callAt := func(needle, field string) *frontend.TestPythonSyntax {
		start := strings.Index(text, needle)
		return syn("call", field, start, start+len(needle), syn("identifier", "function", start, start+4), syn("argument_list", "arguments", start+4, start+len(needle), syn("string", "", start+5, start+len(needle)-1)))
	}
	pStart := strings.Index(text, "x:")
	pEnd := strings.Index(text, " ->") - 1
	param := syn("typed_parameter", "", pStart, pEnd, syn("identifier", "", pStart, pStart+1), syn("type", "type", pStart+3, pEnd, callAt("eval('x')", "")))
	ret := callAt("eval('y')", "")
	fun := syn("function_definition", "", 0, len(text), syn("identifier", "name", 4, 5), syn("parameters", "parameters", 5, pEnd+1, param), syn("type", "return_type", ret.Start, ret.End, ret), syn("block", "body", len(text)-4, len(text), syn("pass_statement", "", len(text)-4, len(text))))
	root, err := frontend.NormalizePythonForTest(context.Background(), text, syn("module", "", 0, len(text), fun))
	if err != nil {
		t.Fatal(err)
	}
	f := root.List(frontend.Body)[0]
	args := f.Child(frontend.Args).List(frontend.Args)
	if len(args) != 1 || args[0].Child(frontend.Annotation) == nil || f.Child(frontend.Returns) == nil || args[0].Child(frontend.Annotation).Kind() != frontend.Call || f.Child(frontend.Returns).Kind() != frontend.Call {
		t.Fatal("annotation lost")
	}
	if err := frontend.ValidateTreeForTest(frontend.Result{Format: "python", AST: root}, len(text)); err != nil {
		t.Fatal(err)
	}
	text = "class C(metaclass=eval('x')): pass"
	start := strings.Index(text, "metaclass")
	kw := syn("keyword_argument", "", start, len(text)-7, syn("identifier", "name", start, start+9), callAt("eval('x')", "value"))
	cls := syn("class_definition", "", 0, len(text), syn("identifier", "name", 6, 7), syn("argument_list", "superclasses", 7, len(text)-6, kw), syn("block", "body", len(text)-4, len(text), syn("pass_statement", "", len(text)-4, len(text))))
	root, err = frontend.NormalizePythonForTest(context.Background(), text, syn("module", "", 0, len(text), cls))
	if err != nil {
		t.Fatal(err)
	}
	c := root.List(frontend.Body)[0]
	if len(c.List(frontend.Bases)) != 0 || len(c.List(frontend.Keywords)) != 1 || c.List(frontend.Keywords)[0].Child(frontend.FieldValue).Kind() != frontend.Call {
		t.Fatal("class keyword lost")
	}
}

func TestEveryArgumentFieldIsTraversableAndBoundsValidated(t *testing.T) {
	for _, key := range []frontend.FieldKind{frontend.Posonlyargs, frontend.KWOnlyargs, frontend.Vararg, frontend.Kwarg, frontend.TypeParams} {
		t.Run(key.String(), func(t *testing.T) {
			bad := mustIRNode(t, frontend.Arg, 0, 99)
			kind := frontend.Arguments
			field := frontend.NodesField(key, []*frontend.Node{bad})
			if key == frontend.Vararg || key == frontend.Kwarg {
				field = frontend.ChildField(key, bad)
			}
			if key == frontend.TypeParams {
				kind = frontend.FunctionDef
			}
			args := mustIRNode(t, kind, 0, 1, field)
			root := mustIRNode(t, frontend.Module, 0, 1, frontend.NodesField(frontend.Body, []*frontend.Node{args}))
			if children := args.Children(); len(children) != 1 || children[0].End != 99 {
				t.Fatal("analysis traversal omitted an argument field")
			}
			// Bounds validation already covers every serialized field independently.
			if frontend.ValidateTreeForTest(frontend.Result{Format: "python", AST: root}, 1) == nil {
				t.Fatal("missed hidden invalid coordinates")
			}
		})
	}
}

func TestAmbiguousSyntheticTypeWrapperRetainsDescendants(t *testing.T) {
	text := "x y"
	wrapper := syn("type", "", 0, len(text), syn("identifier", "", 0, 1), syn("identifier", "", 2, 3))
	tree, err := frontend.NormalizePythonForTest(context.Background(), text, syn("module", "", 0, len(text), wrapper))
	var failure *frontend.Failure
	if !errors.As(err, &failure) || failure.Category != "unsupported_projection" {
		t.Fatal("ambiguous type wrapper was inferred")
	}
	n := tree.List(frontend.Body)[0]
	if n.Kind() != frontend.UnsupportedExpression || len(n.List(frontend.Body)) != 2 {
		t.Fatal("ambiguous wrapper dropped traversable descendants")
	}
}

func TestPythonLiteralProjection(t *testing.T) {
	for _, tc := range []struct {
		source, want string
		bytes, ok    bool
	}{
		{source: `'hello'`, want: "hello", bytes: false, ok: true},
		{source: "", want: "", bytes: false, ok: false},
		{source: "plain", want: "", bytes: false, ok: false},
		{source: `abc'x'`, want: "", bytes: false, ok: false},
		{source: `u'x'`, want: "x", bytes: false, ok: true},
		{source: `RB'\n'`, want: `\n`, bytes: true, ok: true},
		{source: `'x"`, want: "", bytes: false, ok: false},
		{source: `'''x''`, want: "", bytes: false, ok: false},
		{source: `b'секрет'`, want: "", bytes: false, ok: false},
		{source: `b'\u0041'`, want: `\u0041`, bytes: true, ok: true},
		{source: `b'\N{SPACE}'`, want: `\N{SPACE}`, bytes: true, ok: true},
		{source: `'\a\b\f\r\t\v\\\'\"'`, want: "\a\b\f\r\t\v\\'\"", bytes: false, ok: true},
		{source: `'\x'`, want: "", bytes: false, ok: false},
		{source: `'\U00110000'`, want: "", bytes: false, ok: false},
		{source: `'\400'`, want: "Ā", bytes: false, ok: true},

		{source: `"\x54\u004f\U0000004bEN"`, want: "TOKEN", bytes: false, ok: true},
		{source: `r'\n'`, want: `\n`, bytes: false, ok: true},
		{source: `b'\xff'`, want: string([]byte{255}), bytes: true, ok: true},
		{source: `br'\xff'`, want: `\xff`, bytes: true, ok: true},
		{source: `'\141\n'`, want: "a\n", bytes: false, ok: true},
		{source: "'''a\r\nb'''", want: "a\nb", bytes: false, ok: true},
		{source: `'\s'`, want: `\s`, bytes: false, ok: true},
		{source: `f'{value}'`, want: "", bytes: false, ok: false},
		{source: `'\N{SPACE}'`, want: "", bytes: false, ok: false},
		{source: `'\ud800'`, want: "", bytes: false, ok: false},
		{source: `b'\400'`, want: "", bytes: false, ok: false},
		{source: `'\xQ0'`, want: "", bytes: false, ok: false},
	} {
		t.Run(tc.source, func(t *testing.T) {
			v, b, ok := frontend.PythonLiteralForTest(tc.source)
			if v != tc.want || b != tc.bytes || ok != tc.ok {
				t.Fatalf("got %q,%v,%v", v, b, ok)
			}
		})
	}
}

func FuzzPythonLiteralProjection(f *testing.F) {
	for _, s := range []string{`'plain'`, `b'\xff'`, `'\u0041'`, `f'{x}'`, string([]byte{0xff}), "'''x'''"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > frontend.MaxBytes {
			t.Skip()
		}
		a, _, ok := frontend.PythonLiteralForTest(s)
		if ok && len(a) > len(s) {
			t.Fatal("unexpected expansion")
		}
	})
}

func TestParserInputBudgetBeforeBackendSelection(t *testing.T) {
	o := frontend.DefaultOptions()
	o.Python = true
	if _, e := frontend.Parse(context.Background(), o, "python", strings.Repeat("x", frontend.MaxBytes+1)); e == nil {
		t.Fatal("input limit")
	}
}

func TestConfigTreeValidationRejectsInvalidShapesAndCoordinates(t *testing.T) {
	for _, node := range []*frontend.ConfigNode{
		{Kind: "mystery"},
		{Kind: "array", Elements: []*frontend.ConfigNode{nil}},
		{
			Kind: "object",
			Members: []frontend.Member{{
				Key:   "x",
				Start: 0,
				End:   2,
				Value: &frontend.ConfigNode{Kind: "null"},
			}},
		},
		{
			Kind: "object",
			Members: []frontend.Member{{Key: "x", Value: &frontend.ConfigNode{Kind: "null"}}, {
				Key:   "x",
				Value: &frontend.ConfigNode{Kind: "null"},
			}},
		},
		{Kind: "string", Start: -1},
	} {
		if err := frontend.ValidateTreeForTest(frontend.Result{Format: "yaml", Config: node}, 1); err == nil {
			t.Fatalf("invalid config was accepted: %+v", node)
		}
	}
}

func options(t *testing.T) frontend.Options {
	t.Helper()
	if !frontend.BackendFor("python").Available || !frontend.BackendFor("toml").Available {
		t.Skip("embedded native/config parsers not linked in this explicit core-only build")
	}
	o := frontend.DefaultOptions()
	o.Python = true
	o.TOML = true
	return o
}

func mustIRNode(t *testing.T, kind frontend.NodeKind, start, end int, fields ...frontend.Field) *frontend.Node {
	t.Helper()
	node, err := frontend.NewNode(kind, start, end, fields...)
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func syn(kind, field string, start, end int, children ...*frontend.TestPythonSyntax) *frontend.TestPythonSyntax {
	return &frontend.TestPythonSyntax{Kind: kind, Field: field, Start: start, End: end, Named: true, Children: children}
}
