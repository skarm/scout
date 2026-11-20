//go:build !coreonly && cgo

package frontend_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/frontend"
)

// Full builds must actually link and exercise all three parsers. This suite
// never launches Python; an empty PATH must not disable any capability.
func TestNativeParsersWithoutInterpreterOrUserConfig(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PYTHONPATH", t.TempDir())
	o := frontend.DefaultOptions()
	o.Python = true
	o.YAML = true
	o.TOML = true
	for _, tc := range []struct{ format, text string }{{
		format: "python",
		text:   "import os\ntoken=os.getenv('TOKEN')\nprint(token)\n",
	}, {
		format: "yaml",
		text:   "name: sample\ndescription: text\n",
	}, {
		format: "toml",
		text:   "name='sample'\n[policy]\nallowed=true\n",
	}} {
		t.Run(tc.format, func(t *testing.T) {
			if !frontend.BackendFor(tc.format).Available {
				t.Fatal("native capability not linked")
			}
			r, e := frontend.Parse(context.Background(), o, tc.format, tc.text)
			if e != nil || r.Status != "ok" {
				t.Fatal(r, e)
			}
		})
	}
}

func TestNativeYAMLRejectsTypedAmbiguity(t *testing.T) {
	o := frontend.DefaultOptions()
	o.YAML = true
	for _, text := range []string{"x: !!int not-a-number", "x: !!bool yes", "x: !!null arbitrary", "x: &p [1]\ny: *p"} {
		if _, e := frontend.Parse(context.Background(), o, "yaml", text); e == nil {
			t.Fatalf("accepted unsupported scalar: %q", text)
		}
	}
}

func TestNativePythonProjectsTryClauses(t *testing.T) {
	const program = `try:
    work()
except ValueError as problem:
    recover(problem)
except:
    fallback()
else:
    success()
finally:
    cleanup()
`

	cfg := frontend.DefaultOptions()
	cfg.Python = true
	result, err := frontend.Parse(t.Context(), cfg, "python", program)
	if err != nil {
		t.Fatal(err)
	}

	n := result.AST.List(frontend.Body)[0]
	if n.Kind() != frontend.Try || len(n.List(frontend.Body)) != 1 ||
		len(n.List(frontend.Orelse)) != 1 || len(n.List(frontend.Finalbody)) != 1 {
		t.Fatalf("unexpected try clauses: %+v", n)
	}

	handlers := n.List(frontend.Handlers)
	if len(handlers) != 2 || handlers[0].Kind() != frontend.ExceptHandler ||
		handlers[0].String(frontend.FieldName) != "problem" ||
		handlers[0].Child(frontend.Test).String(frontend.ID) != "ValueError" ||
		handlers[1].Child(frontend.Test) != nil || len(handlers[1].List(frontend.Body)) != 1 {
		t.Fatalf("unexpected exception handlers: %+v", handlers)
	}

	_, err = frontend.Parse(t.Context(), cfg, "python", "try:\n    work()\nexcept* TypeError:\n    recover()\n")
	var limitation *frontend.Failure
	if !errors.As(err, &limitation) || limitation.Category != "unsupported_projection" {
		t.Fatalf("exception group limitation: %v", err)
	}
}

func TestNativeYAMLMappingStartsUsePhysicalBytes(t *testing.T) {
	o := frontend.DefaultOptions()
	o.YAML = true
	const first = "name: alpha"
	const second = "ключ: value"
	for _, tc := range []struct{ name, prefix, separator string }{
		{"LF", "", "\n"},
		{"bare CR", "", "\r"},
		{"CRLF", "", "\r\n"},
		{"UTF-8 BOM", "\ufeff", "\n"},
		{"UTF-8 BOM with CRLF", "\ufeff", "\r\n"},
		{"NEL", "", "\u0085"},
		{"line separator", "", "\u2028"},
		{"paragraph separator", "", "\u2029"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := tc.prefix + first + tc.separator + second + tc.separator
			result, err := frontend.Parse(t.Context(), o, "yaml", text)
			if err != nil {
				t.Fatal(err)
			}
			if result.Config == nil || len(result.Config.Members) != 2 {
				t.Fatalf("expected two mapping members: %+v", result.Config)
			}
			for i, want := range []struct {
				key, value     string
				keyAt, valueAt int
			}{
				{"name", "alpha", len(tc.prefix), len(tc.prefix + "name: ")},
				{"ключ", "value", len(tc.prefix + first + tc.separator), len(tc.prefix + first + tc.separator + "ключ: ")},
			} {
				got := result.Config.Members[i]
				if got.Key != want.key || got.Value == nil || got.Value.Text != want.value {
					t.Fatalf("member %d content changed: %+v", i, got)
				}
				if got.Start != want.keyAt || got.End != want.valueAt || got.Value.Start != want.valueAt {
					t.Fatalf("member %d starts at key/value bytes %d/%d, want %d/%d (key span ends at %d)", i, got.Start, got.Value.Start, want.keyAt, want.valueAt, got.End)
				}
			}
		})
	}
}

func TestNativePythonStringAndOperatorAlternatives(t *testing.T) {
	o := frontend.DefaultOptions()
	o.Python = true
	for _, tc := range []struct {
		source string
		kind   frontend.NodeKind
		value  string
		parts  int
	}{
		{source: `x = 'one' 'two'`, kind: frontend.Constant, value: "onetwo", parts: 0},
		{source: `x = b'one' b'two'`, kind: frontend.JoinedStr, value: "", parts: 2},
		{source: `x = f'hello {secret}'`, kind: frontend.JoinedStr, value: "", parts: 1},
		{source: `x = one if flag else two`, kind: frontend.IfExp, value: "", parts: 0},
		{source: `x = left and right`, kind: frontend.BoolOp, value: "", parts: 2},
		{source: `x = left or right`, kind: frontend.BoolOp, value: "", parts: 2},
		{source: `x = -3`, kind: frontend.UnaryOp, value: "", parts: 0},
		{source: `x = left + right`, kind: frontend.BinOp, value: "", parts: 0},
	} {
		t.Run(tc.source, func(t *testing.T) {
			r, err := frontend.Parse(context.Background(), o, "python", tc.source)
			if err != nil {
				t.Fatal(err)
			}
			n := r.AST.List(frontend.Body)[0].Child(frontend.FieldValue)
			if n.Kind() != tc.kind {
				t.Fatalf("kind=%s", n.Kind())
			}
			if tc.value != "" {
				if value, _ := n.Field(frontend.FieldValue).Text(); value != tc.value {
					t.Fatalf("value=%q", value)
				}
			}
			if tc.parts > 0 && len(n.List(frontend.Values)) != tc.parts {
				t.Fatalf("lost expression parts: %v", n.List(frontend.Values))
			}
		})
	}
}

func TestNativePythonWithBindsOnlyExplicitAliases(t *testing.T) {
	o := frontend.DefaultOptions()
	o.Python = true
	text := "with open('one') as stream, open('two'):\n    pass\n"
	r, err := frontend.Parse(context.Background(), o, "python", text)
	if err != nil {
		t.Fatal(err)
	}
	n := r.AST.List(frontend.Body)[0]
	items := n.List(frontend.Items)
	if n.Kind() != frontend.With || len(items) != 2 || len(n.List(frontend.Body)) != 1 {
		t.Fatalf("with projection lost structure: %v", n)
	}
	if items[0].Child(frontend.ContextExpr).Kind() != frontend.Call || items[0].Child(frontend.OptionalVars).String(frontend.ID) != "stream" {
		t.Fatal("explicit alias was lost")
	}
	if items[1].Child(frontend.ContextExpr).Kind() != frontend.Call || items[1].Child(frontend.OptionalVars) != nil {
		t.Fatal("unaliased item acquired a target")
	}
}

func TestNativeConfigScalarsAndArraysRetainOrderAndTypes(t *testing.T) {
	o := frontend.DefaultOptions()
	o.YAML = true
	o.TOML = true
	for _, tc := range []struct{ format, text string }{
		{format: "yaml", text: "items: [true, false, null, 42, 1.5, text]\n"},
		{format: "toml", text: "items = [true, false, 42, 1.5, 'text']\n"},
	} {
		r, err := frontend.Parse(context.Background(), o, tc.format, tc.text)
		if err != nil {
			t.Fatal(err)
		}
		items := r.Config.Members[0].Value.Elements
		if items[0].Kind != "bool" || !items[0].Bool || items[1].Kind != "bool" || items[1].Bool {
			t.Fatal("boolean values changed")
		}
		if tail := items[len(items)-1]; tail.Kind != "string" || tail.Text != "text" {
			t.Fatal("array order or string value changed")
		}
		if tc.format == "yaml" && items[2].Kind != "null" {
			t.Fatal("null became a string")
		}
	}
}

// These digests pin the existing transport contract, including byte spans and
// explicit partial projections, before changing the normalizer's dispatch.
func TestNativePythonProjectionContract(t *testing.T) {
	options := frontend.DefaultOptions()
	options.Python = true
	for _, tc := range []struct {
		name, source, category, digest string
	}{
		{
			name:     "access-assign",
			source:   "import os.path as path\nfrom ..tools import run as execute\nfrom __future__ import annotations\nx = y = value.attr[0]\nx += 1\ny: str = 'text'\nz = (item := x)\n",
			category: "",
			digest:   "5609a2ea844ef64a3b16d0f966e1868115eba0d02d98776d6292deb7660a9d3f",
		},
		{
			name:     "operators",
			source:   "a = left and right or fallback\nb = one if flag else two\nc = left + right\nd = not flag\ne = -3\nf = ~1\n",
			category: "",
			digest:   "e8ac68f27423930b48bdf2fd6ae8d4f63b8c7ee3617bf88f203a670d6fb9afd9",
		},
		{
			name:     "containers",
			source:   "a = [one, *items]\nb = (one, two)\nc = {one, two}\nd = {'key': value, **other}\n",
			category: "",
			digest:   "b57370a52987efa2bb03bc11fac675b87145991a878db88a939fdc3e5d2cb0a8",
		},
		{
			name:     "comprehensions",
			source:   "a = [item for item in items if enabled]\nb = {item for item in items}\nc = {key: value for key, value in pairs if key}\nd = (item for item in items)\n",
			category: "",
			digest:   "a48f89b7b8a34641adc1f408f97c0d972e3d563ee1a09304a3c5f880ac96f955",
		},
		{
			name:     "strings",
			source:   "a = 'секрет'\nb = b'\\xff'\nc = 'one' 'two'\nd = b'one' b'two'\ne = f'value={item!r:{width}}'\n",
			category: "unsupported_projection",
			digest:   "45723df8635dbe5cfdd1d18f198dfc511cc02e4562096011c1b37378b1f18998",
		},
		{
			name:     "definitions",
			source:   "@decorate(option)\ndef run(a: str, /, b=1, *items, c: int=2, **kwargs) -> str:\n    return b\nclass Handler(Base, metaclass=Meta):\n    pass\nf = lambda item=1: item\n",
			category: "",
			digest:   "f1c0e54e34329ed0768bf02ace33602cac2ef0fe12a287436f8ef29ad6725941",
		},
		{
			name:     "conditionals",
			source:   "if one:\n    first()\nelif two:\n    second()\nelse:\n    third()\nfor item in items:\n    continue\nelse:\n    pass\nwhile ready:\n    break\nelse:\n    pass\n",
			category: "",
			digest:   "e2fdc5f65425c9792cd591081d980e1ef3ba14f054607467e36b2d870e336fbf",
		},
		{
			name:     "with-terminal",
			source:   "def run():\n    global shared\n    with open('one') as stream, open('two'):\n        assert stream\n        del shared\n        raise ValueError('x') from cause\n    return stream\n",
			category: "",
			digest:   "c70fa57820b09b44a2341d90e3c3654306d13b8f54779b00f23bbbd6c27acd7b",
		},
		{
			name:     "calls",
			source:   "run(one, *items, named=value, **options)\n",
			category: "",
			digest:   "8ce50e1d4870cab853a645af67e94843c1f19abe99e4368776892b0c43bfd776",
		},
		{
			name:     "numbers",
			source:   "a = 0x10\nb = 1.5\nc = True\nd = False\ne = None\nf = ...\n",
			category: "",
			digest:   "6defac90191a7a8f77da439554623df4f4d70b01dc59fadef4faf98f5eff534a",
		},
		{
			name:   "try-statement",
			source: "try:\n    run()\nexcept Error as error:\n    recover(error)\nfinally:\n    cleanup()\n",
			digest: "fcd61aab797d6d93865a94dc9739843da004d97b909dce412f50bc874ed980a8",
		},
		{
			name:     "type-parameters",
			source:   "def identity[T](value: T) -> T:\n    return value\n",
			category: "unsupported_projection",
			digest:   "cf7cb5b87be0f9f4b085d55e9603293931d2c8e144e4554160dbaeefd1ab863c",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := frontend.Parse(context.Background(), options, "python", tc.source)
			category := ""
			var failure *frontend.Failure
			if err != nil {
				if !errors.As(err, &failure) {
					t.Fatal(err)
				}
				category = failure.Category
			}
			if category != tc.category || result.AST == nil {
				t.Fatalf("status=%s category=%s tree=%v", result.Status, category, result.AST)
			}
			encoded, err := json.Marshal(result.AST)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(encoded)
			actual := hex.EncodeToString(digest[:])
			if actual != tc.digest {
				t.Fatalf("projection digest=%s, want %s", actual, tc.digest)
			}
		})
	}
}

func TestPythonBinaryOperatorIdentity(t *testing.T) {
	for _, op := range []string{"+", "-", "*", "/", "//", "%", "**", "@", "|", "&", "^", "<<", ">>"} {
		t.Run(op, func(t *testing.T) {
			options := frontend.DefaultOptions()
			options.Python = true
			text := "left " + op + " right"
			result, err := frontend.Parse(t.Context(), options, "python", text)
			if err != nil {
				t.Fatal(err)
			}
			body := result.AST.List(frontend.Body)
			if len(body) != 1 {
				t.Fatal("missing expression")
			}
			expression := body[0].Child(frontend.FieldValue)
			if expression.Kind() != frontend.BinOp || expression.String(frontend.Op) != op {
				t.Fatalf("operator identity: %s %q", expression.Kind(), expression.String(frontend.Op))
			}
			children := expression.Children()
			if len(children) != 2 || children[0].String(frontend.ID) != "left" || children[1].String(frontend.ID) != "right" {
				t.Fatal("scalar operator changed evaluated children")
			}
			if expression.Start != 0 || expression.End != len(text) {
				t.Fatal("physical span changed")
			}
		})
	}
}

func TestPythonImaginaryLiteralTruth(t *testing.T) {
	options := frontend.DefaultOptions()
	options.Python = true
	for _, tc := range []struct {
		literal string
		truth   bool
	}{
		{literal: "0j", truth: false},
		{literal: "0.0j", truth: false},
		{literal: "0J", truth: false},
		{literal: "1e-999j", truth: false},
		{literal: "1j", truth: true},
		{literal: ".25J", truth: true},
		{literal: "1_000j", truth: true},
		{literal: "1e999j", truth: true},
	} {
		t.Run(tc.literal, func(t *testing.T) {
			result, err := frontend.Parse(t.Context(), options, "python", tc.literal)
			if err != nil {
				t.Fatal(err)
			}

			n := result.AST.List(frontend.Body)[0].Child(frontend.FieldValue)
			truth, known := n.Field(frontend.NumericTruth).Boolean()
			if n.Kind() != frontend.Constant || !known || truth != tc.truth || n.Start != 0 || n.End != len(tc.literal) {
				t.Fatalf("%s projected truth = %v, known = %v, node = %+v", tc.literal, truth, known, n)
			}
		})
	}
}

func TestPythonSubscriptRetainsAllIndexExpressions(t *testing.T) {
	options := frontend.DefaultOptions()
	options.Python = true
	for _, tc := range []struct {
		key   string
		tuple bool
		items []string
	}{
		{key: "row()", items: []string{"row()"}},
		{key: "row(),", tuple: true, items: []string{"row()"}},
		{key: "row(), col()", tuple: true, items: []string{"row()", "col()"}},
		{key: "row(1, 2)", items: []string{"row(1, 2)"}},
	} {
		t.Run(tc.key, func(t *testing.T) {
			const object = "table"
			text := object + "[" + tc.key + "]"
			result, err := frontend.Parse(t.Context(), options, "python", text)
			if err != nil {
				t.Fatal(err)
			}

			n := result.AST.List(frontend.Body)[0].Child(frontend.FieldValue)
			if n.Kind() != frontend.Subscript || n.Child(frontend.FieldValue).String(frontend.ID) != object {
				t.Fatalf("lost subscript receiver: %+v", n)
			}

			key := n.Child(frontend.Slice)
			if key == nil || key.Start != len(object)+1 || key.End != len(text)-1 {
				t.Fatalf("subscript key span changed: %+v", key)
			}

			items := []*frontend.Node{key}
			if tc.tuple {
				if key.Kind() != frontend.Tuple {
					t.Fatalf("subscript key = %s, want tuple", key.Kind())
				}

				items = key.List(frontend.Elts)
			}

			if len(items) != len(tc.items) {
				t.Fatalf("subscript has %d index expressions, want %d", len(items), len(tc.items))
			}

			for i, item := range items {
				if item.Kind() != frontend.Call || text[item.Start:item.End] != tc.items[i] {
					t.Fatalf("index %d lost expression or coordinates: %+v", i, item)
				}
			}
		})
	}

	result, err := frontend.Parse(t.Context(), options, "python", "table[row(), start():stop()]")
	var limitation *frontend.Failure
	if !errors.As(err, &limitation) || limitation.Category != "unsupported_projection" || result.AST == nil {
		t.Fatalf("slice syntax should preserve partial projection: %v", err)
	}

	items := result.AST.List(frontend.Body)[0].Child(frontend.FieldValue).Child(frontend.Slice).List(frontend.Elts)
	if len(items) != 2 || items[1].Kind() != frontend.UnsupportedExpression || len(items[1].Children()) != 2 {
		t.Fatal("partial slice lost its bounds")
	}
}

func TestPythonCallPreservesGeneratorAsOneArgument(t *testing.T) {
	options := frontend.DefaultOptions()
	options.Python = true
	const expression = "item for item in values if enabled"
	for _, text := range []string{"sum(" + expression + ")", "sum((" + expression + "), start=0)"} {
		t.Run(text, func(t *testing.T) {
			result, err := frontend.Parse(t.Context(), options, "python", text)
			if err != nil {
				t.Fatal(err)
			}

			call := result.AST.List(frontend.Body)[0].Child(frontend.FieldValue)
			args := call.List(frontend.Args)
			if call.Kind() != frontend.Call || len(args) != 1 || args[0].Kind() != frontend.GeneratorExp {
				t.Fatalf("generator was not retained as one argument: %+v", call)
			}

			generator := args[0]
			start := strings.Index(text, expression)
			if generator.Start != start-1 || generator.End != start+len(expression)+1 || generator.Child(frontend.Elt).String(frontend.ID) != "item" {
				t.Fatalf("generator expression or physical span changed: %+v", generator)
			}

			clauses := generator.List(frontend.Generators)
			if len(clauses) != 1 || clauses[0].Child(frontend.Target).String(frontend.ID) != "item" || clauses[0].Child(frontend.Iter).String(frontend.ID) != "values" {
				t.Fatalf("generator loop not retained: %+v", clauses)
			}

			if filters := clauses[0].List(frontend.Ifs); len(filters) != 1 || filters[0].String(frontend.ID) != "enabled" {
				t.Fatal("generator filter not retained")
			}

			keywords := call.List(frontend.Keywords)
			if strings.Contains(text, "start=") && (len(keywords) != 1 || keywords[0].String(frontend.FieldArg) != "start") {
				t.Fatalf("explicit generator call lost keyword argument: %+v", keywords)
			}
		})
	}
}
