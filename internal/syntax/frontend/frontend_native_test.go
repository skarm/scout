//go:build !coreonly && cgo

package frontend_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
			digest:   "44d97dd94f882fc8165c79711c5f01cb65c967742fff78e62c59247d72228db7",
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
			name:     "unknown-statements",
			source:   "try:\n    run()\nexcept Error as error:\n    recover(error)\nfinally:\n    cleanup()\n",
			category: "unsupported_projection",
			digest:   "f064cf6f65fac3297f2ecf5b3afd36edbb31738095fdbc68c424dc7263a93162",
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
