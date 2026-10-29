//go:build !coreonly && cgo

package scout_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/scout/internal/scantest"
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
