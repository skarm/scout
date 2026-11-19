//go:build !coreonly && cgo

package bundle

import (
	"context"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func TestScriptScalarResultOrigins(t *testing.T) {
	for _, lang := range []string{language.JavaScript, language.TypeScript} {
		for _, tc := range []struct {
			expr                   string
			retainsText, dependent bool
		}{
			{"value", true, true},
			{"value + 'x'", true, true},
			{"+value", false, true},
			{"-value", false, true},
			{"~value", false, true},
			{"!value", false, true},
			{"value * 2", false, true},
			{"value === 'x'", false, true},
			{"value++", false, true},
			{"--value", false, true},
			{"value -= 2", false, true},
			{"void (copy = value)", false, false},
			{"typeof value", false, false},
		} {
			t.Run(lang+"/"+tc.expr, func(t *testing.T) {
				origin := &report.SourceRef{Path: "sample.txt"}
				env := map[string]bundleValue{"value": {remote: origin, remoteKind: 2, secret: origin}}
				v := evaluateScriptExpression(t, lang, tc.expr, env)
				if (v.remote == origin) != tc.retainsText || (v.secret == origin) != tc.dependent {
					t.Fatalf("text origin=%v, data origin=%v", v.remote, v.secret)
				}
				if tc.expr == "void (copy = value)" && env["copy"].remote != origin {
					t.Fatal("discarding the result also discarded the operand's assignment")
				}
				if (tc.expr == "value++" || tc.expr == "--value" || tc.expr == "value -= 2") && env["value"].remote != nil {
					t.Fatal("updated binding retained the previous text")
				}
			})
		}
	}
}

func TestScriptLiteralArrayPositions(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want []string
	}{
		{"[]", nil},
		{"[/* note */]", nil},
		{"['a', /* note */ 'b',]", []string{"a", "b"}},
		{"[, 'b']", []string{"", "b"}},
		{"['a', , /* note */ , 'd']", []string{"a", "", "", "d"}},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			values := evaluateScriptExpression(t, language.JavaScript, tc.expr, nil).items
			if len(values) != len(tc.want) {
				t.Fatalf("array has %d items, want %d", len(values), len(tc.want))
			}
			for i, want := range tc.want {
				if values[i].text != want || values[i].known != (want != "") {
					t.Fatalf("item %d: got %q, known=%t", i, values[i].text, values[i].known)
				}
			}
		})
	}
}

func evaluateScriptExpression(t *testing.T, lang, expr string, env map[string]bundleValue) bundleValue {
	t.Helper()

	tree, err := scriptsyntax.Parse(t.Context(), lang, expr)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Root == nil || len(tree.Root.Children) != 1 {
		t.Fatal("expected one expression statement")
	}
	view, err := source.NewView(expr, []source.Span{{Start: 0, End: len(expr)}})
	if err != nil {
		t.Fatal(err)
	}

	p := &bundleProgram{language: lang, unit: document.Unit{View: view}}
	b := &bundleAnalysis{ctx: t.Context()}
	v := b.eval(p, b.scriptValue(p, tree.Root.Children[0], 0), env, 0)
	if b.err != nil || b.gap != nil {
		t.Fatalf("projection: %v, %v", b.err, b.gap)
	}
	return v
}

func TestPythonBooleanResultOrigins(t *testing.T) {
	for _, tc := range []struct {
		expr        string
		retainsText bool
	}{
		{"value", true},
		{"value + 'x'", true},
		{"value * 2", true},
		{"value and value", true},
		{"value or value", true},
		{"not value", false},
		{"not (copy := value)", false},
		{"value == 'ordinary'", false},
		{"value != 'ordinary'", false},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			// Local abstract string value, with independent text and data-dependency
			// labels. No network operation or execution of inspected code is involved.
			origin := &report.SourceRef{Path: "local-text-fixture.txt"}
			env := map[string]bundleValue{"value": {text: "ordinary", known: true, remote: origin, remoteKind: 2, secret: origin}}
			b, p, n := pythonExpressionFixture(t, tc.expr)
			got := b.eval(p, n, env, 0)
			if b.err != nil || b.gap != nil && tc.expr != "value * 2" {
				t.Fatalf("projection: %v %v", b.err, b.gap)
			}
			if tc.retainsText && got.remote != origin || !tc.retainsText && got.remote != nil || got.secret != origin {
				t.Fatalf("text origin=%v dependency=%v", got.remote, got.secret)
			}
			if !tc.retainsText && (got.remoteKind != 0 || got.known || got.hasCallableIdentity()) {
				t.Fatal("boolean acquired a text or callable identity")
			}
			if tc.expr == "not (copy := value)" && env["copy"].remote != origin {
				t.Fatal("operand assignment was discarded")
			}
		})
	}
}

func TestPythonBooleanProjectionHonorsBudget(t *testing.T) {
	b, p, n := pythonExpressionFixture(t, "not value")
	b.ctx = analysisbudget.WithLimit(t.Context(), 1)
	got := b.eval(p, n, map[string]bundleValue{"value": {text: "ordinary", known: true}}, 0)
	if b.err == nil || got.remote != nil || got.known {
		t.Fatal("exhausted projection returned an asserted value")
	}
}

func TestPythonTextOperatorsDoNotInventExactValues(t *testing.T) {
	for _, tc := range []struct {
		expr  string
		exact bool
	}{
		{"'a' + 'book'", true},
		{"'%s' % 'book'", false},
	} {
		b, p, n := pythonExpressionFixture(t, tc.expr)
		got := b.eval(p, n, nil, 0)
		if b.err != nil || got.known != tc.exact || tc.exact && got.text != "abook" {
			t.Fatalf("expression %s: text=%q known=%t error=%v", tc.expr, got.text, got.known, b.err)
		}
		if !tc.exact && b.gap == nil {
			t.Fatal("unsupported formatting lost its partial state")
		}
	}
}

func TestPythonUnknownComparisonKeepsExplicitUncertainty(t *testing.T) {
	for _, expr := range []string{"value == other", "value != other"} {
		b, p, n := pythonExpressionFixture(t, expr)
		origin := &report.SourceRef{Path: "local-object-fixture.txt"}
		got := b.eval(p, n, map[string]bundleValue{"value": {remote: origin, remoteKind: 2}}, 0)
		if b.err != nil || b.gap == nil || got.remote != origin {
			t.Fatalf("unknown rich comparison lost uncertainty or possible origin: %+v, %v, %v", got, b.err, b.gap)
		}
	}

	b, p, n := pythonExpressionFixture(t, "not value")
	origin := &report.SourceRef{Path: "local-object-fixture.txt"}
	got := b.eval(p, n, map[string]bundleValue{"value": {remote: origin, remoteKind: 2, secret: origin}}, 0)
	if b.err != nil || b.gap != nil || got.remote != nil || got.secret != origin {
		t.Fatal("not must yield a boolean even for an unknown operand")
	}

	b, p, n = pythonExpressionFixture(t, "not value")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	b.ctx = ctx
	if got := b.eval(p, n, nil, 0); b.err == nil || got.known || got.remote != nil {
		t.Fatal("cancelled projection asserted a result")
	}
}

func pythonExpressionFixture(t *testing.T, expr string) (*bundleAnalysis, *bundleProgram, *bundleNode) {
	t.Helper()
	options := frontend.DefaultOptions()
	options.Python = true
	tree, err := frontend.Parse(t.Context(), options, language.Python, expr)
	if err != nil {
		t.Fatal(err)
	}
	body := tree.AST.List(frontend.Body)
	if len(body) != 1 || body[0].Kind() != frontend.Expr {
		t.Fatal("expected one expression")
	}
	view, err := source.NewView(expr, []source.Span{{Start: 0, End: len(expr)}})
	if err != nil {
		t.Fatal(err)
	}
	p := &bundleProgram{language: language.Python, unit: document.Unit{View: view}}
	b := &bundleAnalysis{ctx: t.Context()}
	return b, p, b.pythonNode(p, body[0].Child(frontend.FieldValue), 0)
}
