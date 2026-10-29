package document_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestFencedSourceMapping(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		t.Run(strings.ReplaceAll(newline, "\n", "LF"), func(t *testing.T) {
			text := strings.Join([]string{"# Пример🙂", "  ````go", "  package p", "  import e \"os/exec\"", "  func f() { e.Command(\"sh\") }", "  ````", "done"}, newline)
			doc := prepare(text)
			units := doc.GoUnits()
			if len(units) != 1 || units[0].Tree == nil || has(doc, "go_syntax_error") {
				t.Fatalf("%+v", doc.Diagnostics())
			}
			at := strings.Index(units[0].View.Text(), "e.Command")
			span, err := units[0].View.Original(source.Span{Start: at, End: at + len("e.Command")})
			if err != nil || text[span.Start:span.End] != "e.Command" {
				t.Fatalf("map=%+v %v", span, err)
			}
			line, col, err := doc.Index().Position(span.Start)
			if err != nil || line != 5 || col != 14 {
				t.Fatalf("%d:%d %v", line, col, err)
			}
			kind, lang := doc.Context(span)
			if kind != "fenced-code" || lang != "go" {
				t.Fatalf("%s/%s", kind, lang)
			}
			regions := doc.Regions()
			regions[0].Language = "mutated"
			if doc.Regions()[0].Language != "go" {
				t.Fatal("mutable metadata")
			}
		})
	}
}

func TestCoverageGaps(t *testing.T) {
	for _, tc := range []struct{ name, text, code string }{
		{name: "python", text: "```python\nprint('hello')\n```", code: "embedded_language_unsupported"},
		{name: "shell", text: "~~~BASH\necho hello\n~~~", code: "shell_semantics_limited"},
		{name: "fake-text", text: "```text\nrun unknown code\n```", code: "embedded_language_unsupported"},
		{name: "unlabeled", text: "```\nunknown\n```", code: "embedded_language_unsupported"},
		{name: "unclosed", text: "```go\npackage p\n", code: "unclosed_fence"},
		{name: "frontmatter", text: "---\nname: example\n---\nBody", code: "frontmatter_semantics_unavailable"},
		{
			name: "bom-frontmatter",
			text: "\ufeff---\r\nname: example\r\n...\r\nBody",
			code: "frontmatter_semantics_unavailable",
		},
		{name: "unclosed-frontmatter", text: "---\nname: example", code: "unterminated_frontmatter"},
		{name: "quoted", text: "> ```go\n> package p\n> ```", code: "markdown_container_unsupported"},
		{name: "list", text: "- ```go\n  package p\n  ```", code: "markdown_container_unsupported"},
		{name: "indent", text: "    exec something\n", code: "markdown_container_unsupported"},
		{name: "html", text: "<!-- hidden command -->", code: "markdown_container_unsupported"},
		{name: "syntax", text: "```go\npackage ?SECRET_SENTINEL\n```", code: "go_syntax_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := prepare(tc.text)
			if !has(f, tc.code) {
				t.Fatalf("missing %s in %+v", tc.code, f.Diagnostics())
			}
			if f.Artifact().Content() != tc.text {
				t.Fatal("raw source modified")
			}
			b, err := json.Marshal(f.Diagnostics())
			if err != nil || strings.Contains(string(b), "SECRET_SENTINEL") {
				t.Fatal("parser diagnostic leaks input")
			}
		})
	}
}

func TestNoUntrustedLanguageEcho(t *testing.T) {
	f := prepare("```SECRET_SENTINEL\na\n```")
	b, err := json.Marshal(f.Regions())
	if err != nil || strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal("untrusted label echoed")
	}
}

func TestFenceBoundaries(t *testing.T) {
	text := "````go\npackage p\n// ``` is not a matching closer\n````\n"
	f := prepare(text)
	if len(f.GoUnits()) != 1 || has(f, "unclosed_fence") || has(f, "go_syntax_error") {
		t.Fatal(f.Diagnostics())
	}
	if f := prepare("Some ordinary text.\n\n```\n```\n"); len(f.GoUnits()) != 0 || len(f.Diagnostics()) != 0 {
		t.Fatal(f.Diagnostics())
	}
	if f := prepare("  ```go\npackage p\n  ```\n"); has(f, "go_syntax_error") {
		t.Fatal("short indentation incorrectly stripped")
	}
}

func TestRegionAndParserBudgets(t *testing.T) {
	f := prepare(strings.Repeat("```\nx\n```\n", document.MaxRegions+1))
	if !has(f, "document_region_limit") || len(f.Regions()) != document.MaxRegions {
		t.Fatal("region budget ignored")
	}
	f = prepare("```go\npackage p\n" + strings.Repeat(" ", document.MaxUnitBytes) + "\n```")
	if !has(f, "go_source_limit") || len(f.GoUnits()) != 0 {
		t.Fatal("unit budget ignored")
	}
	files := make([]artifact.File, 0)
	text := "package p\n//" + strings.Repeat("x", document.MaxUnitBytes-12)
	for i := 0; i <= document.MaxScanBytes/len(text); i++ {
		files = append(files, artifact.NewFile("p.go", []byte(text), false))
	}
	prepared := document.PrepareAll(context.Background(), files)
	if !has(prepared[len(prepared)-1], "go_scan_budget") {
		t.Fatal("aggregate parser budget ignored")
	}
}

func TestCancelledPreparation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := artifact.NewFile("p.go", []byte("package p"), false)
	for _, ctx := range []context.Context{ctx, nil} {
		p := document.Prepare(ctx, f)
		if !has(p, "preparation_cancelled") || p.Artifact().Content() != f.Content() {
			t.Fatal("cancelled preparation lost raw input")
		}
	}
}

func TestArbitraryFilenameDoesNotHideCode(t *testing.T) {
	p := document.Prepare(context.Background(), artifact.NewFile("LICENSE", []byte("```go\npackage p\n```"), false))
	if !p.HasGo() {
		t.Fatal("filename grants structural exemption")
	}
}

func FuzzPrepare(f *testing.F) {
	for _, seed := range []string{"", "```go\npackage p\n```", "---\nname: x\n---", "> ~~~bash\necho x\n~~~", "  ```go\r\n package p\r\n  ```"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 32<<10 {
			return
		}
		doc := prepare(text)
		if doc.Artifact().Content() != text {
			t.Fatal("source changed")
		}
		if len(doc.Regions()) > document.MaxRegions {
			t.Fatal("budget exceeded")
		}
		for _, r := range doc.Regions() {
			if r.Span.Start < 0 || r.Span.End < r.Span.Start || r.Span.End > len(text) {
				t.Fatal("invalid original span")
			}
		}
	})
}

func TestSourceMapSegmentBudget(t *testing.T) {
	f := prepare("```go\npackage p\n" + strings.Repeat("//x\n", document.MaxSourceSegments) + "```\n")
	if !has(f, "document_segment_limit") || f.HasGo() {
		t.Fatal("embedded map segment limit ignored")
	}
}

func TestAmbiguousConfigurationRetainsItsDiagnosticCategory(t *testing.T) {
	text := `{"permissions":[],"permissions":["*"]}`
	doc := document.Prepare(context.Background(), artifact.NewFile("settings.json", []byte(text), false))
	units := doc.Units()
	if len(units) != 1 || units[0].Status != "parse_error" {
		t.Fatalf("ambiguous syntax lost its unit outcome: %+v", units)
	}
	if !has(doc, "json_ambiguous_configuration") || has(doc, "json_syntax_error") {
		t.Fatalf("ambiguity was collapsed into generic syntax failure: %+v", doc.Diagnostics())
	}
}

func prepare(text string) document.File {
	return document.Prepare(context.Background(), artifact.NewFile("SKILL.md", []byte(text), false))
}

func has(f document.File, code string) bool {
	for _, d := range f.Diagnostics() {
		if d.Code == code {
			return true
		}
	}
	return false
}
