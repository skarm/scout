package metadata_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/metadata"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestStructuredAgentDeclarationsAreSourceBoundAndUntrusted(t *testing.T) {
	text := `[{"role":"system","content":{"protocol":"AISOP V1","format":"json"}},{"role":"user","content":{"aisop":{"declared_tools":["SENSITIVE_TOOL_NAME"],"functions":{"run":{"constraints":["bounded"]}}}}}]`
	docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile(".aisop/work.aisop.json", []byte(text), false)})
	r := metadata.Collect(context.Background(), docs, "")
	if r.Completeness != report.Complete || len(r.Files) != 1 || r.Files[0].Format != "aisop" {
		t.Fatalf("%+v", r)
	}
	seen := map[string]bool{}
	for _, f := range r.Files[0].Fields {
		seen[f.Name] = true
		if f.Source.ByteStart < 0 || f.Source.ByteEnd > len(text) || f.ValueSHA256 == "" || f.Source.SpanSHA256 == "" {
			t.Fatal(f)
		}
	}
	if !seen["declared_tools"] || !seen["workflow_nodes"] {
		t.Fatal(seen)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "SENSITIVE_TOOL_NAME") {
		t.Fatal("source declaration leaked into report")
	}
	bad := strings.Replace(text, `"role":"system"`, `"role":"attacker"`, 1)
	r = metadata.Collect(context.Background(), document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("bad.aisop.json", []byte(bad), false)}), "")
	if r.Completeness != report.Partial {
		t.Fatal("invalid envelope certified")
	}
}
