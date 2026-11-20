package metadata //nolint:testpackage // Exercises private canonical hashing and skill schema validation.

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

func TestCollectManifestFieldsAndItemCompleteness(t *testing.T) {
	for _, tc := range []struct {
		field, value string
		complete     bool
		items        int
		issue        string
	}{
		{field: "permissions", value: `["read"," "]`, complete: true, items: 1, issue: ""},
		{field: "allowed-tools", value: `"Bash"`, complete: true, items: 1, issue: ""},
		{field: "permissions", value: `["read",1]`, complete: false, items: 1, issue: ""},
		{field: "triggers", value: `["start"]`, complete: true, items: 1, issue: ""},
		{field: "triggers", value: `"start"`, complete: true, items: 1, issue: "trigger_declaration_type_unverified"},
		{field: "triggers", value: `[1]`, complete: false, items: 0, issue: "trigger_declaration_type_unverified"},
		{field: "parameters", value: `{"x":{"type":"string"}}`, complete: true, items: 1, issue: ""},
		{field: "parameters", value: `[{"name":"x"},{"name":"x"}]`, complete: false, items: 2, issue: ""},
		{field: "parameters", value: `[{"type":"string"}]`, complete: false, items: 0, issue: ""},
		{field: "parameters", value: `false`, complete: false, items: 0, issue: ""},
		{field: "future", value: `"PRIVATE_SENTINEL"`, complete: false, items: 0, issue: "uninterpreted_field"},
	} {
		t.Run(tc.field+tc.value, func(t *testing.T) {
			text := `{"` + tc.field + `":` + tc.value + `}`
			files := []artifact.File{artifact.NewFile("plugin.json", []byte(text), false)}
			r := Collect(context.Background(), document.PrepareAll(context.Background(), files), "auto")
			if len(r.Files) != 1 {
				t.Fatal(r)
			}
			f := r.Files[0]
			if tc.issue != "" && !slices.Contains(f.Issues, tc.issue) {
				t.Fatal(f)
			}
			if tc.field != "future" {
				if len(f.Fields) != 1 || f.Fields[0].ItemsComplete != tc.complete || len(f.Fields[0].Items) != tc.items {
					t.Fatal(f)
				}
				ref := f.Fields[0].Source
				if ref.SpanSHA256 != artifact.Hash([]byte(text[ref.ByteStart:ref.ByteEnd])) {
					t.Fatal(ref)
				}
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "PRIVATE_SENTINEL") {
				t.Fatal("literal leaked")
			}
		})
	}
}

func TestSkillMetadataContracts(t *testing.T) {
	for _, tc := range []struct{ text, host, issue string }{
		{text: `{}`, host: "agent-skills", issue: "required_skill_fields_missing_or_wrong_type"},
		{text: `{}`, host: "claude-code", issue: ""},
		{text: `{"name":"Bad","description":"ok"}`, host: "agent-skills", issue: "skill_name_contract_invalid"},
		{text: `{"name":"two--dashes","description":"ok"}`, host: "auto", issue: "skill_name_contract_invalid"},
		{text: `{"name":"good","description":" "}`, host: "claude-code", issue: "skill_description_contract_invalid"},
		{text: `{"name":"good","description":1}`, host: "auto", issue: "required_skill_fields_missing_or_wrong_type"},
		{text: `{"disable-model-invocation":"true"}`, host: "claude-code", issue: "invocation_switch_type_invalid"},
		{text: `{"user-invocable":false}`, host: "claude-code", issue: ""},
		{text: `{"allowed-tools":["Bash","Read"]}`, host: "claude-code", issue: ""},
		{text: `{"allowed-tools":["Bash",1]}`, host: "claude-code", issue: "tool_declaration_type_unverified"},
		{text: `{"disallowed-tools":false}`, host: "claude-code", issue: "tool_declaration_type_unverified"},
		{text: `{"allowed-tools":["Bash"]}`, host: "agent-skills", issue: "tool_declaration_type_unverified"},
		{text: `{"allowed-tools":"Bash"}`, host: "claude-code", issue: ""},
	} {
		t.Run(tc.text+tc.host, func(t *testing.T) {
			f := report.MetadataFile{}
			validateSkill(metadataNode(t, tc.text), tc.host, &f)
			if tc.issue != "" && !slices.Contains(f.Issues, tc.issue) {
				t.Fatal(f)
			}
			if tc.issue == "" && len(f.Issues) > 0 {
				t.Fatal(f)
			}
		})
	}
	f := report.MetadataFile{}
	validateSkill(&jsonconfig.Node{
		Kind: "object",
		Members: []jsonconfig.Member{{
			Key: "description",
			Value: &jsonconfig.Node{
				Kind:   "string",
				String: strings.Repeat("界", 1025),
			},
		}},
	}, "claude-code", &f)
	if !slices.Contains(f.Issues, "skill_description_contract_invalid") {
		t.Fatal(f)
	}
}

func TestMetadataCancellationMissingFrontmatterAndCanonicalValues(t *testing.T) {
	docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("SKILL.md", []byte("instructions"), false)})
	for _, host := range []string{"claude-code", "agent-skills"} {
		r := Collect(context.Background(), docs, host)
		if len(r.Files) != 1 {
			t.Fatal(r)
		}
		if (r.Completeness == report.Partial) != (host == "agent-skills") {
			t.Fatal(r)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := Collect(ctx, docs, "auto"); r.Completeness != report.Partial || len(r.Files) != 0 {
		t.Fatal(r)
	}
	for _, pair := range [][2]string{{`{"b":2,"a":1}`, `{"a":1.0,"b":2e0}`}, {`[1e2,1e-2]`, `[100,0.01]`}} {
		if canonicalHash(metadataNode(t, pair[0])) != canonicalHash(metadataNode(t, pair[1])) {
			t.Fatal(pair)
		}
	}
	if canonicalHash(nil) == canonicalHash(metadataNode(t, `null`)) {
		t.Fatal("absent/null merged")
	}
	if canonicalHash(metadataNode(t, `[1,2]`)) == canonicalHash(metadataNode(t, `[2,1]`)) {
		t.Fatal("array order lost")
	}
	for _, value := range []string{"1e999999", "1e-5000", "bad", strings.Repeat("1", 257)} {
		if got := canonicalNumber("number", value); got != value {
			t.Fatalf("unbounded number %s changed to %s", value, got)
		}
	}
}

func TestOnlyVirtualMetadataPathsAreURLDecoded(t *testing.T) {
	for _, tc := range []struct {
		path        string
		frontmatter bool
	}{
		{path: "docs/%53KILL.md"},
		{path: "docs/SKILL.md", frontmatter: true},
		{path: report.ObjectPathPrefix + "fixture/SKILL.md", frontmatter: true},
		{path: report.ObjectPathPrefix + "fixture/%2553KILL.md"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			file := artifact.NewFile(tc.path, []byte("Ordinary documentation.\n"), false)
			docs := document.PrepareAll(t.Context(), []artifact.File{file})
			got := Collect(t.Context(), docs, report.HostAgentSkills)
			if tc.frontmatter {
				if got.Completeness != report.Partial || len(got.Files) != 1 || got.Files[0].Path != tc.path || got.Files[0].Status != "required_missing" {
					t.Fatalf("missing required frontmatter was lost: %+v", got)
				}
			} else if got.Completeness != report.Complete || len(got.Files) != 0 {
				t.Fatalf("literal percent escapes invented a skill: %+v", got)
			}
		})
	}
}

func TestYAMLExampleDoesNotSupplySkillFrontmatter(t *testing.T) {
	if !frontend.BackendFor("yaml").Available {
		t.Skip("YAML parser unavailable in this build")
	}
	options := frontend.DefaultOptions()
	options.YAML = true
	registry, err := parse.WithFrontends(options)
	if err != nil {
		t.Fatal(err)
	}
	const body = "# Instructions\n\n```yaml\nname: example\ndescription: Read sample values\n```\n"
	for _, tc := range []struct {
		name, header string
		want         report.Completeness
	}{
		{name: "missing", want: report.Partial},
		{name: "present", header: "---\nname: instructions\ndescription: Read a document\n---\n", want: report.Complete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := []artifact.File{artifact.NewFile("SKILL.md", []byte(tc.header+body), false)}
			docs := document.PrepareAllWithRegistry(t.Context(), files, registry)
			got := Collect(t.Context(), docs, report.HostAgentSkills)
			if got.Completeness != tc.want || len(got.Files) != 1 {
				t.Fatalf("expected one frontmatter record: %+v", got)
			}
			missing := slices.ContainsFunc(got.Files, func(f report.MetadataFile) bool { return f.Status == "required_missing" })
			if missing != (tc.header == "") {
				t.Fatalf("wrong frontmatter outcome: %+v", got.Files)
			}
		})
	}
}

func metadataNode(t *testing.T, text string) *jsonconfig.Node {
	t.Helper()
	n, err := jsonconfig.Parse(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
