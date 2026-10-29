// Package metadata records parsed skill/agent metadata separately from security
// findings. A valid document is not trusted policy or proof of loader activation.
package metadata

import (
	"context"
	"net/url"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

const maxMetadataRecords = 512

const valueTriggers = "triggers"

func Collect(ctx context.Context, docs []document.File, host string) report.MetadataReport {
	r := report.MetadataReport{
		Files:        []report.MetadataFile{},
		Completeness: report.Complete,
		Limitations:  []string{"Syntax and selected frontmatter types only; no complete harness schema, settings precedence, environment interpolation or effective permission guarantee.", "YAML aliases, merges, custom tags and multiple documents are explicitly rejected by the selected parser profile. TOML evidence is whole-unit, not per-token.", "Name/description values are hashed, not copied into reports; existence of a declaration does not establish author trust."},
	}

	for _, d := range docs {
		if ctx.Err() != nil {
			r.Completeness = report.Partial
			break
		}

		if !collectFile(d, host, &r) {
			return r
		}
	}

	return r
}

func collectFile(d document.File, host string, r *report.MetadataReport) bool {
	if handled, proceed := collectStructured(d, r); handled {
		return proceed
	}

	name := d.Artifact().Metadata().Path
	if p, e := url.PathUnescape(name); e == nil {
		name = p
	}

	isSkill := strings.EqualFold(path.Base(name), "SKILL.md")
	isManifest := slices.Contains([]string{"plugin.json", "manifest.json", "skill.json"}, path.Base(name))
	found := false

	for _, u := range d.Units() {
		if !metadataUnit(u, isManifest) {
			continue
		}

		if !admitRecord(r) {
			return false
		}

		found = true

		f := collectUnit(d, u, isSkill, host)
		if len(f.Issues) > 0 {
			r.Completeness = report.Partial
		}

		r.Files = append(r.Files, f)
	}

	if isSkill && !found {
		if !admitRecord(r) {
			return false
		}

		status := "not_declared"

		if host == report.HostAgentSkills {
			r.Completeness = report.Partial
			status = "required_missing"
		}

		r.Files = append(r.Files, report.MetadataFile{
			Path:   d.Artifact().Metadata().Path,
			Format: "frontmatter",
			Status: status,
			Fields: []report.MetadataField{},
			Issues: []string{"no_parsed_frontmatter_not_a_loader_validation"},
		})
	}

	return true
}

func admitRecord(r *report.MetadataReport) bool {
	if len(r.Files) >= maxMetadataRecords {
		r.Completeness = report.Partial
		return false
	}

	return true
}

func metadataUnit(u document.Unit, manifest bool) bool {
	return u.Origin == "frontmatter" || slices.Contains([]string{"yaml", "toml"}, u.Language) || (manifest && u.Language == language.JSON)
}

func collectUnit(d document.File, u document.Unit, isSkill bool, host string) report.MetadataFile {
	f := report.MetadataFile{
		Path:          d.Artifact().Metadata().Path,
		Format:        u.Language,
		Status:        u.Status,
		Parser:        u.ParserID,
		ParserVersion: u.ParserVersion,
		Fields:        []report.MetadataField{},
		Issues:        []string{},
	}

	t, ok := u.Tree.(parse.JSONTree)
	if !ok || t.Root == nil || t.Root.Kind != jsonconfig.KindObject {
		f.Issues = append(f.Issues, "metadata_mapping_unavailable")
		return f
	}

	f.Status = "parsed_subset"
	collectFields(d, u, t.Root, &f)

	if isSkill && u.Origin == "frontmatter" {
		validateSkill(t.Root, host, &f)
	}

	return f
}

func collectFields(d document.File, u document.Unit, root *jsonconfig.Node, f *report.MetadataFile) {
	for _, m := range root.Members {
		known := slices.Contains([]string{"parameters", "name", "description", "triggers", "permissions", "license", "compatibility", "metadata", "allowed-tools", "disallowed-tools", "disable-model-invocation", "user-invocable", "context", "agent", "model", "hooks", "policy", "interface", "dependencies", "approval_policy", "sandbox_mode", "mcp_servers", "mcpServers"}, m.Key)
		if m.Key == valueTriggers && !stringArray(m.Value) {
			f.Issues = append(f.Issues, "trigger_declaration_type_unverified")
		}

		if !known {
			f.Issues = append(f.Issues, "uninterpreted_field")
			continue
		}

		at, e := u.View.Original(m.Value.Span)
		if e != nil {
			f.Issues = append(f.Issues, "source_mapping_failed")
			continue
		}

		raw := d.Artifact().Content()
		meta := d.Artifact().Metadata()

		field := report.MetadataField{
			Name:        m.Key,
			Kind:        m.Value.Kind,
			ValueSHA256: canonicalHash(m.Value),
			Source: report.SourceRef{
				Path:       meta.Path,
				SHA256:     meta.SHA256,
				ByteStart:  at.Start,
				ByteEnd:    at.End,
				SpanSHA256: artifact.Hash([]byte(raw[at.Start:at.End])),
			},
		}
		if slices.Contains([]string{"permissions", "allowed-tools", valueTriggers}, m.Key) {
			collectListItems(m.Value, &field)
		}

		if m.Key == "parameters" {
			collectParameters(m.Value, &field)
		}

		f.Fields = append(f.Fields, field)
	}
}

func collectListItems(n *jsonconfig.Node, field *report.MetadataField) {
	field.ItemsComplete = n.Kind == jsonconfig.KindArray || n.Kind == jsonconfig.KindString

	items := n.Elements
	if n.Kind == jsonconfig.KindString {
		items = []*jsonconfig.Node{n}
	}

	for _, item := range items {
		if item.Kind != jsonconfig.KindString {
			field.ItemsComplete = false
			continue
		}

		if strings.TrimSpace(item.String) == "" {
			continue
		}

		hash := canonicalHash(item)
		field.Items = append(field.Items, report.MetadataItem{NameSHA256: hash, ValueSHA256: hash})
	}
}

func collectParameters(n *jsonconfig.Node, field *report.MetadataField) {
	seenParameters := map[string]bool{}

	field.ItemsComplete = n.Kind == jsonconfig.KindObject || n.Kind == jsonconfig.KindArray
	for _, item := range n.Members {
		field.Items = append(field.Items, report.MetadataItem{
			NameSHA256:  artifact.Hash([]byte(item.Key)),
			ValueSHA256: canonicalHash(item.Value),
		})
	}

	for _, item := range n.Elements {
		n, ok := item.Get("name").Text()
		if !ok {
			field.ItemsComplete = false
			continue
		}

		if seenParameters[n] {
			field.ItemsComplete = false
		}

		seenParameters[n] = true
		field.Items = append(field.Items, report.MetadataItem{
			NameSHA256:  artifact.Hash([]byte(n)),
			ValueSHA256: canonicalHash(item),
		})
	}
}

func validateSkill(root *jsonconfig.Node, host string, f *report.MetadataFile) {
	validateSkillIdentity(root, host, f)

	for _, key := range []string{"disable-model-invocation", "user-invocable"} {
		if v := root.Get(key); v != nil && v.Kind != jsonconfig.KindBool {
			f.Issues = append(f.Issues, "invocation_switch_type_invalid")
		}
	}

	for _, key := range []string{"allowed-tools", "disallowed-tools"} {
		validateTools(root.Get(key), host, f)
	}
}

func validateSkillIdentity(root *jsonconfig.Node, host string, f *report.MetadataFile) {
	if host != report.HostClaudeCode && !requiredSkillFields(root) {
		f.Issues = append(f.Issues, "required_skill_fields_missing_or_wrong_type")
	}

	for _, rule := range []struct {
		name, issue string
		valid       func(string) bool
	}{
		{
			name:  "name",
			issue: "skill_name_contract_invalid",
			valid: func(s string) bool { return textmatch.Slug(s, 64) && !strings.Contains(s, "--") },
		},
		{
			name:  "description",
			issue: "skill_description_contract_invalid",
			valid: func(s string) bool { return utf8.RuneCountInString(s) <= 1024 && strings.TrimSpace(s) != "" },
		},
	} {
		if value, ok := root.Get(rule.name).Text(); ok && !rule.valid(value) {
			f.Issues = append(f.Issues, rule.issue)
		}
	}
}

func requiredSkillFields(root *jsonconfig.Node) bool {
	name, nok := root.Get("name").Text()
	description, dok := root.Get("description").Text()

	return nok && name != "" && dok && strings.TrimSpace(description) != ""
}

func stringArray(n *jsonconfig.Node) bool {
	valid := n.Kind == jsonconfig.KindArray
	for _, item := range n.Elements {
		if item.Kind != jsonconfig.KindString {
			valid = false
		}
	}

	return valid
}

func validateTools(v *jsonconfig.Node, host string, f *report.MetadataFile) {
	if v == nil {
		return
	}

	valid := v.Kind == jsonconfig.KindString || (host == report.HostClaudeCode && stringArray(v))
	if !valid {
		f.Issues = append(f.Issues, "tool_declaration_type_unverified")
	}
}
