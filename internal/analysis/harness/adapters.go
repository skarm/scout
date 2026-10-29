package harness

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Read-only manifest and launcher grammar shared by harness captures.
var manifestFieldKinds = map[string]string{
	"name":           "string",
	"displayName":    "string",
	"version":        "string",
	"description":    "string",
	"homepage":       "string",
	"repository":     "string",
	"license":        "string",
	"defaultEnabled": "bool",
}

func (p *plugin) discover() {
	if p.host == "unknown" {
		p.issue("plugin_layout_unverified", p.manifest.meta.Path, report.OutcomePartial)
		return
	}

	var root *jsonconfig.Node
	if p.manifest != nil {
		root = p.object(p.manifest)
		if root != nil {
			p.validateManifest(root)
		}
	} else if p.host == report.HostCodex {
		p.issue("plugin_manifest_missing", "", "invalid")
	}
	// Defaults remain candidates even after malformed manifests. No inference
	// that an invalid declaration makes the rest of a package harmless.
	p.issue("plugin_loader_semantics_limited", p.manifestPath(), report.OutcomePartial)
	p.directory("skills", "skills", root, "skill", false)

	if p.host == report.HostClaudeCode {
		p.directory("commands", "commands", root, "command", true)
		p.directory("agents", "agents", root, "agent", true)
		p.directory("outputStyles", "output-styles", root, "instruction", true)
		p.directory("workflows", "workflows", root, "workflow", true)
	}

	p.rootSkill(root)

	p.configs("hooks", "hooks/hooks.json", "hook_config", root)
	p.configs("mcpServers", ".mcp.json", "mcp_config", root)

	if p.host == report.HostClaudeCode {
		p.configs("lspServers", ".lsp.json", "lsp_config", root)
	}

	if p.host == report.HostCodex {
		p.configs("apps", ".app.json", "app_config", root)
	}

	p.discoverHostConfigs()
	p.discoverExtensions(root)
}

func (p *plugin) rootSkill(root *jsonconfig.Node) {
	if e := p.entry("SKILL.md"); e != nil {
		act := p.activation
		if root.Get("skills") != nil || p.hasDirectory("skills") {
			act = "inactive_for_profile"
		}

		p.component("skill", e, act, "host_default", whole(e), "root-skill")
	}
}

func (p *plugin) discoverHostConfigs() {
	for _, name := range []string{"AGENTS.md", "CLAUDE.md", "settings.json", ".claude/settings.json", ".claude/settings.local.json", ".codex/config.toml", "agents/openai.yaml"} {
		if e := p.entry(name); e != nil {
			id := p.component("host_config", e, "unknown", "package_inventory", whole(e), name)
			if name == "settings.json" || strings.HasSuffix(name, "/settings.json") || strings.HasSuffix(name, "/settings.local.json") {
				if settings := p.object(e); settings != nil {
					p.settings(e, settings, id)
				}
			}

			p.issue("plugin_host_configuration_unverified", e.meta.Path, report.OutcomePartial)
		}
	}
}

func (p *plugin) discoverExtensions(root *jsonconfig.Node) {
	if root != nil {
		if deps := root.Get("dependencies"); deps != nil {
			for i, item := range deps.Elements {
				if !p.b.step() {
					break
				}

				src := ref(p.manifest, item.Span)
				id := p.component("dependency", p.manifest, p.activation, "manifest", src, fmt.Sprintf("dependency:%d", i))
				p.reference(id, "dependency", "unresolved", "external_dependency_not_materialized", "", src)
			}
		}

		for _, key := range []string{"experimental", "monitors", "themes", "channels", "extensions", "userConfig"} {
			if n := root.Get(key); n != nil {
				p.component("unsupported_extension", p.manifest, "unknown", "manifest", ref(p.manifest, n.Span), key)
				p.issue("plugin_extension_unverified", p.manifest.meta.Path, report.OutcomePartial)
			}
		}
	}
}

func (p *plugin) manifestPath() string {
	if p.manifest != nil {
		return p.manifest.meta.Path
	}

	return ""
}

func (p *plugin) validateManifest(n *jsonconfig.Node) {
	name, ok := n.Get("name").Text()
	if !ok || !validName(name) {
		p.issue("plugin_name_invalid", p.manifest.meta.Path, "invalid")
	}
	// Metadata values are never used as authority, IDs or output messages.
	known := map[string]bool{}
	for _, k := range []string{"name", "displayName", "version", "description", "author", "homepage", "repository", "license", "keywords", "metadata", "skills", "commands", "agents", "hooks", "mcpServers", "lspServers", "apps", "outputStyles", "workflows", "dependencies", "defaultEnabled", "experimental", "monitors", "themes", "channels", "extensions", "userConfig", "interface"} {
		known[k] = true
	}

	for _, m := range n.Members {
		if !p.b.step() {
			return
		}

		p.validateManifestMember(m, known[m.Key])
	}
}

func (p *plugin) validateManifestMember(m jsonconfig.Member, known bool) {
	if !known {
		p.issue("plugin_unknown_field", p.manifest.meta.Path, report.OutcomePartial)
	}

	if expected, typed := manifestFieldKinds[m.Key]; typed && m.Value.Kind != expected {
		p.issue("plugin_metadata_type_invalid", p.manifest.meta.Path, "invalid")
	}

	switch m.Key {
	case "keywords":
		if _, valid := stringValues(m.Value); !valid {
			p.issue("plugin_metadata_type_invalid", p.manifest.meta.Path, "invalid")
		}
	case "dependencies":
		if m.Value.Kind != jsonconfig.KindArray {
			p.issue("plugin_dependency_shape_unverified", p.manifest.meta.Path, report.OutcomePartial)
		}
	}
}

// stringValues validates array declarations used by keywords and argv forms.
// Absent argv is optional; non-array declarations never become valid argv.
func stringValues(n *jsonconfig.Node) ([]string, bool) {
	if n == nil {
		return nil, true
	}

	valid := n.Kind == jsonconfig.KindArray

	var values []string

	for _, item := range n.Elements {
		value, ok := item.Text()
		if !ok {
			valid = false
		}

		values = append(values, value)
	}

	return values, valid
}

func (p *plugin) component(kind string, e *entry, activation, basis string, s *report.SourceRef, salt string) string {
	if p.activation == "inactive_for_profile" {
		activation = p.activation
	}

	id := p.b.node(p.id, kind, e, p.host, activation, s, salt)
	p.b.edge(p.rootNode, id, "includes", basis, activation, s)

	return id
}

func (p *plugin) hasDirectory(name string) bool {
	return len(p.ns.descendants(path.Join(p.root, name))) != 0
}

func (p *plugin) directory(field, defaultName string, root *jsonconfig.Node, kind string, replace bool) {
	custom := root.Get(field)

	activation := p.activation
	if p.host == report.HostCodex {
		activation = "unknown"
	}

	if replace && custom != nil {
		activation = "inactive_for_profile"
	}

	p.selectFiles(defaultName, kind, activation, "host_default", nil, false)

	if custom == nil {
		return
	}

	for _, n := range pathValues(custom) {
		if !p.b.step() {
			return
		}

		if text, ok := n.Text(); ok {
			p.selectFiles(text, kind, p.activation, "manifest", ref(p.manifest, n.Span), true)
		} else {
			p.issue("plugin_component_path_type_invalid", p.manifestPath(), "invalid")
		}
	}

	if !slices.Contains([]string{"string", "array"}, custom.Kind) {
		p.issue("plugin_component_path_type_invalid", p.manifestPath(), "invalid")
	}
}

func (p *plugin) selectFiles(raw, kind, activation, basis string, s *report.SourceRef, required bool) {
	if p.activation == "inactive_for_profile" {
		activation = p.activation
	}

	rel, reason := localPath(raw, required)
	if reason != "" {
		p.reference(p.rootNode, "component_path", "unresolved", reason, "", s)
		return
	}

	name := path.Join(p.root, rel)
	found := false

	for _, key := range p.ns.selectNames(name) {
		if !p.b.step() {
			return
		}

		match := componentFileMatches(kind, key)

		if !match {
			continue
		}

		found = true

		p.selectedFile(key, name, kind, activation, basis, s)
	}

	if required && !found {
		p.reference(p.rootNode, "component_path", "unresolved", "missing_or_unsupported_component", "", s)
	}
}

func componentFileMatches(kind, key string) bool {
	switch kind {
	case "skill":
		return path.Base(key) == "SKILL.md"
	case "workflow":
		return true
	default:
		return strings.EqualFold(path.Ext(key), ".md")
	}
}

func (p *plugin) selectedFile(key, name, kind, activation, basis string, s *report.SourceRef) {
	e := p.ns.entries[key]
	effective := activation

	if nestedComponent(kind, key, name) {
		if effective != "inactive_for_profile" {
			effective = "unknown"
		}

		p.issue("nested_component_discovery_unverified", e.meta.Path, report.OutcomePartial)
	}

	id := p.component(kind, e, effective, basis, whole(e), "file")
	if s != nil {
		p.b.edge(p.rootNode, id, "declares", basis, effective, s)
	}

	if e.doc == nil {
		p.issue("plugin_input_unavailable", e.meta.Path, report.OutcomePartial)
	}

	if kind == "skill" || kind == "agent" {
		p.issue("component_frontmatter_unverified", e.meta.Path, report.OutcomePartial)
	}
}

func nestedComponent(kind, key, name string) bool {
	rest := strings.TrimPrefix(key, name+"/")
	if name == "." {
		rest = key
	}

	depth := strings.Count(rest, "/")
	if kind == "skill" {
		return depth > 1
	}

	return depth > 0 && key != name
}

func (p *plugin) configs(field, defaultName, kind string, root *jsonconfig.Node) {
	n := root.Get(field)

	def := p.entry(defaultName)
	if def != nil {
		activation := p.defaultConfigActivation(def, n, kind)

		p.configFile(def, kind, activation, "host_default", whole(def))
	}

	if n == nil {
		return
	}

	for i, item := range pathValues(n) {
		if !p.b.step() {
			return
		}

		s := ref(p.manifest, item.Span)
		if raw, ok := item.Text(); ok {
			p.declaredConfigFile(raw, kind, s)
		} else if item.Kind == jsonconfig.KindObject {
			id := p.component(kind, p.manifest, p.activation, "manifest", s, fmt.Sprintf("%s:inline:%d", field, i))
			p.inspectConfig(p.manifest, item, kind, id, p.activation)
		} else {
			p.issue("plugin_config_shape_invalid", p.manifestPath(), "invalid")
		}
	}
}

func (p *plugin) declaredConfigFile(raw, kind string, s *report.SourceRef) {
	rel, reason := localPath(raw, true)
	if reason != "" {
		p.reference(p.rootNode, "component_path", "unresolved", reason, "", s)
		return
	}

	e := p.entry(rel)
	if e == nil {
		p.reference(p.rootNode, "component_path", "unresolved", "missing_component", "", s)
		return
	}

	id := p.configFile(e, kind, p.activation, "manifest", s)
	if e.doc == nil {
		p.reference(p.rootNode, "component_path", "unresolved", "component_not_captured", "", s)
	} else {
		p.reference(p.rootNode, "component_path", "resolved", "captured_file", id, s)
	}
}

func (p *plugin) defaultConfigActivation(def *entry, n *jsonconfig.Node, kind string) string {
	activation := p.activation
	if p.host == report.HostCodex && n == nil && kind != "hook_config" {
		activation = "unknown"

		p.issue("plugin_default_config_activation_unverified", def.meta.Path, report.OutcomePartial)
	}

	if n != nil {
		if p.host == report.HostCodex {
			activation = "inactive_for_profile"
		} else {
			activation = "unknown"

			p.issue("plugin_config_merge_unverified", def.meta.Path, report.OutcomePartial)
		}
	}

	return activation
}

func (p *plugin) configFile(e *entry, kind, activation, basis string, s *report.SourceRef) string {
	if p.activation == "inactive_for_profile" {
		activation = p.activation
	}

	id := p.component(kind, e, activation, basis, whole(e), kind)
	if s != nil {
		p.b.edge(p.rootNode, id, "declares", basis, activation, s)
	}

	key := kind + "\x00" + e.meta.Path + "\x00" + activation
	if p.processedConfigs[key] {
		return id
	}

	p.processedConfigs[key] = true

	n := p.object(e)
	if n != nil {
		p.inspectConfig(e, n, kind, id, activation)
	}

	return id
}

func (p *plugin) inspectConfig(e *entry, n *jsonconfig.Node, kind, parent, activation string) {
	switch kind {
	case "hook_config":
		p.hooks(e, n, parent, activation)
	case "mcp_config", "lsp_config":
		p.servers(e, n, kind, parent, activation)
	default:
		p.issue("plugin_app_mapping_unverified", e.meta.Path, report.OutcomePartial)
	}
}

func (p *plugin) reference(component, kind, status, reason, target string, s *report.SourceRef) {
	if component == "" {
		return
	}

	if status == "resolved" && target == "" {
		status = "unresolved"
		reason = "component_graph_budget_exceeded"
	}

	if len(p.b.r.References) >= p.b.r.Limits.References {
		p.issue("plugin_reference_limit", "", report.OutcomePartial)
		return
	}

	encoded, file := "", ""
	if s != nil {
		encoded = fmt.Sprintf("%s:%d:%d", s.Path, s.ByteStart, s.ByteEnd)
		file = s.Path
	}

	id := identity("reference-v1", p.id, component, kind, status, reason, target, encoded)
	// Exact repeats may arise from a default config also explicitly declared.
	if p.b.references[id] {
		return
	}

	p.b.references[id] = true

	p.b.r.References = append(p.b.r.References, report.ComponentReference{
		ID:          id,
		PluginID:    p.id,
		ComponentID: component,
		Kind:        kind,
		Status:      status,
		Reason:      reason,
		TargetID:    target,
		Source:      s,
	})
	if status != "resolved" {
		p.issue("plugin_reference_unresolved", file, report.OutcomePartial)
	}
}

func validName(s string) bool { return textmatch.Slug(s, 128) }

func pathValues(n *jsonconfig.Node) []*jsonconfig.Node {
	if n == nil {
		return nil
	}

	if n.Kind == jsonconfig.KindArray {
		return n.Elements
	}

	return []*jsonconfig.Node{n}
}

// localPath accepts only portable paths. It never performs decoding, expansion,
// filesystem lookup or resolution against the scanner's working directory.
func localPath(raw string, requireDot bool) (string, string) {
	if raw == "" {
		return "", "empty_reference"
	}

	if strings.ContainsAny(raw, "\\:\x00\r\n\t") || strings.HasPrefix(raw, "/") {
		return "", "nonlocal_reference"
	}

	if strings.ContainsAny(raw, "$~*?[]{}") {
		return "", "symbolic_reference"
	}

	if requireDot && raw != "." && !strings.HasPrefix(raw, "./") {
		return "", "relative_prefix_required"
	}

	clean := path.Clean(raw)
	if strings.HasPrefix(clean+"/", "../") {
		return "", "outside_package"
	}

	return clean, ""
}
