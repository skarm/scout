package harness

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

const (
	fieldAgents          = "agents"
	fieldApps            = "apps"
	fieldArgs            = "args"
	fieldCommand         = "command"
	fieldCommands        = "commands"
	fieldDependencies    = "dependencies"
	fieldHooks           = "hooks"
	fieldLSPServers      = "lspServers"
	fieldMCPServers      = "mcpServers"
	fieldMCPServersSnake = "mcp_servers"
	fieldMatcher         = "matcher"
	fieldName            = "name"
	fieldOutputStyles    = "outputStyles"
	fieldPrompt          = "prompt"
	fieldSkills          = "skills"
	fieldType            = "type"
	fieldURL             = "url"
	fieldVersion         = "version"
	fieldWorkflows       = "workflows"
)

const (
	basisConfiguration    = "configuration"
	basisHookPayload      = "hook_payload"
	basisInlineShell      = "inline_shell"
	basisManifest         = "manifest"
	basisPackageInventory = "package_inventory"
	basisSettings         = "settings"
	basisStaticReference  = "static_reference"
)

const (
	relationDeclares  = "declares"
	relationIncludes  = "includes"
	relationInvokes   = "invokes"
	relationRegisters = "registers"
)

const (
	referenceKindCommand        = "command"
	referenceKindComponentPath  = "component_path"
	referenceKindDependency     = "dependency"
	referenceKindHandler        = "handler"
	referenceKindHookBehavior   = "hook_behavior"
	referenceKindRemoteEndpoint = "remote_endpoint"
	referenceKindRuntime        = "runtime"
)

const (
	maxManifestNameBytes = 128
	defaultHooksPath     = "hooks/hooks.json"
	componentLSPConfig   = "lsp_config"
)

//nolint:gochecknoglobals // Read-only manifest and launcher grammar shared by harness captures.
var manifestFieldKinds = map[string]string{
	fieldName:        "string",
	"displayName":    "string",
	fieldVersion:     "string",
	"description":    "string",
	"homepage":       "string",
	"repository":     "string",
	"license":        "string",
	"defaultEnabled": "bool",
}

func (p *plugin) discover() {
	if p.nativeWorkspace {
		p.discoverNativeWorkspace()
		return
	}

	if p.projectSettings {
		p.discoverHostConfig(artifact.ClaudeProjectSettings)
		p.discoverHostConfig(artifact.ClaudeProjectLocalSettings)

		return
	}

	if p.host == "unknown" {
		p.issue(issuePluginLayoutUnverified, p.manifest.Meta.Path, report.OutcomePartial)
		return
	}

	if p.host == report.HostGeminiCLI {
		p.discoverGeminiExtension()
		return
	}

	if p.host == report.HostOpenClaw {
		p.discoverOpenClawPackage()
		return
	}

	if p.portable != "" {
		p.discoverPortable()
		return
	}

	if p.host == report.HostGrokCLI {
		p.discoverGrokPackage()
		return
	}

	if p.host == report.HostQwenCode {
		p.discoverQwenExtension()
		return
	}

	if p.host == report.HostZCode {
		p.discoverZCodePackage()
		return
	}

	if p.host == report.HostCursor || p.host == report.HostCopilotCLI {
		p.discoverNativePackage()
		return
	}

	var root *jsonconfig.Node
	if p.manifest != nil {
		root = p.object(p.manifest)
		if root != nil {
			p.validateManifest(root)
		}
	} else if p.host == report.HostCodex {
		p.issue(issuePluginManifestMissing, "", formatInvalid)
	}
	// Defaults remain candidates even after malformed manifests. No inference
	// that an invalid declaration makes the rest of a package harmless.
	p.issue(issuePluginLoaderSemanticsLimited, p.manifestPath(), report.OutcomePartial)
	p.directory(fieldSkills, "skills", root, report.ComponentSkill, false)

	if p.host == report.HostClaudeCode {
		p.directory(fieldCommands, "commands", root, componentCommand, true)
		p.directory(fieldAgents, "agents", root, componentAgent, true)
		p.directory(fieldOutputStyles, "output-styles", root, componentInstruction, true)
		p.directory(fieldWorkflows, "workflows", root, componentWorkflow, true)
	}

	p.rootSkill(root)

	p.configs(fieldHooks, defaultHooksPath, report.ComponentHookConfig, root)
	p.configs(fieldMCPServers, artifact.MCPConfig, report.ComponentMCPConfig, root)

	if p.host == report.HostClaudeCode {
		p.configs(fieldLSPServers, ".lsp.json", componentLSPConfig, root)
	}

	if p.host == report.HostCodex {
		p.configs(fieldApps, ".app.json", componentAppConfig, root)
	}

	p.discoverHostConfigs()
	p.discoverExtensions(root)
}

func (p *plugin) rootSkill(root *jsonconfig.Node) {
	if e := p.entry(artifact.SkillManifest); e != nil {
		act := p.activation
		if root.Get(fieldSkills) != nil || p.HasDirectory("skills") {
			act = activationInactiveForProfile
		}

		p.component(report.ComponentSkill, e, act, selectionHostDefault, whole(e), "root-skill")
	}
}

func (p *plugin) discoverHostConfigs() {
	for _, name := range []string{"AGENTS.md", "CLAUDE.md", artifact.ClaudeSettings, artifact.ClaudeProjectSettings, artifact.ClaudeProjectLocalSettings, ".codex/config.toml", "agents/openai.yaml"} {
		p.discoverHostConfig(name)
	}
}

func (p *plugin) discoverHostConfig(name string) {
	e := p.entry(name)
	if e == nil {
		return
	}

	id := p.component(componentHostConfig, e, activationUnknown, basisPackageInventory, whole(e), name)
	if name == artifact.ClaudeSettings || strings.HasSuffix(name, "/settings.json") || strings.HasSuffix(name, "/settings.local.json") {
		if settings := p.object(e); settings != nil {
			p.settings(e, settings, id)
		}
	}

	p.issue(issuePluginHostConfigurationUnverified, e.Meta.Path, report.OutcomePartial)
}

func (p *plugin) discoverExtensions(root *jsonconfig.Node) {
	if root != nil {
		if deps := root.Get(fieldDependencies); deps != nil {
			for i, item := range deps.Elements {
				if !p.b.step() {
					break
				}

				src := ref(p.manifest, item.Span)
				id := p.component(componentDependency, p.manifest, p.activation, basisManifest, src, fmt.Sprintf("dependency:%d", i))
				p.reference(id, referenceKindDependency, report.ReferenceUnresolved, reasonExternalDependencyNotMaterialized, "", src)
			}
		}

		for _, key := range []string{"experimental", "monitors", "themes", "channels", "extensions", "userConfig"} {
			if n := root.Get(key); n != nil {
				p.component(componentUnsupportedExtension, p.manifest, activationUnknown, basisManifest, ref(p.manifest, n.Span), key)
				p.issue(issuePluginExtensionUnverified, p.manifest.Meta.Path, report.OutcomePartial)
			}
		}
	}
}

func (p *plugin) manifestPath() string {
	if p.manifest != nil {
		return p.manifest.Meta.Path
	}

	return ""
}

func (p *plugin) validateManifest(n *jsonconfig.Node) {
	name, ok := n.Get(fieldName).Text()
	if !ok || !validName(name) {
		p.issue(issuePluginNameInvalid, p.manifest.Meta.Path, formatInvalid)
	}
	// Metadata values are never used as authority, IDs or output messages.
	known := map[string]bool{}
	for _, k := range []string{fieldName, "displayName", fieldVersion, "description", "author", "homepage", "repository", "license", "keywords", "metadata", fieldSkills, fieldCommands, fieldAgents, fieldHooks, fieldMCPServers, fieldLSPServers, fieldApps, fieldOutputStyles, fieldWorkflows, fieldDependencies, "defaultEnabled", "experimental", "monitors", "themes", "channels", "extensions", "userConfig", "interface"} {
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
		p.issue(issuePluginUnknownField, p.manifest.Meta.Path, report.OutcomePartial)
	}

	if expected, typed := manifestFieldKinds[m.Key]; typed && m.Value.Kind != expected {
		p.issue(issuePluginMetadataTypeInvalid, p.manifest.Meta.Path, formatInvalid)
	}

	switch m.Key {
	case "keywords":
		if _, valid := stringValues(m.Value); !valid {
			p.issue(issuePluginMetadataTypeInvalid, p.manifest.Meta.Path, formatInvalid)
		}
	case fieldDependencies:
		if m.Value.Kind != jsonconfig.KindArray {
			p.issue(issuePluginDependencyShapeUnverified, p.manifest.Meta.Path, report.OutcomePartial)
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
	if p.activation == activationInactiveForProfile {
		activation = p.activation
	}

	id := p.b.node(p.id, kind, e, p.host, activation, s, salt)
	p.b.edge(p.rootNode, id, relationIncludes, basis, activation, s)

	return id
}

func (p *plugin) HasDirectory(name string) bool {
	return len(p.ns.descendants(path.Join(p.root, name))) != 0
}

func (p *plugin) directory(field, defaultName string, root *jsonconfig.Node, kind string, replace bool) {
	custom := root.Get(field)

	activation := p.activation
	if p.host == report.HostCodex {
		activation = activationUnknown
	}

	if replace && custom != nil {
		activation = activationInactiveForProfile
	}

	p.selectFiles(defaultName, kind, activation, selectionHostDefault, nil, false)

	if custom == nil {
		return
	}

	for _, n := range pathValues(custom) {
		if !p.b.step() {
			return
		}

		if text, ok := n.Text(); ok {
			p.selectFiles(text, kind, p.activation, basisManifest, ref(p.manifest, n.Span), true)
		} else {
			p.issue(issuePluginComponentPathTypeInvalid, p.manifestPath(), formatInvalid)
		}
	}

	if !slices.Contains([]string{"string", "array"}, custom.Kind) {
		p.issue(issuePluginComponentPathTypeInvalid, p.manifestPath(), formatInvalid)
	}
}

func (p *plugin) selectFiles(raw, kind, activation, basis string, s *report.SourceRef, required bool) {
	if p.activation == activationInactiveForProfile {
		activation = p.activation
	}

	rel, reason := artifactpath.Reference(raw, required && !p.nativePaths())
	if required && rel == "." && p.nativePaths() {
		reason = reasonMissingOrUnsupportedComponent
	}

	if reason != "" {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reason, "", s)
		return
	}

	name := path.Join(p.root, rel)
	found := false

	for _, key := range p.ns.selectNames(name) {
		if !p.b.step() {
			return
		}

		if p.excludeNestedComponent(kind, key, name) {
			continue
		}

		match := p.componentFileMatches(kind, key)

		if !match {
			continue
		}

		found = true

		p.selectedFile(key, name, kind, activation, basis, s)
	}

	if required && !found {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingOrUnsupportedComponent, "", s)
	}
}

func (p *plugin) excludeNestedComponent(kind, key, dir string) bool {
	switch p.host {
	case report.HostZCode:
		return kind == report.ComponentSkill && nestedComponent(kind, key, dir)
	case report.HostQwenCode:
		return (kind == report.ComponentSkill || kind == componentWorkflow) && nestedComponent(kind, key, dir) ||
			kind == report.ComponentSkill && (path.Dir(key) == dir || key == dir)
	default:
		return false
	}
}

func (p *plugin) componentFileMatches(kind, key string) bool {
	switch kind {
	case report.ComponentSkill:
		return path.Base(key) == artifact.SkillManifest
	case componentWorkflow:
		return p.host != report.HostGrokCLI && p.host != report.HostQwenCode || agentconfig.InstructionFile(p.host, kind, key)
	default:
		return agentconfig.InstructionFile(p.host, kind, key)
	}
}

func (p *plugin) selectedFile(key, name, kind, activation, basis string, s *report.SourceRef) {
	e := p.ns.entries[key]
	effective := activation

	supportsNested := (p.host == report.HostGeminiCLI || p.host == report.HostQwenCode) && kind == componentCommand ||
		p.host == report.HostQwenCode && kind == componentRule ||
		p.host == report.HostOpenClaw && kind == report.ComponentSkill
	if !supportsNested && nestedComponent(kind, key, name) {
		if effective != activationInactiveForProfile {
			effective = "unknown"
		}

		p.issue(issueNestedComponentDiscoveryUnverified, e.Meta.Path, report.OutcomePartial)
	}

	id := p.component(kind, e, effective, basis, whole(e), "file")
	if s != nil {
		p.b.edge(p.rootNode, id, relationDeclares, basis, effective, s)
	}

	if e.Doc == nil {
		p.issue(issuePluginInputUnavailable, e.Meta.Path, report.OutcomePartial)
	}

	if kind == report.ComponentSkill || kind == "agent" {
		p.issue(issueComponentFrontmatterUnverified, e.Meta.Path, report.OutcomePartial)
	}
}

func nestedComponent(kind, key, name string) bool {
	rest := strings.TrimPrefix(key, name+"/")
	if name == "." {
		rest = key
	}

	depth := strings.Count(rest, "/")
	if kind == report.ComponentSkill {
		return depth > 1
	}

	return depth > 0 && key != name
}

func (p *plugin) configs(field, defaultName, kind string, root *jsonconfig.Node) {
	p.configsFrom(field, defaultName, kind, p.manifest, root.Get(field))
}

func (p *plugin) configsFrom(field, defaultName, kind string, source *entry, n *jsonconfig.Node) {
	def := p.entry(defaultName)
	if def != nil {
		activation := p.defaultConfigActivation(def, n, kind)

		p.configFile(def, kind, activation, selectionHostDefault, whole(def))
	}

	if n == nil {
		return
	}

	for i, item := range pathValues(n) {
		if !p.b.step() {
			return
		}

		s := ref(source, item.Span)
		if raw, ok := item.Text(); ok {
			p.declaredConfigFile(raw, kind, s)
		} else if item.Kind == jsonconfig.KindObject {
			id := p.component(kind, source, p.activation, basisManifest, s, fmt.Sprintf("%s:inline:%d", field, i))
			p.inspectConfig(source, item, kind, id, p.activation)
		} else {
			p.issue(issuePluginConfigShapeInvalid, source.Meta.Path, formatInvalid)
		}
	}
}

func (p *plugin) declaredConfigFile(raw, kind string, s *report.SourceRef) {
	rel, reason := artifactpath.Reference(raw, !p.nativePaths())
	if reason != "" {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reason, "", s)
		return
	}

	e := p.entry(rel)
	if e == nil {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingComponent, "", s)
		return
	}

	if p.b.hookTracer != nil && kind == report.ComponentHookConfig && e.Doc != nil {
		*e.Doc = e.Doc.WithDeclaredHookShell(p.b.ctx)
	}

	id := p.configFile(e, kind, p.activation, basisManifest, s)
	if e.Doc == nil {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, report.ReferenceReasonComponentNotCaptured, "", s)
	} else {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceResolved, reasonCapturedFile, id, s)
	}
}

func (p *plugin) defaultConfigActivation(def *entry, n *jsonconfig.Node, kind string) string {
	activation := p.activation
	if p.host == report.HostZCode && kind == report.ComponentHookConfig {
		return activation
	}

	if p.host == report.HostCodex && n == nil && kind != report.ComponentHookConfig {
		activation = activationUnknown

		p.issue(issuePluginDefaultConfigActivationUnverified, def.Meta.Path, report.OutcomePartial)
	}

	if n != nil {
		if p.host == report.HostCodex || p.host == report.HostCursor {
			activation = activationInactiveForProfile
		} else {
			activation = activationUnknown

			p.issue(issuePluginConfigMergeUnverified, def.Meta.Path, report.OutcomePartial)
		}
	}

	return activation
}

func (p *plugin) configFile(e *entry, kind, activation, basis string, s *report.SourceRef) string {
	if p.activation == activationInactiveForProfile {
		activation = p.activation
	}

	id := p.component(kind, e, activation, basis, whole(e), kind)
	if s != nil {
		p.b.edge(p.rootNode, id, relationDeclares, basis, activation, s)
	}

	key := kind + "\x00" + e.Meta.Path + "\x00" + activation
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
	case report.ComponentHookConfig:
		switch p.host {
		case report.HostCursor, report.HostCopilotCLI:
			p.nativeHooks(e, n, parent, activation)
		case report.HostZCode:
			p.zcodeHooks(e, n, parent, activation)
		default:
			p.hooks(e, n, parent, activation)
		}
	case report.ComponentMCPConfig, componentLSPConfig:
		p.servers(e, n, kind, parent, activation)
	default:
		p.issue(issuePluginAppMappingUnverified, e.Meta.Path, report.OutcomePartial)
	}
}

func (p *plugin) reference(component, kind, status, reason, target string, s *report.SourceRef) {
	if component == "" {
		return
	}

	if status == report.ReferenceResolved && target == "" {
		status = report.ReferenceUnresolved
		reason = "component_graph_budget_exceeded"
	}

	if len(p.b.r.References) >= p.b.r.Limits.References {
		p.issue(issuePluginReferenceLimit, "", report.OutcomePartial)
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
	if status != report.ReferenceResolved {
		p.issue(issuePluginReferenceUnresolved, file, report.OutcomePartial)
	}
}

func validName(s string) bool { return textmatch.Slug(s, maxManifestNameBytes) }

func pathValues(n *jsonconfig.Node) []*jsonconfig.Node {
	if n == nil {
		return nil
	}

	if n.Kind == jsonconfig.KindArray {
		return n.Elements
	}

	return []*jsonconfig.Node{n}
}
