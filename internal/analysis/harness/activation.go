package harness

import (
	"fmt"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/hooktrace"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/syntax/hookevent"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const (
	reasonCapturedFile                        = "captured_file"
	reasonCapturedHandlerNotRuntimeProof      = "captured_handler_not_runtime_proof"
	reasonCapturedInlineShell                 = "captured_inline_shell"
	reasonComplexShellCommand                 = "complex_shell_command"
	reasonDynamicCommand                      = "dynamic_command"
	reasonExternalDependencyNotMaterialized   = "external_dependency_not_materialized"
	reasonInvalidCommandBytes                 = "invalid_command_bytes"
	reasonMissingComponent                    = "missing_component"
	reasonMissingOrUnsupportedComponent       = "missing_or_unsupported_component"
	reasonRemoteBehaviorUnverified            = "remote_behavior_unverified"
	reasonRemoteImplementationNotScanned      = "remote_implementation_not_scanned"
	reasonSemanticOrToolResolutionUnavailable = "semantic_or_tool_resolution_unavailable"
)

const (
	hookTypeAgent   = "agent"
	hookTypeCommand = "command"
	hookTypeHTTP    = "http"
	hookTypeMCPTool = "mcp_tool"
	hookTypePrompt  = "prompt"
)

const (
	maxHookFindingContexts               = 32
	reasonInterpreterArgumentsUnverified = "interpreter_arguments_unverified"
)

//nolint:gochecknoglobals // Read-only manifest and launcher grammar shared by harness captures.
var commandLaunchers = map[string]struct {
	operand            int
	subcommand, reason string
}{
	"python": {
		operand:    1,
		subcommand: "",
		reason:     reasonInterpreterArgumentsUnverified,
	}, "python3": {
		operand:    1,
		subcommand: "",
		reason:     reasonInterpreterArgumentsUnverified,
	}, "node": {
		operand:    1,
		subcommand: "",
		reason:     reasonInterpreterArgumentsUnverified,
	}, "ruby": {
		operand:    1,
		subcommand: "",
		reason:     reasonInterpreterArgumentsUnverified,
	}, "perl": {
		operand:    1,
		subcommand: "",
		reason:     reasonInterpreterArgumentsUnverified,
	}, "go": {
		operand:    2,
		subcommand: "run",
		reason:     "launcher_arguments_unverified",
	},
}

type contextIndex struct {
	byPath   map[string][]report.Component
	nodes    map[string]report.Component
	incoming map[string][]report.ComponentEdge
}

// Enrich attaches only bounded contextual references. Findings retain all IDs,
// severity, evidence and traces. A graph edge is not a new taint-flow claim.
func Enrich(findings []report.Finding, g report.ComponentGraph) bool {
	index := findingContextIndex(g)
	truncated := false

	operations := 0
	for i := range findings {
		if index.enrichFinding(&findings[i], &operations, &truncated) {
			return true
		}
	}

	return truncated
}

// ApplyConfigScopes annotates the captured versions of config objects in the graph.
func ApplyConfigScopes(docs []document.File, g report.ComponentGraph) []document.File {
	type configSource struct{ path, digest string }

	type scopedConfig struct {
		file  configSource
		scope document.ConfigScope
	}

	bySource := map[configSource][]document.ConfigScope{}
	seen := map[scopedConfig]bool{}

	for _, n := range g.Components {
		if n.Source == nil || (n.Kind != report.ComponentMCPConfig && n.Kind != report.ComponentHookConfig) {
			continue
		}

		file := configSource{path: n.Source.Path, digest: n.Source.SHA256}
		scope := document.ConfigScope{
			Role: n.Kind,
			Host: n.Host,
			Span: source.Span{
				Start: n.Source.ByteStart,
				End:   n.Source.ByteEnd,
			},
		}

		key := scopedConfig{file: file, scope: scope}
		if seen[key] {
			continue
		}

		seen[key] = true

		bySource[file] = append(bySource[file], scope)
	}

	out := append([]document.File(nil), docs...)
	for i := range out {
		meta := out[i].Artifact().Metadata()
		out[i] = out[i].WithConfigScopes(bySource[configSource{path: meta.Path, digest: meta.SHA256}])
	}

	return out
}

func findingContextIndex(g report.ComponentGraph) contextIndex {
	byPath := map[string][]report.Component{}

	nodes := map[string]report.Component{}
	for _, n := range g.Components {
		nodes[n.ID] = n
		if n.Path != "" {
			byPath[n.Path] = append(byPath[n.Path], n)
		}
	}

	incoming := map[string][]report.ComponentEdge{}

	for _, edge := range g.Edges {
		if edge.Relation == "invokes" {
			incoming[edge.To] = append(incoming[edge.To], edge)
		}
	}

	return contextIndex{byPath: byPath, nodes: nodes, incoming: incoming}
}

func (x contextIndex) enrichFinding(f *report.Finding, operations *int, truncated *bool) bool {
	add := findingContextAdder(f, truncated)
	for _, n := range x.byPath[f.Location.Path] {
		*operations += 1
		if *operations > Limits().Operations {
			return true
		}

		if !contextOverlap(f.Location, n.Source) {
			continue
		}

		add(n, "same_component_bytes")

		for _, edge := range x.incoming[n.ID] {
			*operations += 1
			if *operations > Limits().Operations {
				return true
			}

			if component, ok := x.nodes[edge.From]; ok {
				add(component, "declared_handler_reference")
			}
		}
	}

	return false
}

func contextOverlap(location report.Location, s *report.SourceRef) bool {
	return s == nil || (location.ByteEnd > s.ByteStart && location.ByteStart < s.ByteEnd)
}

func findingContextAdder(f *report.Finding, truncated *bool) func(report.Component, string) {
	seen := map[string]bool{}

	return func(n report.Component, relation string) {
		key := n.ID + "/" + relation
		if seen[key] {
			return
		}

		seen[key] = true

		if len(f.Contexts) >= maxHookFindingContexts {
			*truncated = true
			return
		}

		f.Contexts = append(f.Contexts, report.FindingContext{
			ComponentID: n.ID,
			PluginID:    n.PluginID,
			Host:        n.Host,
			Relation:    relation,
			Activation:  n.Activation,
		})
	}
}

func (p *plugin) hooks(e *entry, n *jsonconfig.Node, parent, activation string) {
	state := p.b.hooks[e.Meta.Path]
	if state.Uncertain && p.host != report.HostGeminiCLI && p.host != report.HostGrokCLI && p.host != report.HostQwenCode {
		p.issue(issuePluginHookDisableUnverified, e.Meta.Path, report.OutcomePartial)
	}

	if state.Disabled && p.host == report.HostClaudeCode {
		return
	}

	hooks := n.Get(fieldHooks)
	if hooks == nil && p.host != report.HostGeminiCLI && (p.host != report.HostQwenCode || !p.nativeWorkspace && e != p.manifest) {
		hooks = n
	}

	if hooks == nil || hooks.Kind != jsonconfig.KindObject {
		p.issue(issuePluginHooksInvalid, e.Meta.Path, formatInvalid)
		return
	}

	for eventIndex, event := range hooks.Members {
		if !p.b.step() {
			return
		}

		if (p.host == report.HostGeminiCLI && p.nativeWorkspace || p.host == report.HostQwenCode) && agentconfig.HookSetting(event.Key) {
			continue
		}

		if !p.hookEvent(e, event, parent, activation, eventIndex) {
			return
		}
	}
}

func (p *plugin) hookEvent(e *entry, event jsonconfig.Member, parent, activation string, eventIndex int) bool {
	if !hookevent.ForHost(p.host, event.Key) {
		p.issue(issuePluginHookEventUnverified, e.Meta.Path, report.OutcomePartial)
		return true
	}

	if event.Value.Kind != jsonconfig.KindArray {
		p.issue(issuePluginHooksInvalid, e.Meta.Path, formatInvalid)
		return true
	}

	for gi, group := range event.Value.Elements {
		if !p.b.step() {
			return false
		}

		items := group.Get(fieldHooks)
		if items == nil || items.Kind != jsonconfig.KindArray {
			p.issue(issuePluginHooksInvalid, e.Meta.Path, formatInvalid)
			continue
		}

		for hi, h := range items.Elements {
			if !p.b.step() {
				return false
			}

			matcher, _ := group.Get(fieldMatcher).Text()
			p.hookHandler(e, h, parent, activation, event.Key, matcher, eventIndex, gi, hi)
		}
	}

	return true
}

func (p *plugin) hookHandler(e *entry, h *jsonconfig.Node, parent, activation, event, matcher string, eventIndex, gi, hi int) {
	if p.host == report.HostGrokCLI && agentconfig.GrokHookTarget(h) == nil || p.host == report.HostQwenCode && !agentconfig.QwenHookValid(h) {
		p.issue(issuePluginHookTypeUnverified, e.Meta.Path, report.OutcomePartial)
		return
	}

	s := ref(e, h.Span)
	id := p.component(report.ComponentHook, e, activation, basisConfiguration, s, fmt.Sprintf("hook:%d:%d:%d", eventIndex, gi, hi))
	p.b.edge(parent, id, relationRegisters, basisConfiguration, activation, s)
	// Event/matcher values may be arbitrary or hostile strings. They
	// remain available by source reference, never copied into diagnostics.
	kind, _ := h.Get(fieldType).Text()
	if p.host == report.HostGeminiCLI && kind != hookTypeCommand {
		p.issue(issuePluginHookTypeUnverified, e.Meta.Path, report.OutcomePartial)
		return
	}

	switch kind {
	case hookTypeCommand:
		p.hookCommand(e, h, id, activation, event, matcher)
	case hookTypeHTTP:
		p.reference(id, referenceKindRemoteEndpoint, report.ReferenceUnresolved, reasonRemoteBehaviorUnverified, "", s)
	case hookTypePrompt, hookTypeAgent:
		p.hookPrompt(e, h, id, activation, eventIndex, gi, hi, s)
	case hookTypeMCPTool:
		p.reference(id, referenceKindHookBehavior, report.ReferenceUnresolved, reasonSemanticOrToolResolutionUnavailable, "", s)
	default:
		p.issue(issuePluginHookTypeUnverified, e.Meta.Path, report.OutcomePartial)
	}
}

func (p *plugin) hookCommand(e *entry, h *jsonconfig.Node, id, activation, event, matcher string) {
	cmd := h.Get(fieldCommand)

	text, ok := cmd.Text()
	if !ok || strings.TrimSpace(text) == "" {
		p.issue(issuePluginHookCommandInvalid, e.Meta.Path, formatInvalid)
		return
	}

	s := ref(e, h.Span)
	if p.host == report.HostQwenCode {
		if shell, _ := h.Get("shell").Text(); shell != "" && shell != "bash" {
			p.reference(id, referenceKindHookBehavior, report.ReferenceUnresolved, reasonSemanticOrToolResolutionUnavailable, "", s)
			return
		}

		p.command(id, text, nil, false, s, activation, true)

		return
	}

	if p.host == report.HostGrokCLI {
		p.grokHookCommand(e, id, text, activation, s)
		return
	}

	args, valid := stringValues(h.Get(fieldArgs))
	argv := h.Get(fieldArgs) != nil

	if !valid {
		p.issue(issuePluginHookArgsInvalid, e.Meta.Path, formatInvalid)
		return
	}

	if p.b.hookTracer != nil && p.linkTracedHook(e, h, event, matcher, id, activation, s) {
		return
	}

	p.command(id, text, args, argv, s, activation, true)
}

func (p *plugin) linkTracedHook(e *entry, h *jsonconfig.Node, event, matcher, id, activation string, s *report.SourceRef) bool {
	paths := p.traceHook(e, h, event, matcher)

	if p.host == report.HostGeminiCLI && p.linkGeminiHandler(paths, id, activation, s) {
		return true
	}

	if h.Get(fieldArgs) != nil {
		return false
	}

	for _, unit := range e.Doc.Units() {
		if unit.Origin != document.OriginHookShell || unit.Span.Start < h.Span.Start || unit.Span.End > h.Span.End {
			continue
		}

		tree, ok := unit.Tree.(parse.ShellTree)
		if !ok {
			continue
		}

		inline, file := hooktrace.ShellLink(tree, p.host, p.projectSettings, len(paths) != 0)
		if inline {
			p.linkInlineHook(e, unit, id, activation, s)
			return true
		}

		if file {
			for _, traced := range paths {
				if target := p.ns.entries[traced.Target]; len(traced.Steps) == 1 && target != nil {
					p.capturedHandler(id, target, activation, s)
					p.reference(id, referenceKindRuntime, report.ReferenceUnresolved, report.ReferenceReasonRuntimeNotMaterialized, "", s)

					return true
				}
			}
		}
	}

	return false
}

func (p *plugin) linkInlineHook(e *entry, unit document.Unit, id, activation string, s *report.SourceRef) {
	child := p.component(componentHandler, e, activation, basisInlineShell, ref(e, unit.Span), "inline")
	p.b.edge(id, child, relationInvokes, basisInlineShell, activation, s)
	p.reference(id, referenceKindHandler, report.ReferenceResolved, reasonCapturedInlineShell, child, s)
}

func (p *plugin) hookPrompt(e *entry, h *jsonconfig.Node, id, activation string, eventIndex, gi, hi int, s *report.SourceRef) {
	prompt := h.Get(fieldPrompt)
	if text, ok := prompt.Text(); ok && strings.TrimSpace(text) != "" {
		child := p.component(componentInstruction, e, activation, basisHookPayload, ref(e, prompt.Span), fmt.Sprintf("prompt:%d:%d:%d", eventIndex, gi, hi))
		p.b.edge(id, child, relationInvokes, basisHookPayload, activation, ref(e, prompt.Span))
	} else {
		p.issue(issuePluginHookPromptInvalid, e.Meta.Path, formatInvalid)
	}

	p.reference(id, referenceKindHookBehavior, report.ReferenceUnresolved, reasonSemanticOrToolResolutionUnavailable, "", s)
}

func (p *plugin) settings(e *entry, n *jsonconfig.Node, parent string) {
	state := p.b.hooks[e.Meta.Path]
	if state.Uncertain {
		p.issue(issuePluginHookDisableUnverified, e.Meta.Path, report.OutcomePartial)
	}

	off := state.Disabled
	if n.Get(fieldHooks) != nil && !off {
		p.hooks(e, n, parent, "unknown")
	}

	for key := range strings.FieldsSeq("apiKeyHelper awsAuthRefresh awsCredentialExport gcpAuthRefresh otelHeadersHelper statusLine fileSuggestion") {
		value, selected := settingsCommandValue(n.Get(key), key, off)
		if !selected {
			continue
		}

		if value == nil {
			p.issue(issuePluginSettingsCommandInvalid, e.Meta.Path, formatInvalid)
			continue
		}

		id := p.component(componentSettingsCommand, e, activationUnknown, basisSettings, ref(e, value.Span), key)
		p.b.edge(parent, id, relationRegisters, basisSettings, activationUnknown, ref(e, value.Span))
		p.settingsCommand(e, value, id)
	}
}

func settingsCommandValue(value *jsonconfig.Node, key string, off bool) (*jsonconfig.Node, bool) {
	if value == nil {
		return nil, false
	}

	if key == "statusLine" || key == "fileSuggestion" {
		if off {
			return nil, false
		}

		kind, _ := value.Get(fieldType).Text()
		if kind != "command" {
			return nil, false
		}

		value = value.Get(fieldCommand)
	}

	return value, true
}

func (p *plugin) settingsCommand(e *entry, value *jsonconfig.Node, id string) {
	if text, ok := value.Text(); ok {
		p.command(id, text, nil, false, ref(e, value.Span), "unknown", false)
	} else if value.Kind == jsonconfig.KindArray && len(value.Elements) > 0 {
		words, valid := stringValues(value)

		if valid {
			p.command(id, words[0], words[1:], true, ref(e, value.Span), "unknown", false)
		} else {
			p.issue(issuePluginSettingsCommandInvalid, e.Meta.Path, formatInvalid)
		}
	} else {
		p.issue(issuePluginSettingsCommandInvalid, e.Meta.Path, formatInvalid)
	}
}

func (p *plugin) servers(e *entry, n *jsonconfig.Node, kind, parent, activation string) {
	servers := p.serverMap(e, n, kind)
	if servers == nil {
		return
	}

	if servers.Kind != jsonconfig.KindObject {
		p.issue(issuePluginServerMapInvalid, e.Meta.Path, formatInvalid)
		return
	}

	for i, m := range servers.Members {
		if !p.b.step() {
			return
		}

		if p.host == report.HostCopilotCLI && m.Key == "$schema" && m.Value.Kind == jsonconfig.KindString {
			continue
		}

		p.serverEntry(e, m.Value, kind, parent, activation, i)
	}
}

func (p *plugin) serverMap(e *entry, n *jsonconfig.Node, kind string) *jsonconfig.Node {
	servers := n

	if kind == report.ComponentMCPConfig {
		return p.mcpServerMap(e, n)
	}

	if kind == componentLSPConfig && n.Get(fieldLSPServers) != nil &&
		(p.host != report.HostQwenCode || e == p.manifest && !p.nativeWorkspace) {
		servers = n.Get(fieldLSPServers)
	}

	return servers
}

func (p *plugin) mcpServerMap(e *entry, n *jsonconfig.Node) *jsonconfig.Node {
	if p.host == report.HostQwenCode {
		return n.Get(fieldMCPServers)
	}

	if p.host == report.HostZCode && p.nativeWorkspace {
		if servers := agentconfig.ZCodeMCP(n); servers != nil {
			return servers
		}
	}

	servers := n

	camel, snake := n.Get(fieldMCPServers), n.Get(fieldMCPServersSnake)
	if camel != nil && snake != nil {
		p.issue(issuePluginMCPWrappersAmbiguous, e.Meta.Path, formatInvalid)
		return nil
	}

	if camel != nil {
		servers = camel
	}

	if snake != nil {
		servers = snake
	}

	if p.host == report.HostClaudeCode && snake != nil {
		p.issue(issuePluginMCPWrapperUnverified, e.Meta.Path, report.OutcomePartial)
	}

	return servers
}

func (p *plugin) serverEntry(e *entry, n *jsonconfig.Node, kind, parent, activation string, i int) {
	if (p.host == report.HostGrokCLI || p.host == report.HostZCode) && kind == report.ComponentMCPConfig {
		if enabled := n.Get("enabled"); enabled != nil && enabled.Kind == jsonconfig.KindBool && !enabled.Bool {
			activation = activationInactiveForProfile
		}
	}

	s := ref(e, n.Span)

	role := "mcp_server"
	if kind == componentLSPConfig {
		role = "lsp_server"
	}

	id := p.component(role, e, activation, basisConfiguration, s, fmt.Sprintf("%s:%d", role, i))
	p.b.edge(parent, id, relationDeclares, basisConfiguration, activation, s)

	if n.Kind != jsonconfig.KindObject {
		p.issue(issuePluginServerInvalid, e.Meta.Path, formatInvalid)
		return
	}

	if p.host == report.HostQwenCode && kind == componentLSPConfig && p.qwenLSPSocket(e, n, id) {
		return
	}

	command := n.Get(fieldCommand)

	endpoints := []*jsonconfig.Node{n.Get(fieldURL)}
	if p.host == report.HostGeminiCLI || p.host == report.HostQwenCode {
		endpoints = append(endpoints, n.Get(agentconfig.StreamableHTTPURL))
	}

	remote := p.serverEndpoints(e, id, endpoints)
	if remote > 1 || command != nil && remote != 0 {
		p.issue(issuePluginServerTransportAmbiguous, e.Meta.Path, report.OutcomePartial)
	}

	if command != nil {
		p.serverCommand(e, n, id, s, activation)
	} else if remote == 0 {
		p.issue(issuePluginServerTransportUnverified, e.Meta.Path, report.OutcomePartial)
	}
}

func (p *plugin) serverEndpoints(e *entry, id string, endpoints []*jsonconfig.Node) int {
	count := 0

	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}

		count++

		if value, ok := endpoint.Text(); (!ok || (p.host == report.HostGeminiCLI || p.host == report.HostQwenCode) && strings.TrimSpace(value) == "") &&
			!(p.host == report.HostDeepSeekHarness && endpoint.Kind == jsonconfig.KindExpression) {
			p.issue(issuePluginServerURLInvalid, e.Meta.Path, formatInvalid)
		}

		p.reference(id, referenceKindRemoteEndpoint, report.ReferenceUnresolved, reasonRemoteImplementationNotScanned, "", ref(e, endpoint.Span))
	}

	return count
}

func (p *plugin) serverCommand(e *entry, n *jsonconfig.Node, id string, s *report.SourceRef, activation string) {
	if p.host == report.HostDeepSeekHarness && deepSeekDynamicCommand(n) {
		p.reference(id, referenceKindCommand, report.ReferenceUnresolved, reasonDynamicCommand, "", s)
		return
	}

	text, ok := n.Get(fieldCommand).Text()
	args, valid := stringValues(n.Get(fieldArgs))

	if !ok || text == "" || !valid {
		p.issue(issuePluginServerCommandInvalid, e.Meta.Path, formatInvalid)
		return
	}

	if p.portable != "" {
		p.portableCommand(id, text, args, s, activation)
		return
	}

	p.command(id, text, args, true, s, activation, false)
}

// command recognizes only simple direct argv or one simple shell command. It
// NEVER treats an arbitrary substring in an echo, comment or shell string as a
// handler. Relative working directories and environment expansion are unknown.
func (p *plugin) command(component, text string, args []string, argv bool, s *report.SourceRef, activation string, hook bool) {
	p.commandFrom(component, text, args, argv, s, activation, hook, "")
}

func (p *plugin) commandFrom(component, text string, args []string, argv bool, s *report.SourceRef, activation string, hook bool, relativeDir string) {
	if strings.ContainsRune(text, 0) {
		p.reference(component, referenceKindCommand, report.ReferenceUnresolved, reasonInvalidCommandBytes, "", s)
		return
	}

	words := []string{text}
	if argv {
		words = append(words, args...)
	} else {
		tree, err := shellsyntax.Parse(p.b.ctx, text)

		command, valid := hooktrace.SimpleShellCommand(tree)
		if err != nil || !valid {
			p.reference(component, referenceKindCommand, report.ReferenceUnresolved, reasonComplexShellCommand, "", s)
			return
		}

		words = nil

		for _, word := range command.Words {
			v, ok := hooktrace.SymbolicWord(word, p.host, hook)
			if !ok {
				p.reference(component, referenceKindCommand, report.ReferenceUnresolved, reasonDynamicCommand, "", s)
				return
			}

			words = append(words, v)
		}
	}

	p.resolveCommand(component, words, argv, s, activation, hook, relativeDir)
}

func (p *plugin) resolveCommand(component string, words []string, argv bool, s *report.SourceRef, activation string, hook bool, relativeDir string) {
	candidate, externalRuntime, reason := commandOperand(words)
	if reason != "" {
		p.reference(component, referenceKindCommand, report.ReferenceUnresolved, reason, "", s)
		return
	}

	if externalRuntime {
		p.reference(component, referenceKindRuntime, report.ReferenceUnresolved, report.ReferenceReasonRuntimeNotMaterialized, "", s)
	}

	rel, kind, reason := p.handlerPath(candidate, argv, hook)
	if relativeDir != "" && candidate == words[0] && reason != "" {
		if local, ok := grokRelativeExecutable(relativeDir, candidate); ok {
			rel, kind, reason = local, referenceKindHandler, ""
		}
	}

	if reason != "" {
		p.reference(component, kind, report.ReferenceUnresolved, reason, "", s)
		return
	}

	e := p.entry(rel)
	if e == nil || e.Doc == nil {
		p.reference(component, referenceKindHandler, report.ReferenceUnresolved, report.ReferenceReasonHandlerNotCaptured, "", s)
		return
	}

	p.capturedHandler(component, e, activation, s)
	// A single source operand cannot attest the rest of go run's build inputs.
	if externalRuntime {
		p.issue(issueHandlerDependencyClosureUnverified, e.Meta.Path, report.OutcomePartial)
	}
}

func (p *plugin) capturedHandler(component string, e *entry, activation string, s *report.SourceRef) {
	id := p.component(componentHandler, e, activation, basisStaticReference, whole(e), "handler")
	p.b.edge(component, id, relationInvokes, basisStaticReference, activation, s)
	p.reference(component, referenceKindHandler, report.ReferenceResolved, reasonCapturedHandlerNotRuntimeProof, id, s)
}

func (p *plugin) handlerPath(candidate string, argv, hook bool) (string, string, string) {
	suffix, rooted := hooktrace.RootedSuffix(candidate, p.host, argv, hook)
	if p.host == report.HostZCode && p.nativeWorkspace {
		rooted = false
	}

	if argv && !hook && !rooted {
		suffix, rooted = p.extensionMCPOperand(candidate)
	}

	if !rooted {
		reason := "external_command_not_materialized"
		if strings.HasPrefix(candidate, "./") || strings.HasPrefix(candidate, "../") {
			reason = "working_directory_unknown"
		}

		return "", referenceKindCommand, reason
	}

	rel, reason := artifactpath.Reference(suffix, false)

	return rel, referenceKindHandler, reason
}

func commandOperand(words []string) (string, bool, string) {
	if hooktrace.IsShellInterpreter(words[0]) {
		args := words[1:]

		index := shellsyntax.FileArgumentIndex(len(args), func(i int) (string, bool) { return args[i], true })
		if index < 0 {
			return "", false, reasonInterpreterArgumentsUnverified
		}

		return args[index], true, ""
	}

	launcher, ok := commandLaunchers[words[0]]
	if !ok {
		return words[0], false, ""
	}

	if len(words) <= launcher.operand {
		return "", false, launcher.reason
	}

	if launcher.subcommand != "" && words[1] != launcher.subcommand {
		return "", false, launcher.reason
	}

	if strings.HasPrefix(words[launcher.operand], "-") {
		return "", false, launcher.reason
	}

	return words[launcher.operand], true, ""
}
