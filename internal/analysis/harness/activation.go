package harness

import (
	"fmt"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const reasonInterpreterArgumentsUnverified = "interpreter_arguments_unverified"

//nolint:gochecknoglobals // Read-only manifest and launcher grammar shared by harness captures.
var commandLaunchers = map[string]struct {
	operand            int
	subcommand, reason string
}{
	"sh": {operand: 1, subcommand: "", reason: reasonInterpreterArgumentsUnverified}, "bash": {
		operand:    1,
		subcommand: "",
		reason:     reasonInterpreterArgumentsUnverified,
	}, "dash": {
		operand:    1,
		subcommand: "",
		reason:     reasonInterpreterArgumentsUnverified,
	}, "zsh": {
		operand:    1,
		subcommand: "",
		reason:     reasonInterpreterArgumentsUnverified,
	}, "python": {
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

//nolint:gochecknoglobals // Read-only manifest and launcher grammar shared by harness captures.
var pluginRootParameters = map[string]string{report.HostClaudeCode: "CLAUDE_PLUGIN_ROOT", report.HostCodex: "PLUGIN_ROOT"}

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

// ApplyConfigScopes annotates actual config objects only. It never turns quoted
// examples or JSON extracted string tokens into installed configuration.
func ApplyConfigScopes(docs []document.File, g report.ComponentGraph) []document.File {
	byPath := map[string][]document.ConfigScope{}
	seen := map[string]bool{}

	for _, n := range g.Components {
		if n.Source == nil || (n.Kind != "mcp_config" && n.Kind != "hook_config") {
			continue
		}

		key := fmt.Sprintf("%s:%s:%s:%d:%d", n.Host, n.Kind, n.Source.Path, n.Source.ByteStart, n.Source.ByteEnd)
		if seen[key] {
			continue
		}

		seen[key] = true

		byPath[n.Source.Path] = append(byPath[n.Source.Path], document.ConfigScope{
			Role: n.Kind,
			Host: n.Host,
			Span: source.Span{
				Start: n.Source.ByteStart,
				End:   n.Source.ByteEnd,
			},
		})
	}

	out := append([]document.File(nil), docs...)
	for i := range out {
		out[i] = out[i].WithConfigScopes(byPath[out[i].Artifact().Metadata().Path])
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

		if len(f.Contexts) >= 32 {
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
	state := p.b.hooks[e.meta.Path]
	if state.Uncertain {
		p.issue("plugin_hook_disable_unverified", e.meta.Path, report.OutcomePartial)
	}

	if state.Disabled && p.host == report.HostClaudeCode {
		return
	}

	hooks := n.Get("hooks")
	if hooks == nil {
		hooks = n
	}

	if hooks.Kind != jsonconfig.KindObject {
		p.issue("plugin_hooks_invalid", e.meta.Path, "invalid")
		return
	}

	for eventIndex, event := range hooks.Members {
		if !p.b.step() {
			return
		}

		if !p.hookEvent(e, event.Value, parent, activation, eventIndex) {
			return
		}
	}
}

func (p *plugin) hookEvent(e *entry, event *jsonconfig.Node, parent, activation string, eventIndex int) bool {
	if event.Kind != jsonconfig.KindArray {
		p.issue("plugin_hooks_invalid", e.meta.Path, "invalid")
		return true
	}

	for gi, group := range event.Elements {
		if !p.b.step() {
			return false
		}

		items := group.Get("hooks")
		if items == nil || items.Kind != jsonconfig.KindArray {
			p.issue("plugin_hooks_invalid", e.meta.Path, "invalid")
			continue
		}

		for hi, h := range items.Elements {
			if !p.b.step() {
				return false
			}

			p.hookHandler(e, h, parent, activation, eventIndex, gi, hi)
		}
	}

	return true
}

func (p *plugin) hookHandler(e *entry, h *jsonconfig.Node, parent, activation string, eventIndex, gi, hi int) {
	s := ref(e, h.Span)
	id := p.component("hook", e, activation, "configuration", s, fmt.Sprintf("hook:%d:%d:%d", eventIndex, gi, hi))
	p.b.edge(parent, id, "registers", "configuration", activation, s)
	// Event/matcher values may be arbitrary or hostile strings. They
	// remain available by source reference, never copied into diagnostics.
	kind, _ := h.Get("type").Text()
	switch kind {
	case "command":
		p.hookCommand(e, h, id, activation)
	case "http":
		p.reference(id, "remote_endpoint", "unresolved", "remote_behavior_unverified", "", s)
	case "prompt", "agent":
		p.hookPrompt(e, h, id, activation, eventIndex, gi, hi, s)
	case "mcp_tool":
		p.reference(id, "hook_behavior", "unresolved", "semantic_or_tool_resolution_unavailable", "", s)
	default:
		p.issue("plugin_hook_type_unverified", e.meta.Path, report.OutcomePartial)
	}
}

func (p *plugin) hookCommand(e *entry, h *jsonconfig.Node, id, activation string) {
	cmd := h.Get("command")

	text, ok := cmd.Text()
	if !ok || strings.TrimSpace(text) == "" {
		p.issue("plugin_hook_command_invalid", e.meta.Path, "invalid")
		return
	}

	args, valid := stringValues(h.Get("args"))
	argv := h.Get("args") != nil

	if !valid {
		p.issue("plugin_hook_args_invalid", e.meta.Path, "invalid")
		return
	}

	p.command(id, text, args, argv, ref(e, h.Span), activation)
}

func (p *plugin) hookPrompt(e *entry, h *jsonconfig.Node, id, activation string, eventIndex, gi, hi int, s *report.SourceRef) {
	prompt := h.Get("prompt")
	if text, ok := prompt.Text(); ok && strings.TrimSpace(text) != "" {
		child := p.component("instruction", e, activation, "hook_payload", ref(e, prompt.Span), fmt.Sprintf("prompt:%d:%d:%d", eventIndex, gi, hi))
		p.b.edge(id, child, "invokes", "hook_payload", activation, ref(e, prompt.Span))
	} else {
		p.issue("plugin_hook_prompt_invalid", e.meta.Path, "invalid")
	}

	p.reference(id, "hook_behavior", "unresolved", "semantic_or_tool_resolution_unavailable", "", s)
}

func (p *plugin) settings(e *entry, n *jsonconfig.Node, parent string) {
	state := p.b.hooks[e.meta.Path]
	if state.Uncertain {
		p.issue("plugin_hook_disable_unverified", e.meta.Path, report.OutcomePartial)
	}

	off := state.Disabled
	if n.Get("hooks") != nil && !off {
		p.hooks(e, n, parent, "unknown")
	}

	for key := range strings.FieldsSeq("apiKeyHelper awsAuthRefresh awsCredentialExport gcpAuthRefresh otelHeadersHelper statusLine fileSuggestion") {
		value, selected := settingsCommandValue(n.Get(key), key, off)
		if !selected {
			continue
		}

		if value == nil {
			p.issue("plugin_settings_command_invalid", e.meta.Path, "invalid")
			continue
		}

		id := p.component("settings_command", e, "unknown", "settings", ref(e, value.Span), key)
		p.b.edge(parent, id, "registers", "settings", "unknown", ref(e, value.Span))
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

		kind, _ := value.Get("type").Text()
		if kind != "command" {
			return nil, false
		}

		value = value.Get("command")
	}

	return value, true
}

func (p *plugin) settingsCommand(e *entry, value *jsonconfig.Node, id string) {
	if text, ok := value.Text(); ok {
		p.command(id, text, nil, false, ref(e, value.Span), "unknown")
	} else if value.Kind == jsonconfig.KindArray && len(value.Elements) > 0 {
		words, valid := stringValues(value)

		if valid {
			p.command(id, words[0], words[1:], true, ref(e, value.Span), "unknown")
		} else {
			p.issue("plugin_settings_command_invalid", e.meta.Path, "invalid")
		}
	} else {
		p.issue("plugin_settings_command_invalid", e.meta.Path, "invalid")
	}
}

func (p *plugin) servers(e *entry, n *jsonconfig.Node, kind, parent, activation string) {
	servers := p.serverMap(e, n, kind)
	if servers == nil {
		return
	}

	if servers.Kind != jsonconfig.KindObject {
		p.issue("plugin_server_map_invalid", e.meta.Path, "invalid")
		return
	}

	for i, m := range servers.Members {
		if !p.b.step() {
			return
		}

		p.serverEntry(e, m.Value, kind, parent, activation, i)
	}
}

func (p *plugin) serverMap(e *entry, n *jsonconfig.Node, kind string) *jsonconfig.Node {
	servers := n

	if kind == "mcp_config" {
		return p.mcpServerMap(e, n)
	}

	if kind == "lsp_config" && n.Get("lspServers") != nil {
		servers = n.Get("lspServers")
	}

	return servers
}

func (p *plugin) mcpServerMap(e *entry, n *jsonconfig.Node) *jsonconfig.Node {
	servers := n

	camel, snake := n.Get("mcpServers"), n.Get("mcp_servers")
	if camel != nil && snake != nil {
		p.issue("plugin_mcp_wrappers_ambiguous", e.meta.Path, "invalid")
		return nil
	}

	if camel != nil {
		servers = camel
	}

	if snake != nil {
		servers = snake
	}

	if p.host == report.HostClaudeCode && snake != nil {
		p.issue("plugin_mcp_wrapper_unverified", e.meta.Path, report.OutcomePartial)
	}

	return servers
}

func (p *plugin) serverEntry(e *entry, n *jsonconfig.Node, kind, parent, activation string, i int) {
	s := ref(e, n.Span)

	role := "mcp_server"
	if kind == "lsp_config" {
		role = "lsp_server"
	}

	id := p.component(role, e, activation, "configuration", s, fmt.Sprintf("%s:%d", role, i))
	p.b.edge(parent, id, "declares", "configuration", activation, s)

	if n.Kind != jsonconfig.KindObject {
		p.issue("plugin_server_invalid", e.meta.Path, "invalid")
		return
	}

	command := n.Get("command")

	url := n.Get("url")
	if command != nil && url != nil {
		p.issue("plugin_server_transport_ambiguous", e.meta.Path, report.OutcomePartial)
	}

	if url != nil {
		if _, ok := url.Text(); !ok {
			p.issue("plugin_server_url_invalid", e.meta.Path, "invalid")
		}

		p.reference(id, "remote_endpoint", "unresolved", "remote_implementation_not_scanned", "", ref(e, url.Span))
	}

	if command != nil {
		p.serverCommand(e, n, id, s, activation)
	} else if url == nil {
		p.issue("plugin_server_transport_unverified", e.meta.Path, report.OutcomePartial)
	}
}

func (p *plugin) serverCommand(e *entry, n *jsonconfig.Node, id string, s *report.SourceRef, activation string) {
	text, ok := n.Get("command").Text()
	args, valid := stringValues(n.Get("args"))

	if !ok || text == "" || !valid {
		p.issue("plugin_server_command_invalid", e.meta.Path, "invalid")
		return
	}

	p.command(id, text, args, true, s, activation)
}

// command recognizes only simple direct argv or one simple shell command. It
// NEVER treats an arbitrary substring in an echo, comment or shell string as a
// handler. Relative working directories and environment expansion are unknown.
func (p *plugin) command(component, text string, args []string, argv bool, s *report.SourceRef, activation string) {
	if strings.ContainsRune(text, 0) {
		p.reference(component, "command", "unresolved", "invalid_command_bytes", "", s)
		return
	}

	words := []string{text}
	if argv {
		words = append(words, args...)
	} else {
		tree, err := shellsyntax.Parse(p.b.ctx, text)

		command, valid := simpleShellCommand(tree)
		if err != nil || !valid {
			p.reference(component, "command", "unresolved", "complex_shell_command", "", s)
			return
		}

		words = nil

		for _, word := range command.Words {
			v, ok := symbolicWord(word, p.host)
			if !ok {
				p.reference(component, "command", "unresolved", "dynamic_command", "", s)
				return
			}

			words = append(words, v)
		}
	}

	p.resolveCommand(component, words, argv, s, activation)
}

func simpleShellCommand(tree *shellsyntax.File) (*shellsyntax.Command, bool) {
	if tree == nil || len(tree.Statements) != 1 || len(tree.Statements[0].Commands) != 1 {
		return nil, false
	}

	statement := tree.Statements[0]

	command := statement.Commands[0]
	if len(command.Assignments) != 0 || len(command.Redirects) != 0 || command.Subshell != nil || len(command.Words) == 0 || slices.Contains([]string{"&", "&&", "||"}, statement.Next) {
		return nil, false
	}

	return command, true
}

func (p *plugin) resolveCommand(component string, words []string, argv bool, s *report.SourceRef, activation string) {
	candidate, externalRuntime, reason := commandOperand(words)
	if reason != "" {
		p.reference(component, "command", "unresolved", reason, "", s)
		return
	}

	if externalRuntime {
		p.reference(component, "runtime", "unresolved", "runtime_not_materialized", "", s)
	}

	rel, kind, reason := handlerPath(candidate, p.host, argv)
	if reason != "" {
		p.reference(component, kind, "unresolved", reason, "", s)
		return
	}

	e := p.entry(rel)
	if e == nil || e.doc == nil {
		p.reference(component, "handler", "unresolved", "handler_not_captured", "", s)
		return
	}

	id := p.component("handler", e, activation, "static_reference", whole(e), "handler")
	p.b.edge(component, id, "invokes", "static_reference", activation, s)
	p.reference(component, "handler", "resolved", "captured_handler_not_runtime_proof", id, s)
	// A single source operand cannot attest the rest of go run's build inputs.
	if externalRuntime {
		p.issue("handler_dependency_closure_unverified", e.meta.Path, report.OutcomePartial)
	}
}

func handlerPath(candidate, host string, argv bool) (string, string, string) {
	prefix := "${CLAUDE_PLUGIN_ROOT}/"
	if host == report.HostCodex {
		prefix = "${PLUGIN_ROOT}/"
	}

	if !argv {
		prefix = "\x00scout-plugin-root/"
	}

	if !strings.HasPrefix(candidate, prefix) {
		reason := "external_command_not_materialized"
		if strings.HasPrefix(candidate, "./") || strings.HasPrefix(candidate, "../") {
			reason = "working_directory_unknown"
		}

		return "", "command", reason
	}

	rel, reason := localPath(strings.TrimPrefix(candidate, prefix), false)

	return rel, "handler", reason
}

func commandOperand(words []string) (string, bool, string) {
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

func symbolicWord(w *shellsyntax.Word, host string) (string, bool) {
	if w == nil || w.Expands {
		return "", false
	}

	var b strings.Builder

	for _, part := range w.Parts {
		switch part.Kind {
		case "literal":
			b.WriteString(part.Text)
		case "parameter":
			if part.Text == pluginRootParameters[host] && part.Text != "" {
				b.WriteString("\x00scout-plugin-root")
			} else {
				return "", false
			}
		default:
			return "", false
		}
	}

	return b.String(), true
}
