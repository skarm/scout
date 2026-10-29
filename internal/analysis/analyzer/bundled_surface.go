// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified Go implementation of SkillSpector BH1-BH4 declaration/transfer checks.

package analyzer

import (
	"context"
	"errors"
	"net"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/hookpolicy"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"

	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // These hook vocabularies are initialized once and only read by concurrent scans.
var (
	hookEvents      = hookpolicy.Events
	sensitiveEvents = stringSet("UserPromptSubmit UserPromptExpansion MessageDisplay PreToolUse PermissionRequest PermissionDenied PostToolUse PostToolUseFailure PostToolBatch SubagentStop TaskCreated TaskCompleted Stop StopFailure PreCompact PostCompact Elicitation ElicitationResult")
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var surfaceTextFields = map[string][]struct {
	field string
	trim  bool
}{
	"command": {{field: "command", trim: true}}, "prompt": {{field: "prompt", trim: true}}, "agent": {{
		field: "prompt",
		trim:  true,
	}}, "mcp_tool": {{
		field: "server",
		trim:  false,
	}, {
		field: "tool",
		trim:  false,
	}},
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var wrappedAutomaticCommands = map[string]bool{"statusLine": true, "fileSuggestion": true}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	executableEnvironment = stringSet("CLAUDE_CODE_SHELL_PREFIX LD_PRELOAD DYLD_INSERT_LIBRARIES GIT_SSH_COMMAND")
	endpointEnvironment   = stringSet("ANTHROPIC_BASE_URL ANTHROPIC_BEDROCK_BASE_URL ANTHROPIC_VERTEX_BASE_URL")
	proxyEnvironment      = stringSet("HTTP_PROXY HTTPS_PROXY http_proxy https_proxy")
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	criticalPermissionTools  = stringSet("Bash Bash(*) PowerShell PowerShell(*) Read Edit Write")
	criticalPermissionPaths  = stringSet("// //** ~ ~/**")
	sensitivePermissionPaths = stringSet("~/.aws/credentials ~/.npmrc ~/.pypirc ~/.docker/config.json")
)

type bundledSurface struct {
	id    string
	hooks hookpolicy.Policy
}

func (a bundledSurface) Rule() report.Rule {
	title := map[string]string{
		ruleBH1: "Bundled non-command lifecycle handler declaration",
		ruleBH2: "Bundled hook transfers sensitive content remotely",
		ruleBH3: "Bundled permission or execution/traffic setting requires review",
		ruleBH4: "Bundled settings declare automatic command execution",
	}[a.id]

	severity := report.Medium
	if a.id == ruleBH2 {
		severity = report.Critical
	}

	if a.id == ruleBH3 {
		severity = report.Critical
	}

	return report.Rule{
		ID:          rulePrefixNVIDIA + a.id,
		Version:     "3",
		Title:       title,
		Description: title,
		Severity:    severity,
		Category:    "bundled-execution-surface",
		Method:      "bounded-hook-settings-analysis",
		Limitation:  "Conditional declarations, not proven host activation. Closed captured settings.local-before-settings disable semantics within a namespace/project; external settings and host trust remain unknown. BH2 requires a remote HTTP event body or direct literal or symbolic-HOME upload command. BH3 descriptor severity is a maximum; acceptEdits is medium and project-ignored auto is low.",
	}
}

func (bundledSurface) AppliesTo(document.File) bool { return true }

func (a bundledSurface) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	out := Result{}
	seen := map[source.Span]bool{}
	partial := false

	for _, u := range d.Units() {
		tree, ok := u.Tree.(parse.JSONTree)
		if !ok || tree.Root == nil {
			continue
		}

		emit := a.surfaceEmitter(u, &out, &partial, seen, budget)
		a.inspectSurfaceUnit(ctx, d, u, tree.Root, emit, &partial)
	}

	if ctx.Err() != nil {
		return out, ctx.Err()
	}

	if partial {
		return out, errors.New("bundled hook/settings shape or event semantics incomplete")
	}

	return out, nil
}

func (a bundledSurface) inspectSurfaceUnit(ctx context.Context, d document.File, u document.Unit, root *jsonconfig.Node, emit func(*jsonconfig.Node, ...report.Severity), partial *bool) {
	name := strings.ToLower(path.Base(d.Artifact().Metadata().Path))
	settings := name == "settings.json" || name == "settings.local.json"
	state := a.surfaceHookState(d, u, root, settings)

	*partial = *partial || state.Uncertain
	if settings || name == "hooks.json" {
		a.inspectSurface(ctx, root, settings, state.Disabled, emit, partial)
	}

	for _, scope := range d.ConfigScopes() {
		if scope.Role != "hook_config" {
			continue
		}

		if n := scopedNode(root, scope.Span); n != nil {
			a.inspectSurface(ctx, n, false, state.Disabled, emit, partial)
		}
	}
}

func (a bundledSurface) surfaceEmitter(u document.Unit, out *Result, partial *bool, seen map[source.Span]bool, budget int) func(*jsonconfig.Node, ...report.Severity) {
	return func(n *jsonconfig.Node, severity ...report.Severity) {
		if n == nil || out.Truncated {
			return
		}

		at, e := u.View.Original(n.Span)
		if e != nil {
			*partial = true
			return
		}

		if seen[at] {
			return
		}

		seen[at] = true

		if len(out.Matches) >= budget {
			out.Truncated = true
			return
		}

		m := Match{Start: at.Start, End: at.End}
		if len(severity) > 0 {
			m.Severity = severity[0]
		} else if a.id == ruleBH3 {
			m.Severity = report.High
		}

		m.InactiveForSurface = a.id == ruleBH3 && m.Severity == report.Low
		out.Matches = append(out.Matches, m)
	}
}

func (a bundledSurface) surfaceHookState(d document.File, u document.Unit, root *jsonconfig.Node, settings bool) hookpolicy.State {
	state := a.hooks[d.Artifact().Metadata().Path]
	if a.hooks == nil && settings && u.Origin == "file" {
		state = hookpolicy.Local(root)
	}

	if u.Origin != "file" {
		state.Disabled = false
	}

	if !settings {
		for _, scope := range d.ConfigScopes() {
			if scope.Role == "hook_config" && !slices.Contains([]string{"", report.HostClaudeCode}, scope.Host) {
				state.Disabled = false
			}
		}
	}

	return state
}

func (a bundledSurface) inspectSurface(ctx context.Context, root *jsonconfig.Node, settings, disabled bool, emit func(*jsonconfig.Node, ...report.Severity), partial *bool) {
	if root == nil || root.Kind != jsonconfig.KindObject {
		*partial = true
		return
	}

	hooks := surfaceHooks(root, settings, partial)

	if hooks != nil && !disabled {
		if hooks.Kind != jsonconfig.KindObject {
			*partial = true
		} else if !a.inspectHookEvents(ctx, hooks, emit, partial) {
			return
		}
	}

	if settings {
		a.inspectSettings(root, disabled, emit, partial)
	}
}

func surfaceHooks(root *jsonconfig.Node, settings bool, partial *bool) *jsonconfig.Node {
	if n := root.Get("disableAllHooks"); settings && n != nil && n.Kind != jsonconfig.KindBool {
		*partial = true
	}

	hooks := root.Get("hooks")
	if hooks == nil && !settings {
		hooks = root
	}

	return hooks
}

func (a bundledSurface) inspectHookEvents(ctx context.Context, hooks *jsonconfig.Node, emit func(*jsonconfig.Node, ...report.Severity), partial *bool) bool {
	for _, event := range hooks.Members {
		if ctx.Err() != nil {
			return false
		}

		if !hookEvents[event.Key] {
			*partial = true
		}

		if !a.inspectHookGroups(ctx, event.Key, event.Value, emit, partial) {
			return false
		}
	}

	return true
}

func (a bundledSurface) inspectHookGroups(ctx context.Context, event string, groups *jsonconfig.Node, emit func(*jsonconfig.Node, ...report.Severity), partial *bool) bool {
	if groups.Kind != jsonconfig.KindArray {
		*partial = true
		return true
	}

	for _, group := range groups.Elements {
		handlers := group.Get("hooks")
		if handlers == nil || handlers.Kind != jsonconfig.KindArray {
			*partial = true
			continue
		}

		for _, h := range handlers.Elements {
			if ctx.Err() != nil {
				return false
			}

			a.inspectHookHandler(ctx, event, h, emit, partial)
		}
	}

	return true
}

func (a bundledSurface) inspectHookHandler(ctx context.Context, event string, h *jsonconfig.Node, emit func(*jsonconfig.Node, ...report.Severity), partial *bool) {
	kind, _ := h.Get("type").Text()

	valid := surfaceHandlerValid(kind, h)

	if !valid {
		*partial = true
	}
	// AC003 already represents command declarations. Preserve its
	// identity without charging the same declaration twice.
	if a.id == ruleBH1 && kind != "command" {
		emit(h)
	}

	if a.id == ruleBH2 && valid && surfaceHandlerTransfer(ctx, event, kind, h) {
		emit(h)
	}
}

func surfaceHandlerValid(kind string, h *jsonconfig.Node) bool {
	if kind == "http" {
		text, ok := h.Get("url").Text()
		u, err := url.Parse(text)

		return ok && err == nil && u.Hostname() != "" && (u.Scheme == "http" || u.Scheme == "https")
	}

	fields, known := surfaceTextFields[kind]
	if !known {
		return false
	}

	for _, field := range fields {
		if !surfaceText(h, field.field, field.trim) {
			return false
		}
	}

	return true
}

func surfaceText(h *jsonconfig.Node, field string, trim bool) bool {
	text, ok := h.Get(field).Text()
	if trim {
		text = strings.TrimSpace(text)
	}

	return ok && text != ""
}

func surfaceHandlerTransfer(ctx context.Context, event, kind string, h *jsonconfig.Node) bool {
	switch kind {
	case "http":
		text, _ := h.Get("url").Text()
		return sensitiveEvents[event] && externalHTTP(text)
	case "command":
		return directHookUpload(ctx, event, h)
	default:
		return false
	}
}

func (a bundledSurface) inspectSettings(root *jsonconfig.Node, disabled bool, emit func(*jsonconfig.Node, ...report.Severity), partial *bool) {
	if a.id == ruleBH4 {
		inspectAutomaticCommands(root, disabled, emit, partial)
	}

	if a.id == ruleBH3 {
		inspectPermissionSettings(root, emit)
		inspectEnvironmentSettings(root, emit, partial)
	}
}

func inspectAutomaticCommands(root *jsonconfig.Node, disabled bool, emit func(*jsonconfig.Node, ...report.Severity), partial *bool) {
	for key := range strings.FieldsSeq("apiKeyHelper awsAuthRefresh awsCredentialExport gcpAuthRefresh otelHeadersHelper statusLine fileSuggestion") {
		n := root.Get(key)
		if n == nil {
			continue
		}

		if disabled && wrappedAutomaticCommands[key] {
			continue
		}

		if wrappedAutomaticCommands[key] {
			kind, ok := n.Get("type").Text()
			if !ok {
				*partial = true
				continue
			}

			if kind != "command" {
				continue
			}

			n = n.Get("command")
		}

		inspectAutomaticCommand(n, emit, partial)
	}
}

func inspectAutomaticCommand(n *jsonconfig.Node, emit func(*jsonconfig.Node, ...report.Severity), partial *bool) {
	if text, ok := n.Text(); ok {
		if strings.TrimSpace(text) != "" {
			emit(n)
		}
	} else if n != nil && n.Kind == jsonconfig.KindArray {
		for _, part := range n.Elements {
			if _, ok := part.Text(); !ok {
				*partial = true
			}
		}

		if len(n.Elements) > 0 {
			emit(n)
		}
	} else {
		*partial = true
	}
}

func inspectPermissionSettings(root *jsonconfig.Node, emit func(*jsonconfig.Node, ...report.Severity)) {
	permissions := root.Get("permissions")
	if severity := permissionModeSeverity(permissions); severity != "" {
		emit(permissions.Get("defaultMode"), severity)
	}

	for _, n := range permissions.GetOrEmpty("allow").Elements {
		if text, ok := n.Text(); ok {
			if severity := permissionGrantSeverity(text); severity != "" {
				emit(n, severity)
			}
		}
	}

	inspectDirectoryGrants(permissions, emit)

	if nodeBool(root.Get("enableAllProjectMcpServers")) {
		emit(root.Get("enableAllProjectMcpServers"))
	}

	if n := root.Get("enabledMcpjsonServers"); n != nil && len(n.Elements) > 0 {
		emit(n)
	}
}

func permissionModeSeverity(permissions *jsonconfig.Node) report.Severity {
	mode, ok := permissions.Get("defaultMode").Text()
	if !ok {
		return ""
	}

	switch mode {
	case "bypassPermissions":
		disabled, _ := permissions.Get("disableBypassPermissionsMode").Text()
		if disabled != "disable" {
			return report.Critical
		}
	case "acceptEdits":
		return report.Medium
	case report.HostAuto:
		return report.Low
	}

	return ""
}

func inspectDirectoryGrants(permissions *jsonconfig.Node, emit func(*jsonconfig.Node, ...report.Severity)) {
	for _, n := range permissions.GetOrEmpty("additionalDirectories").Elements {
		if text, ok := n.Text(); ok && rootOrHome(text) {
			emit(n, report.Critical)
		}
	}
}

func inspectEnvironmentSettings(root *jsonconfig.Node, emit func(*jsonconfig.Node, ...report.Severity), partial *bool) {
	for _, m := range root.GetOrEmpty("env").Members {
		text, ok := m.Value.Text()
		if !ok {
			*partial = true
			continue
		}

		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}

		inspectEnvironmentValue(m.Key, text, m.Value, emit)
	}
}

func inspectEnvironmentValue(key, text string, n *jsonconfig.Node, emit func(*jsonconfig.Node, ...report.Severity)) {
	switch {
	case executableEnvironment[key]:
		emit(n)
	case endpointEnvironment[key]:
		if strings.TrimRight(strings.ToLower(text), "/") != "https://api.anthropic.com" {
			emit(n)
		}
	case proxyEnvironment[key]:
		if externalHTTP(text) {
			emit(n)
		}
	case key == "NODE_OPTIONS":
		for range nodeImportOptions(text) {
			emit(n)
		}
	}
}

func nodeImportOptions(text string) int {
	count := 0

	for token := range strings.FieldsSeq(text) {
		for _, flag := range []string{"-r", "--require", "--import", "--loader", "--experimental-loader"} {
			if token == flag || strings.HasPrefix(token, flag+"=") {
				count++
			}
		}
	}

	return count
}

func stringSet(text string) map[string]bool {
	m := map[string]bool{}
	for s := range strings.FieldsSeq(text) {
		m[s] = true
	}

	return m
}

func nodeBool(n *jsonconfig.Node) bool { return n != nil && n.Kind == jsonconfig.KindBool && n.Bool }

func rootOrHome(s string) bool {
	if strings.HasPrefix(s, "/") {
		return path.Clean(s) == "/"
	}

	if s == "~" {
		return true
	}

	return strings.HasPrefix(s, "~/") && path.Clean(strings.TrimPrefix(s, "~/")) == "."
}

func permissionGrantSeverity(s string) report.Severity {
	if criticalPermissionTools[s] {
		return report.Critical
	}

	for _, tool := range []string{"Read", "Edit"} {
		if strings.HasPrefix(s, tool+"(") && strings.HasSuffix(s, ")") {
			v := s[len(tool)+1 : len(s)-1]
			if criticalPermissionPaths[v] {
				return report.Critical
			}

			if strings.HasPrefix(v, "~/.ssh/") || sensitivePermissionPaths[v] {
				return report.High
			}
		}
	}

	if broadTool(s) {
		return report.High
	}

	return ""
}

func externalHTTP(text string) bool {
	u, e := url.Parse(text)
	return e == nil && (u.Scheme == "http" || u.Scheme == "https") && closedRemoteHost(u.Hostname())
}

func closedRemoteHost(host string) bool {
	if host == "" || loopbackHost(host) {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}

	if strings.Contains(host, ":") || strings.HasPrefix(strings.ToLower(host), "0x") {
		return false
	}

	if strings.Trim(host, "0123456789.") == "" {
		return false
	}

	return true
}

// Closed direct-command proof only: one simple curl invocation, one remote
// destination, and a literal stdin/sensitive file upload. No shell expansion.
func directHookUpload(ctx context.Context, event string, h *jsonconfig.Node) bool {
	if declaredShell := h.Get("shell"); declaredShell != nil {
		if value, ok := declaredShell.Text(); !ok || value != "bash" {
			return false
		}
	}

	argv, valid := hookUploadArgv(ctx, h)
	if !valid {
		return false
	}

	return directUploadArguments(event, argv)
}

func hookUploadArgv(ctx context.Context, h *jsonconfig.Node) ([]string, bool) {
	command, _ := h.Get("command").Text()
	if args := h.Get("args"); args != nil {
		return hookDeclaredUploadArgv(command, args)
	}

	return shell.UploadArgv(ctx, command, sensitiveAbsoluteFile)
}

func hookDeclaredUploadArgv(command string, args *jsonconfig.Node) ([]string, bool) {
	argv := make([]string, 0)

	if args.Kind != jsonconfig.KindArray {
		return nil, false
	}

	argv = append(argv, command)

	for _, n := range args.Elements {
		s, ok := n.Text()
		if !ok {
			return nil, false
		}

		argv = append(argv, s)
	}

	return argv, true
}
