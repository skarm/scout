// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Adapted closed settings/disable grammar from SkillSpector. Scope isolation,
// captured-byte parsing and immutable binding are Scout-specific.

// Package hookpolicy validates and binds hook settings without executing them.
package hookpolicy

import (
	"context"
	"math"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Fixed event, setting and permission vocabularies shared read-only by scans.
var (
	Events = set("ConfigChange CwdChanged DirectoryAdded Elicitation ElicitationResult FileChanged InstructionsLoaded MessageDisplay Notification PermissionDenied PermissionRequest PostCompact PostToolBatch PostToolUse PostToolUseFailure PreCompact PreToolUse SessionEnd SessionStart Setup Stop StopFailure SubagentStart SubagentStop TaskCompleted TaskCreated TeammateIdle UserPromptExpansion UserPromptSubmit WorktreeCreate WorktreeRemove")
	keys   = set("$schema disableAllHooks env fileSuggestion hooks includeCoAuthoredBy model permissions statusLine")
	modes  = set("acceptEdits auto bypassPermissions default dontAsk manual plan")
)

//nolint:gochecknoglobals // Read-only settings and handler grammar shared by policy validators.
var commandSettingFields = []fieldRule{
	{names: "type", valid: func(n *jsonconfig.Node) bool { return text(n, false) }},
	{names: "command", valid: func(n *jsonconfig.Node) bool { return text(n, false) || stringsList(n) }},
}

//nolint:gochecknoglobals // Read-only settings and handler grammar shared by policy validators.
var permissionFields = []fieldRule{
	{names: "allow", valid: func(n *jsonconfig.Node) bool { return permissionList(n, true) }},
	{names: "ask deny", valid: func(n *jsonconfig.Node) bool { return permissionList(n, false) }},
	{names: "additionalDirectories", valid: stringsList},
	{names: "defaultMode", valid: func(n *jsonconfig.Node) bool { value, ok := n.Text(); return ok && modes[value] }},
	{
		names: "disableBypassPermissionsMode disableAutoMode",
		valid: func(n *jsonconfig.Node) bool { value, ok := n.Text(); return ok && value == "disable" },
	},
}

//nolint:gochecknoglobals // Read-only settings and handler grammar shared by policy validators.
var optionalHandlerRules = []fieldRule{
	{
		names: "if statusMessage model rewakeMessage rewakeSummary",
		valid: func(n *jsonconfig.Node) bool { return text(n, false) },
	},
	{names: "once async asyncRewake continueOnBlock", valid: func(n *jsonconfig.Node) bool { return n.Kind == jsonconfig.KindBool }},
	{names: "timeout", valid: positiveTimeout},
	{names: "shell", valid: func(n *jsonconfig.Node) bool {
		value, ok := n.Text()
		return ok && (value == "bash" || value == "powershell")
	}},
	{names: "allowedEnvVars", valid: stringsList},
	{names: "headers", valid: stringObject},
	{names: "input", valid: func(n *jsonconfig.Node) bool { return n.Kind == jsonconfig.KindObject }},
}

//nolint:gochecknoglobals // Read-only settings and handler grammar shared by policy validators.
var handlerFields = map[string][]fieldRule{
	"command": {{names: "command", required: true, valid: func(n *jsonconfig.Node) bool { return text(n, true) }}, {
		names: "args",
		valid: stringsList,
	}},
	"http":     {{names: "url", required: true, valid: httpURL}},
	"prompt":   {{names: "prompt", required: true, valid: func(n *jsonconfig.Node) bool { return text(n, true) }}},
	"agent":    {{names: "prompt", required: true, valid: func(n *jsonconfig.Node) bool { return text(n, true) }}},
	"mcp_tool": {{names: "server tool", required: true, valid: func(n *jsonconfig.Node) bool { return text(n, true) }}},
}

type (
	State  struct{ Disabled, Uncertain bool }
	Policy map[string]State
)

// Field rules model the closed value grammar; unknown members remain governed
// by the enclosing declaration's policy rather than these reusable rules.
type fieldRule struct {
	names    string
	required bool
	valid    func(*jsonconfig.Node) bool
}

// Bind honors local-before-project precedence only in the same captured
// namespace and project root. Derived strings/fences cannot supply settings.
// A nested skill/plugin is a scope boundary, even without its own settings.
type (
	address = document.Address
	setting struct{ root *jsonconfig.Node }
)

func IsSettings(name string) bool {
	b := path.Base(name)
	return b == "settings.json" || b == "settings.local.json"
}

// ValidDisable only trusts the closed modeled schema. Unknown fields cannot
// make a risky hook disappear; a false flag is never an exemption.
func validDisable(n *jsonconfig.Node) bool {
	if n == nil || n.Kind != jsonconfig.KindObject {
		return false
	}

	flag := n.Get("disableAllHooks")
	if flag == nil || flag.Kind != jsonconfig.KindBool || !flag.Bool {
		return false
	}

	for _, m := range n.Members {
		if !keys[m.Key] {
			return false
		}

		if !validSetting(m.Key, m.Value) {
			return false
		}
	}

	return true
}

func Local(n *jsonconfig.Node) State {
	if n == nil || n.Get("disableAllHooks") == nil {
		return State{}
	}

	flag := n.Get("disableAllHooks")
	if flag.Kind == jsonconfig.KindBool && !flag.Bool {
		return State{}
	}

	valid := validDisable(n)

	return State{Disabled: valid, Uncertain: !valid}
}

func Bind(ctx context.Context, docs []document.File, extraction report.ExtractionReport) Policy {
	addresses := document.CapturedAddresses(docs, extraction)

	settings := map[string]setting{}
	scopes := map[string]bool{}

	for _, d := range docs {
		if ctx.Err() != nil {
			return Policy{}
		}

		a, ok := addresses[d.Artifact().Metadata().Path]
		if !ok {
			continue
		}

		if root, boundary := scopeRoot(a.Name); boundary {
			scopes[a.Namespace+"\x00"+root] = true
		}

		if !IsSettings(a.Name) {
			continue
		}
		// Invalid files are retained: a malformed higher-priority setting prevents
		// an inherited disable from being treated as a closed proof.
		n := settingTree(d)

		settings[a.Namespace+"\x00"+a.Name] = setting{root: n}
	}

	states := scopeStates(scopes, settings)

	return bindAddresses(addresses, states)
}

func validSetting(key string, n *jsonconfig.Node) bool {
	switch key {
	case "$schema", "model":
		return text(n, false)
	case "includeCoAuthoredBy":
		return n.Kind == jsonconfig.KindBool
	case "env":
		return stringObject(n)
	case "statusLine", "fileSuggestion":
		return n.Kind == jsonconfig.KindObject && validateFields(n, commandSettingFields)
	case "permissions":
		return permissionsValid(n)
	case "hooks":
		return hooksValid(n)
	default:
		return true
	}
}

func validateFields(n *jsonconfig.Node, rules []fieldRule) bool {
	for _, rule := range rules {
		for name := range strings.FieldsSeq(rule.names) {
			value := n.Get(name)
			if value == nil && !rule.required {
				continue
			}

			if !rule.valid(value) {
				return false
			}
		}
	}

	return true
}

func stringObject(n *jsonconfig.Node) bool {
	if n == nil || n.Kind != jsonconfig.KindObject {
		return false
	}

	for _, member := range n.Members {
		if !text(member.Value, false) {
			return false
		}
	}

	return true
}

func scopeRoot(name string) (string, bool) {
	if path.Base(name) == "SKILL.md" {
		return path.Dir(name), true
	}

	if strings.HasSuffix(name, ".claude-plugin/plugin.json") || strings.HasSuffix(name, ".codex-plugin/plugin.json") {
		return path.Dir(path.Dir(name)), true
	}

	if !IsSettings(name) {
		return "", false
	}

	root := path.Dir(name)
	if path.Base(root) == ".claude" {
		root = path.Dir(root)
	}

	return root, true
}

func settingTree(d document.File) *jsonconfig.Node {
	for _, u := range d.Units() {
		if tree, ok := u.Tree.(parse.JSONTree); ok && u.Origin == "file" {
			return tree.Root
		}
	}

	return nil
}

func scopeStates(scopes map[string]bool, settings map[string]setting) map[string]State {
	states := map[string]State{}

	for key := range scopes {
		ns, root, _ := strings.Cut(key, "\x00")
		state := State{}

		for _, name := range []string{path.Join(root, ".claude/settings.local.json"), path.Join(root, ".claude/settings.json"), path.Join(root, "settings.local.json"), path.Join(root, "settings.json")} {
			s, ok := settings[ns+"\x00"+name]
			if !ok {
				continue
			}

			if s.root == nil || s.root.Kind != jsonconfig.KindObject {
				state.Uncertain = true
				break
			}

			if s.root.Get("disableAllHooks") != nil {
				state = Local(s.root)
				break
			}
		}

		states[key] = state
	}

	return states
}

func bindAddresses(addresses map[string]address, states map[string]State) Policy {
	out := Policy{}

	for p, a := range addresses {
		root := path.Dir(a.Name)
		for {
			if state, ok := states[a.Namespace+"\x00"+root]; ok {
				out[p] = state
				break
			}

			if root == "." {
				break
			}

			root = path.Dir(root)
		}
	}

	return out
}

func set(s string) map[string]bool {
	m := map[string]bool{}
	for v := range strings.FieldsSeq(s) {
		m[v] = true
	}

	return m
}

func text(n *jsonconfig.Node, nonempty bool) bool {
	s, ok := n.Text()
	return ok && len(s) <= 65536 && !strings.ContainsRune(s, 0) && (!nonempty || strings.TrimSpace(s) != "")
}

func stringsList(n *jsonconfig.Node) bool {
	if n == nil {
		return true
	}

	if n.Kind != jsonconfig.KindArray {
		return false
	}

	for _, v := range n.Elements {
		if !text(v, true) {
			return false
		}
	}

	return true
}

func permissionsValid(n *jsonconfig.Node) bool {
	return n.Kind == jsonconfig.KindObject && validateFields(n, permissionFields)
}

func permissionList(n *jsonconfig.Node, allow bool) bool {
	if !stringsList(n) {
		return false
	}

	if n == nil {
		return true
	}

	for _, v := range n.Elements {
		if !permissionRule(v.String, allow) {
			return false
		}
	}

	return true
}

func permissionRule(s string, allow bool) bool {
	tool, tail, has := strings.Cut(s, "(")
	if !textmatch.Token(tool, len(tool), "_*.-") || allow && strings.Contains(tool, "*") && !mcpWildcard(tool) {
		return false
	}

	if !has {
		return !strings.Contains(s, ")")
	}

	if !strings.HasSuffix(tail, ")") || len(tail) < 2 {
		return false
	}

	return balancedPermissionArgument(tail[:len(tail)-1])
}

func balancedPermissionArgument(s string) bool {
	depth := 0

	for _, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}

	return depth == 0
}

func optionalHandlerFields(h *jsonconfig.Node) bool {
	return validateFields(h, optionalHandlerRules)
}

func positiveTimeout(n *jsonconfig.Node) bool {
	number, err := strconv.ParseFloat(n.String, 64)
	return n.Kind == jsonconfig.KindNumber && err == nil && number > 0 && !math.IsInf(number, 0) && !math.IsNaN(number)
}

func hooksValid(n *jsonconfig.Node) bool {
	if n.Kind != jsonconfig.KindObject {
		return false
	}

	for _, event := range n.Members {
		if !Events[event.Key] || event.Value.Kind != jsonconfig.KindArray {
			return false
		}

		for _, group := range event.Value.Elements {
			if !hookGroupValid(group) {
				return false
			}
		}
	}

	return true
}

func hookGroupValid(group *jsonconfig.Node) bool {
	if group == nil || group.Kind != jsonconfig.KindObject {
		return false
	}

	if v := group.Get("matcher"); v != nil && !text(v, false) {
		return false
	}

	handlers := group.Get("hooks")
	if handlers == nil || handlers.Kind != jsonconfig.KindArray {
		return false
	}

	for _, h := range handlers.Elements {
		if !handlerValid(h) {
			return false
		}
	}

	return true
}

func handlerValid(h *jsonconfig.Node) bool {
	if h == nil || h.Kind != jsonconfig.KindObject {
		return false
	}

	if !optionalHandlerFields(h) {
		return false
	}

	kind, _ := h.Get("type").Text()
	rules, known := handlerFields[kind]

	return known && validateFields(h, rules)
}

func httpURL(n *jsonconfig.Node) bool {
	if !text(n, true) {
		return false
	}

	u, err := url.Parse(n.String)

	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}

func mcpWildcard(tool string) bool {
	body, ok := strings.CutPrefix(tool, "mcp__")
	if !ok || !strings.HasSuffix(body, "*") {
		return false
	}

	body = strings.TrimSuffix(body, "*")

	return textmatch.Token(body, len(body), "_.-") && strings.LastIndex(body, "__") > 0
}
