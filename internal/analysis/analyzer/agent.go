package analyzer

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/hookpolicy"
	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

var environmentReference = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)

var npmPackageName = regexp.MustCompile(`^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$`)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var agentRuleMetadataByID = map[string]agentRuleMetadata{
	ruleAC001: {
		title:    "Agent configuration requests permission bypass",
		category: "approval-bypass",
		severity: report.High,
	},
	ruleAC002: {title: "Agent configuration declares a broad tool approval", category: "excessive-permissions"},
	ruleAC003: {title: "Agent lifecycle hook declares command execution", category: "lifecycle-execution", harness: true},
	ruleSC001: {
		title:      "MCP launcher package is not pinned to an exact version",
		category:   "supply-chain",
		harness:    true,
		limitation: " Selected direct npx/npm-exec/go-run/uvx/uv-tool/pip/docker/podman argv forms only. Container tags are mutable; only a syntactic SHA256 digest counts as pinned. Exact version text is not package integrity, authenticity or a vulnerability check. Wrappers and arbitrary package managers are not resolved.",
	},
	ruleMC001: {
		title:      "MCP endpoint declares non-loopback plaintext HTTP",
		category:   "insecure-transport",
		harness:    true,
		limitation: " URL text only; no DNS, redirects or endpoint access. Loopback exemption is syntactic, not authentication or host trust.",
	},
	ruleMC002: {
		title:      "MCP configuration embeds a credential-like literal",
		category:   "credential-material",
		harness:    true,
		limitation: " Selected env/header names and URL userinfo; literals are not proven live secrets. Runtime interpolation is not evaluated.",
	},
	ruleMC003: {
		title:      "MCP tool schema requests highly sensitive input",
		category:   "sensitive-data-request",
		limitation: " Selected inputSchema property names; legitimate auth tools can also match. readOnlyHint is not treated as a safety guarantee.",
	},
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var serverConfigRules = map[string]bool{ruleSC001: true, ruleMC001: true, ruleMC002: true}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var launcherFamilies = map[string]string{
	"go":     "go",
	"uvx":    "python",
	"uv":     "python",
	"pip":    "python",
	"pip3":   "python",
	"docker": "container",
	"podman": "container",
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	pythonLauncherPrefixes    = map[string][]string{"uv": {"tool", "run"}, "pip": {"install"}, "pip3": {"install"}}
	pythonLauncherFlags       = stringSet("--no-cache --quiet -q")
	containerLauncherFlags    = stringSet("--rm -i -t -it")
	containerLauncherCommands = stringSet("run pull create")
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	nodeLauncherTokens = map[string]nodeLauncherTokenKind{
		"-y":        nodeTokenSkip,
		"--yes":     nodeTokenSkip,
		"--no":      nodeTokenSkip,
		"-p":        nodeTokenPackage,
		"--package": nodeTokenPackage,
		"--":        nodeTokenBarrier,
	}
	nodeLauncherGrammar = map[nodeLauncherState]map[nodeLauncherTokenKind]nodeLauncherTransition{
		nodeInitialNpx: {
			nodeTokenSkip: {next: nodeInitialNpx},
			nodeTokenPackage: {
				next:    nodePackageMode,
				inspect: true,
			},
			nodeTokenBarrier: {
				inspect:  true,
				terminal: true,
			},
			nodeTokenBare: {
				inspect:  true,
				terminal: true,
			},
		},
		nodeInitialNpm: {
			nodeTokenSkip: {next: nodeInitialNpm},
			nodeTokenPackage: {
				next:    nodePackageMode,
				inspect: true,
			},
			nodeTokenBarrier: {
				inspect:  true,
				terminal: true,
			},
		},
		nodePackageMode: {
			nodeTokenSkip: {next: nodePackageMode},
			nodeTokenPackage: {
				next:    nodePackageMode,
				inspect: true,
			},
		},
	}
)

type agentConfigCheck struct {
	id    string
	hooks hookpolicy.Policy
}

type agentRuleMetadata struct {
	title, category string
	severity        report.Severity
	limitation      string
	harness         bool
}

type nodeLauncherTokenKind uint8

const (
	nodeTokenInvalid nodeLauncherTokenKind = iota
	nodeTokenSkip
	nodeTokenPackage
	nodeTokenInlinePackage
	nodeTokenBarrier
	nodeTokenBare
)

type nodeLauncherState uint8

const (
	nodeInitialNpx nodeLauncherState = iota
	nodeInitialNpm
	nodePackageMode
)

type nodeLauncherTransition struct {
	next              nodeLauncherState
	inspect, terminal bool
}
type nodeLauncherToken struct {
	kind  nodeLauncherTokenKind
	node  *jsonconfig.Node
	value string
	next  int
}

func (a agentConfigCheck) Rule() report.Rule {
	metadata := agentRuleMetadataByID[a.id]

	severity := metadata.severity
	if severity == "" {
		severity = report.Medium
	}

	limitation := "Strict bounded JSON and supported field shapes only. A declaration is not proof of runtime activation, compromise or effective host permissions. Hook disables use a closed captured Claude settings.local-before-settings subset; external settings and other precedence remain unknown. YAML/TOML require an explicitly selected trusted parser; TOML positions cover the whole unit." + metadata.limitation
	if metadata.harness {
		limitation += " Includes harness-linked inline/custom-path config objects without assuming activation."
	}

	return report.Rule{
		ID:          a.id,
		Version:     "4",
		Title:       metadata.title,
		Description: metadata.title,
		Category:    metadata.category,
		Severity:    severity,
		Method:      "json-configuration",
		Limitation:  limitation,
	}
}

func (agentConfigCheck) AppliesTo(f document.File) bool {
	for _, u := range f.Units() {
		if _, ok := u.Tree.(parse.JSONTree); ok {
			return true
		}
	}

	return false
}

func (a agentConfigCheck) Find(ctx context.Context, f document.File, budget int) (Result, error) {
	var (
		out        Result
		mappingErr error
	)

	seen := make(map[source.Span]bool)

	if err := ctx.Err(); err != nil {
		return out, err
	}

	for _, u := range f.Units() {
		tree, ok := u.Tree.(parse.JSONTree)
		if !ok || tree.Root == nil {
			continue
		}

		emit := configEmitter(u, &out, &mappingErr, seen, budget)
		a.inspectConfigUnit(ctx, f, u, tree.Root, &out, emit, &mappingErr)

		if out.Truncated || mappingErr != nil || ctx.Err() != nil {
			break
		}
	}

	return out, errors.Join(mappingErr, ctx.Err())
}

func (a agentConfigCheck) inspectConfigUnit(ctx context.Context, f document.File, u document.Unit, root *jsonconfig.Node, out *Result, emit func(source.Span), mappingErr *error) {
	state := a.hookState(f, u, root)

	actualHook := u.Origin == "file" && (hookpolicy.IsSettings(f.Artifact().Metadata().Path) || path.Base(f.Artifact().Metadata().Path) == "hooks.json")
	if a.id != ruleAC003 || !state.Disabled || !actualHook {
		a.inspect(ctx, root, emit)
	}

	if a.id == ruleAC003 && state.Uncertain {
		*mappingErr = errors.New("hook disable semantics incomplete")
	}

	a.inspectConfigScopes(ctx, f, u, root, state, out, emit)
}

func configEmitter(u document.Unit, out *Result, mappingErr *error, seen map[source.Span]bool, budget int) func(source.Span) {
	return func(span source.Span) {
		if out.Truncated || *mappingErr != nil {
			return
		}

		at, err := u.View.Original(span)
		if err != nil {
			*mappingErr = errors.New("configuration evidence mapping failed")
			return
		}

		if seen[at] {
			return
		}

		if len(out.Matches) >= budget {
			out.Truncated = true
			return
		}

		seen[at] = true
		out.Matches = append(out.Matches, Match{Start: at.Start, End: at.End})
	}
}

func (a agentConfigCheck) hookState(f document.File, u document.Unit, root *jsonconfig.Node) hookpolicy.State {
	state := a.hooks[f.Artifact().Metadata().Path]
	if a.hooks == nil && u.Origin == "file" && hookpolicy.IsSettings(f.Artifact().Metadata().Path) {
		state = hookpolicy.Local(root)
	}

	if !hookpolicy.IsSettings(f.Artifact().Metadata().Path) {
		for _, scope := range f.ConfigScopes() {
			if scope.Role == "hook_config" && scope.Host != "" && scope.Host != report.HostClaudeCode {
				state.Disabled = false
			}
		}
	}

	return state
}

func (a agentConfigCheck) inspectConfigScopes(ctx context.Context, f document.File, u document.Unit, root *jsonconfig.Node, state hookpolicy.State, out *Result, emit func(source.Span)) {
	if u.Origin == "file" {
		for _, scope := range f.ConfigScopes() {
			if out.Truncated || ctx.Err() != nil {
				break
			}

			n := scopedConfigNode(root, scope.Span, len(f.Artifact().Content()))

			if n != nil && !(a.id == ruleAC003 && scope.Role == "hook_config" && state.Disabled) {
				a.inspectScope(ctx, n, scope.Role, emit)
			}
		}
	}
}

func scopedConfigNode(root *jsonconfig.Node, span source.Span, bytes int) *jsonconfig.Node {
	if span == (source.Span{Start: 0, End: bytes}) {
		return root
	}

	return scopedNode(root, span)
}

func (a agentConfigCheck) inspect(ctx context.Context, root *jsonconfig.Node, emit func(source.Span)) {
	if root.Kind != jsonconfig.KindObject {
		return
	}

	switch a.id {
	case ruleAC001:
		inspectApprovalPolicy(root, emit)
	case ruleAC002:
		inspectBroadTools(root, emit)
	case ruleAC003:
		inspectCommandHooks(ctx, root.Get("hooks"), emit)
	case ruleMC003:
		inspectSensitiveToolParameters(ctx, root, emit)
	default:
		a.inspectServers(ctx, root, emit)
	}
}

func inspectApprovalPolicy(root *jsonconfig.Node, emit func(source.Span)) {
	for _, field := range []struct{ name, value string }{{name: "approval_policy", value: "never"}, {
		name:  "sandbox_mode",
		value: "danger-full-access",
	}} {
		n := root.Get(field.name)
		if text, ok := n.Text(); ok && text == field.value {
			emit(n.Span)
		}
	}

	permissions := root.Get("permissions")
	n := permissions.Get("defaultMode")

	disabled, _ := permissions.Get("disableBypassPermissionsMode").Text()
	if text, ok := n.Text(); ok && text == "bypassPermissions" && disabled != "disable" {
		emit(n.Span)
	}
}

func inspectBroadTools(root *jsonconfig.Node, emit func(source.Span)) {
	for _, key := range []string{"allowed-tools", "permissions"} {
		for _, node := range broadToolDeclarations(root.Get(key)) {
			emit(node.Span)
		}
	}

	for _, node := range broadToolElementDeclarations(root.Get("permissions").Get("allow")) {
		emit(node.Span)
	}
}

func broadToolDeclarations(n *jsonconfig.Node) []*jsonconfig.Node {
	var nodes []*jsonconfig.Node
	if text, ok := n.Text(); ok && broadTool(text) {
		nodes = append(nodes, n)
	}

	return append(nodes, broadToolElementDeclarations(n)...)
}

func broadToolElementDeclarations(n *jsonconfig.Node) []*jsonconfig.Node {
	var nodes []*jsonconfig.Node
	if n == nil {
		return nodes
	}

	for _, item := range n.Elements {
		if text, ok := item.Text(); ok && broadTool(text) {
			nodes = append(nodes, item)
		}
	}

	return nodes
}

func inspectCommandHooks(ctx context.Context, hooks *jsonconfig.Node, emit func(source.Span)) {
	if hooks == nil {
		return
	}

	for _, event := range hooks.Members {
		if ctx.Err() != nil {
			return
		}

		for _, matcher := range event.Value.Elements {
			group := matcher.Get("hooks")
			if group == nil {
				continue
			}

			for _, hook := range group.Elements {
				kind, _ := hook.Get("type").Text()

				command := hook.Get("command")
				if kind == "command" && surfaceText(hook, "command", true) {
					emit(command.Span)
				}
			}
		}
	}
}

func inspectSensitiveToolParameters(ctx context.Context, root *jsonconfig.Node, emit func(source.Span)) {
	tools := root.Get("tools")
	if tools == nil {
		tools = root.Get("result").Get("tools")
	}

	if tools == nil {
		return
	}

	for _, tool := range tools.Elements {
		if ctx.Err() != nil {
			return
		}

		props := tool.Get("inputSchema").Get("properties")
		if props == nil {
			continue
		}

		for _, m := range props.Members {
			if highlySensitiveParameter(m.Key) {
				emit(m.KeySpan)
			}
		}
	}
}

func (a agentConfigCheck) inspectServers(ctx context.Context, root *jsonconfig.Node, emit func(source.Span)) {
	servers := root.Get("mcpServers")
	if servers == nil {
		servers = root.Get("mcp_servers")
	}

	if servers == nil {
		return
	}

	for _, member := range servers.Members {
		if ctx.Err() != nil {
			return
		}

		a.server(member.Value, emit)
	}
}

func (a agentConfigCheck) server(server *jsonconfig.Node, emit func(source.Span)) {
	if server == nil || server.Kind != jsonconfig.KindObject {
		return
	}

	switch a.id {
	case ruleSC001:
		inspectLauncherServer(server, emit)
	case ruleMC001:
		inspectPlaintextServer(server.Get("url"), emit)
	case ruleMC002:
		inspectServerCredentials(server, emit)
	}
}

func inspectLauncherServer(server *jsonconfig.Node, emit func(source.Span)) {
	command, ok := server.Get("command").Text()

	args := server.Get("args")
	if !ok || args == nil || args.Kind != jsonconfig.KindArray {
		return
	}

	for _, arg := range args.Elements {
		if arg.Kind != jsonconfig.KindString {
			return
		}
	}

	for _, n := range unpinnedLauncher(command, args.Elements) {
		emit(n.Span)
	}
}

func inspectPlaintextServer(n *jsonconfig.Node, emit func(source.Span)) {
	if text, ok := n.Text(); ok {
		u, err := url.Parse(text)
		if err == nil && strings.EqualFold(u.Scheme, "http") && u.Hostname() != "" && !loopbackHost(u.Hostname()) {
			emit(n.Span)
		}
	}
}

func inspectServerCredentials(server *jsonconfig.Node, emit func(source.Span)) {
	for _, field := range []string{"env", "headers", "http_headers"} {
		container := server.Get(field)
		if container == nil || container.Kind != jsonconfig.KindObject {
			continue
		}

		for _, m := range container.Members {
			if !credentialFieldName(m.Key) {
				continue
			}

			if text, ok := m.Value.Text(); ok && credentialLiteral(text) {
				emit(m.Value.Span)
			}
		}
	}

	inspectURLCredential(server.Get("url"), emit)
}

func credentialFieldName(key string) bool {
	key = strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	return literals.SensitiveName(key) || slices.Contains([]string{"AUTHORIZATION", "PROXY_AUTHORIZATION"}, key)
}

func inspectURLCredential(n *jsonconfig.Node, emit func(source.Span)) {
	if text, ok := n.Text(); ok {
		u, err := url.Parse(text)
		if err == nil && u.User != nil {
			if p, yes := u.User.Password(); yes && credentialLiteral(p) {
				emit(n.Span)
			}
		}
	}
}

// Scoped trees retain ORIGINAL source spans; only a wrapper role is supplied by
// discovery. This is not execution or trust in configuration field contents.
func (a agentConfigCheck) inspectScope(ctx context.Context, n *jsonconfig.Node, role string, emit func(source.Span)) {
	if n.Kind != jsonconfig.KindObject {
		return
	}

	if role == "mcp_config" && serverConfigRules[a.id] {
		a.inspectServerScope(ctx, n, emit)
	}

	if role == "hook_config" && a.id == ruleAC003 {
		if n.Get("hooks") != nil {
			a.inspect(ctx, n, emit)
			return
		}

		wrapper := &jsonconfig.Node{Kind: jsonconfig.KindObject, Members: []jsonconfig.Member{{Key: "hooks", Value: n}}}
		a.inspect(ctx, wrapper, emit)
	}
}

func (a agentConfigCheck) inspectServerScope(ctx context.Context, n *jsonconfig.Node, emit func(source.Span)) {
	maps := make([]*jsonconfig.Node, 0)
	if v := n.Get("mcpServers"); v != nil {
		maps = append(maps, v)
	}

	if v := n.Get("mcp_servers"); v != nil {
		maps = append(maps, v)
	}

	if len(maps) == 0 {
		maps = append(maps, n)
	}

	for _, servers := range maps {
		for _, m := range servers.Members {
			if ctx.Err() != nil {
				return
			}

			a.server(m.Value, emit)
		}
	}
}

// Agent checks focus on installable instructions/configuration rather than
// generic language quality. Config declarations are NOT effective permissions:
// trust, precedence and external host policy remain outside this offline scan.
//
//nolint:gochecknoglobals // Cached rules contain only immutable descriptors and compiled regexps; callers receive detached lists.
var compiledAgentRules = sync.OnceValue(buildAgentRules)

func agentRules() []Analyzer {
	return append([]Analyzer(nil), compiledAgentRules()...)
}

func buildAgentRules() []Analyzer {
	return []Analyzer{
		agentSignal(rulePI002, "Instruction to conceal actions from the user", `(?i)\b(?:do not|don't|never)[\t ]+(?:tell|inform|notify)[\t ]+(?:the[\t ]+)?user\b|(?i:не)[\t ]+(?:сообщай(?:те)?|рассказывай(?:те)?|уведомляй(?:те)?)[\t ]+пользовател(?:ю|я)`, "prompt-injection", "Narrow English/Russian concealment wording only; quotation, legitimate privacy instructions and negation require review."),
		agentSignal(ruleAG001, "Agent approval or sandbox bypass flag is referenced", `(?:--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox)\b`, "approval-bypass", "A literal flag reference, not proof of invocation. A prohibition or example can match; host restrictions are not evaluated."),
		agentSignal(ruleAG002, "Claude-style dynamic context command marker", "(?m)(?:^|[\\t ])!`[^`\\r\\n]+`", "preprocessing-execution", "Recognizes a single-line marker, not all Claude preprocessing forms. It can be an example, is not executed, and is not classified as malicious by itself."),
		agentConfigCheck{id: ruleAC001},
		agentConfigCheck{id: ruleAC002},
		agentConfigCheck{id: ruleAC003},
		agentConfigCheck{id: ruleSC001},
		agentConfigCheck{id: ruleMC001},
		agentConfigCheck{id: ruleMC002},
		agentConfigCheck{id: ruleMC003},
		bundledSurface{id: ruleBH1},
		bundledSurface{id: ruleBH2},
		bundledSurface{id: ruleBH3},
		bundledSurface{id: ruleBH4},
	}
}

func agentSignal(id, title, expression, category, limitation string) Analyzer {
	return literal{
		rule: report.Rule{
			ID: id, Version: "1", Title: title, Description: title,
			Severity: report.Medium, Category: category, Method: "literal-agent-signal", Limitation: limitation,
		},
		expression: regexp.MustCompile(expression),
		hint:       literalFilter(expression),
	}
}

func broadTool(s string) bool {
	s = strings.TrimSpace(s)
	return s == "*" || s == "Bash" || s == "Bash(*)" || s == "Bash:*" || s == "mcp__*"
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.EqualFold(host, "localhost.") {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

func credentialLiteral(value string) bool {
	s := strings.TrimSpace(value)
	if s == "" {
		return false
	}
	// Remove references, not entire strings containing one: ${TOKEN}-literal
	// still embeds a literal. Lowercase env values remain allowed by this hint.
	s = strings.TrimSpace(environmentReference.ReplaceAllString(s, ""))

	return s != "" && !strings.EqualFold(s, "Bearer") && !strings.EqualFold(s, "Basic")
}

func highlySensitiveParameter(name string) bool {
	s := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
	switch s {
	case "password", "apikey", "privatekey", "sshprivatekey", "systemprompt", "conversationhistory", "chathistory", "accesstoken", "refreshtoken":
		return true
	}

	return false
}

// A small explicit argv model; does not run package managers or resolve PATH.
// Unknown flags/wrappers are outside this check, never guessed as package names.
func unpinnedLauncher(command string, args []*jsonconfig.Node) []*jsonconfig.Node {
	base := strings.ToLower(path.Base(strings.ReplaceAll(command, "\\", "/")))

	base = strings.TrimSuffix(strings.TrimSuffix(base, ".exe"), ".cmd")
	switch launcherFamilies[base] {
	case "go":
		return unpinnedGoLauncher(args)
	case "python":
		return unpinnedPythonLauncher(base, args)
	case "container":
		return unpinnedContainerLauncher(args)
	default:
		return unpinnedNodeLauncher(base, args)
	}
}

func unpinnedGoLauncher(args []*jsonconfig.Node) []*jsonconfig.Node {
	if len(args) < 2 || args[0].String != "run" || strings.HasPrefix(args[1].String, "-") {
		return nil
	}

	n := args[1]

	at := strings.LastIndexByte(n.String, '@')
	if at < 1 {
		return nil
	} // local/unchecked-module launches are not claimed pinned

	if !textmatch.Version(strings.TrimPrefix(n.String[at+1:], "v")) {
		return []*jsonconfig.Node{n}
	}

	return nil
}

// Launcher grammars consume a known prefix and known flag-only options before
// examining a single package/image operand. Unknown options remain unknown.
func launcherOperand(args []*jsonconfig.Node, flags map[string]bool) *jsonconfig.Node {
	for _, node := range args {
		if flags[node.String] {
			continue
		}

		if strings.HasPrefix(node.String, "-") {
			return nil
		}

		return node
	}

	return nil
}

func unpinnedPythonLauncher(base string, args []*jsonconfig.Node) []*jsonconfig.Node {
	prefix := pythonLauncherPrefixes[base]
	if len(args) < len(prefix) {
		return nil
	}

	for i, word := range prefix {
		if args[i].String != word {
			return nil
		}
	}

	node := launcherOperand(args[len(prefix):], pythonLauncherFlags)
	if node != nil && !pinnedPythonRequirement(node.String) {
		return []*jsonconfig.Node{node}
	}

	return nil
}

func pinnedPythonRequirement(value string) bool {
	name, version, ok := strings.Cut(value, "==")
	return ok && name != "" && version != "" && !strings.ContainsAny(version, "*<>=!~, ;/\\")
}

func unpinnedContainerLauncher(args []*jsonconfig.Node) []*jsonconfig.Node {
	if len(args) < 2 || !containerLauncherCommands[args[0].String] {
		return nil
	}

	node := launcherOperand(args[1:], containerLauncherFlags)
	if node != nil && !pinnedContainerDigest(node.String) {
		return []*jsonconfig.Node{node}
	}

	return nil
}

func pinnedContainerDigest(value string) bool {
	at := strings.LastIndex(value, "@sha256:")
	if at < 1 || len(value[at+8:]) != 64 {
		return false
	}

	_, err := hex.DecodeString(value[at+8:])

	return err == nil
}

func unpinnedNodeLauncher(base string, args []*jsonconfig.Node) []*jsonconfig.Node {
	npmMode := base == "npm"
	if npmMode {
		if len(args) == 0 || args[0].String != "exec" {
			return nil
		}

		args = args[1:]
	} else if base != "npx" {
		return nil
	}

	return unpinnedNodeArguments(args, npmMode)
}

func unpinnedNodeArguments(args []*jsonconfig.Node, npmMode bool) []*jsonconfig.Node {
	var bad []*jsonconfig.Node

	state := nodeInitialNpx
	if npmMode {
		state = nodeInitialNpm
	}

	for i := 0; i < len(args); i++ {
		token := parseNodeLauncherToken(args, i, npmMode)

		transition, valid := nodeLauncherGrammar[state][token.kind]
		if !valid {
			return bad
		}

		if transition.inspect && !pinnedNPM(token.value) {
			bad = append(bad, token.node)
		}

		state = transition.next
		if transition.terminal {
			return bad
		}

		i = token.next
	}

	return bad
}

func classifyNodeLauncherToken(value string, npmMode bool) nodeLauncherTokenKind {
	if npmMode && value == "-p" {
		return nodeTokenInvalid
	}

	if kind, known := nodeLauncherTokens[value]; known {
		return kind
	}

	if strings.HasPrefix(value, "--package=") {
		return nodeTokenInlinePackage
	}

	if strings.HasPrefix(value, "-") {
		return nodeTokenInvalid
	}

	return nodeTokenBare
}

func parseNodeLauncherToken(args []*jsonconfig.Node, i int, npmMode bool) nodeLauncherToken {
	token := nodeLauncherToken{
		kind:  classifyNodeLauncherToken(args[i].String, npmMode),
		node:  args[i],
		value: args[i].String,
		next:  i,
	}
	switch token.kind {
	case nodeTokenPackage, nodeTokenBarrier:
		if i+1 >= len(args) {
			token.kind = nodeTokenInvalid
			return token
		}

		token.node = args[i+1]
		token.value = token.node.String
		token.next = i + 1
	case nodeTokenInlinePackage:
		token.kind = nodeTokenPackage
		token.value = strings.TrimPrefix(token.value, "--package=")
	default:
		// Bare, flag and invalid tokens need no additional operand.
		return token
	}

	return token
}

func pinnedNPM(s string) bool {
	at := strings.LastIndexByte(s, '@')
	if at < 1 || !npmPackageName.MatchString(s[:at]) {
		return false
	}

	return textmatch.Version(s[at+1:])
}

func scopedNode(n *jsonconfig.Node, span source.Span) *jsonconfig.Node {
	if n == nil || span.Start > n.Span.End || span.End < n.Span.Start {
		return nil
	}
	// Config file nodes use the whole-file range including whitespace; inline
	// nodes use exact token spans. Never match an arbitrary containing object.
	if n.Span == span {
		return n
	}

	for _, m := range n.Members {
		if child := scopedNode(m.Value, span); child != nil {
			return child
		}
	}

	for _, e := range n.Elements {
		if child := scopedNode(e, span); child != nil {
			return child
		}
	}

	return nil
}
