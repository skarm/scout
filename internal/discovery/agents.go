package discovery

import (
	"runtime"
	"slices"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

// AllAgents selects every registered discovery layout.
const AllAgents = "all"

type location struct {
	path string
	read func(*tree, string)
}

type agentLayout struct {
	id, label         string
	homeFlag, homeEnv string
	homeOverride      func(*Options) *string
	user, relocated   []location
	defaultHome       []location
	project, system   []location
	systemDefault     string
	systemDarwin      string
	systemWindows     string
	systemUnixOnly    bool
}

//nolint:gochecknoglobals // Read-only discovery layouts and their publication boundaries.
var agentLayouts = []agentLayout{
	{
		id: report.HostCodex, label: "Codex", homeFlag: "codex-home", homeEnv: "CODEX_HOME",
		homeOverride:  func(o *Options) *string { return &o.CodexHome },
		user:          []location{{".agents/skills", (*tree).skills}},
		defaultHome:   []location{{codexHomeDirectory, (*tree).codex}},
		relocated:     []location{{".", (*tree).codex}},
		project:       []location{{codexHomeDirectory, (*tree).codexProject}, {".agents/skills", (*tree).skills}},
		system:        []location{{"config.toml", (*tree).codexConfig}, {"skills", (*tree).skills}},
		systemDefault: "/etc/codex", systemWindows: `C:\ProgramData\OpenAI\Codex`,
	},
	{
		id: report.HostClaudeCode, label: "Claude Code", homeFlag: "claude-home", homeEnv: "CLAUDE_CONFIG_DIR",
		homeOverride:  func(o *Options) *string { return &o.ClaudeHome },
		user:          []location{{claudeGlobalConfig, (*tree).claudeGlobal}},
		defaultHome:   []location{{claudeHomeDirectory, (*tree).claude}},
		relocated:     []location{{claudeGlobalConfig, (*tree).claudeGlobal}, {".", (*tree).claude}},
		project:       []location{{artifact.MCPConfig, (*tree).mcpFile}, {claudeHomeDirectory, (*tree).claudeProject}},
		system:        []location{{"managed-mcp.json", (*tree).mcpFile}, {"managed-settings.json", (*tree).settings}},
		systemDefault: "/etc/claude-code", systemDarwin: "/Library/Application Support/ClaudeCode", systemWindows: `C:\Program Files\ClaudeCode`,
	},
	{
		id: report.HostCursor, label: "Cursor", homeFlag: "cursor-home", homeEnv: "CURSOR_CONFIG_DIR",
		homeOverride:  func(o *Options) *string { return &o.CursorHome },
		user:          []location{{".agents/skills", (*tree).skills}},
		defaultHome:   []location{{agentconfig.CursorDirectory, (*tree).cursorUser}},
		relocated:     []location{{".", (*tree).cursorUser}},
		project:       []location{{agentconfig.CursorDirectory, (*tree).cursorConfig}, {".agents/skills", (*tree).skills}},
		system:        []location{{"hooks.json", (*tree).nativeHooks}},
		systemDefault: "/etc/cursor", systemDarwin: "/Library/Application Support/Cursor", systemWindows: `C:\ProgramData\Cursor`,
	},
	{
		id: report.HostCopilotCLI, label: "Copilot CLI", homeFlag: "copilot-home", homeEnv: "COPILOT_HOME",
		homeOverride: func(o *Options) *string { return &o.CopilotHome },
		defaultHome:  []location{{agentconfig.CopilotDirectory, (*tree).copilotUser}},
		relocated:    []location{{".", (*tree).copilotUser}},
		project: []location{
			{artifact.MCPConfig, (*tree).copilotMCP},
			{agentconfig.CopilotProjectMCP, (*tree).copilotMCP},
			{agentconfig.CopilotProjectHooks, (*tree).copilotHooks},
			{agentconfig.CopilotProjectSettings, (*tree).copilotSettings},
			{agentconfig.CopilotProjectLocalSettings, (*tree).copilotSettings},
			{".github/skills", (*tree).skills},
			{".github/agents", (*tree).agents},
			{".agents/skills", (*tree).skills},
			{".claude/skills", (*tree).skills},
		},
	},
	{
		id: report.HostOpenCode, label: "OpenCode", homeFlag: "opencode-home", homeEnv: "OPENCODE_CONFIG_DIR",
		homeOverride:  func(o *Options) *string { return &o.OpenCodeHome },
		user:          []location{{".agents/skills", (*tree).skills}, {".claude/skills", (*tree).skills}},
		defaultHome:   []location{{".config/opencode", (*tree).openCodeDirectory}},
		relocated:     []location{{".", (*tree).openCodeDirectory}},
		project:       []location{{agentconfig.OpenCodeConfig, (*tree).openCodeConfig}, {agentconfig.OpenCodeConfigJSONC, (*tree).openCodeConfig}, {agentconfig.OpenCodeDirectory, (*tree).openCodeDirectory}, {".agents/skills", (*tree).skills}, {".claude/skills", (*tree).skills}},
		system:        []location{{".", (*tree).openCodeDirectory}},
		systemDefault: "/etc/opencode", systemDarwin: "/Library/Application Support/opencode", systemWindows: `C:\ProgramData\opencode`,
	},
	{
		id: report.HostGeminiCLI, label: "Gemini CLI", homeFlag: "gemini-home", homeEnv: "GEMINI_CLI_HOME",
		homeOverride: func(o *Options) *string { return &o.GeminiHome },
		defaultHome:  []location{{artifact.GeminiDirectory, (*tree).geminiUser}, {".agents/skills", (*tree).geminiSkills}},
		relocated:    []location{{artifact.GeminiDirectory, (*tree).geminiUser}, {".agents/skills", (*tree).geminiSkills}},
		project: []location{
			{artifact.GeminiDirectory, (*tree).geminiDirectory},
			{agentconfig.GeminiContext, (*tree).geminiContext},
			{".agents/skills", (*tree).geminiSkills},
		},
		system: []location{
			{artifact.GeminiSettings, (*tree).geminiSettings},
			{artifact.GeminiSystemDefaults, (*tree).geminiSettings},
			{"policies", (*tree).geminiPolicies},
		},
		systemDefault: "/etc/gemini-cli", systemDarwin: "/Library/Application Support/GeminiCli", systemWindows: `C:\ProgramData\gemini-cli`,
	},
	{
		id: report.HostOpenClaw, label: "OpenClaw", homeFlag: "openclaw-home", homeEnv: "OPENCLAW_STATE_DIR",
		homeOverride: func(o *Options) *string { return &o.OpenClawHome },
		defaultHome:  []location{{artifact.OpenClawDirectory, (*tree).openClawState}, {".agents/skills", (*tree).skills}},
		relocated:    []location{{".", (*tree).openClawState}},
		project: []location{
			{"skills", (*tree).skills},
			{".agents/skills", (*tree).skills},
			{"hooks", (*tree).openClawHooks},
			{".openclaw/extensions", (*tree).openClawPackages},
		},
	},
	{
		id: report.HostGrokCLI, label: "Grok CLI", homeFlag: "grok-home", homeEnv: "GROK_HOME",
		homeOverride:  func(o *Options) *string { return &o.GrokHome },
		user:          []location{{".agents/skills", (*tree).skills}, {".agents/commands", (*tree).commands}},
		defaultHome:   []location{{artifact.GrokDirectory, (*tree).grokUser}},
		relocated:     []location{{".", (*tree).grokUser}},
		project:       []location{{artifact.GrokDirectory, (*tree).grokProject}},
		system:        []location{{artifact.GrokManagedConfig, (*tree).grokTOML}, {artifact.GrokRequirements, (*tree).grokTOML}},
		systemDefault: "/etc/grok", systemUnixOnly: true,
	},
	{
		id: report.HostDeepSeekHarness, label: "DeepSeek Harness", homeFlag: "deepseek-home", homeEnv: "DSH_HOME",
		homeOverride: func(o *Options) *string { return &o.DeepSeekHome },
		user:         []location{{".agents", (*tree).deepSeekShared}},
		defaultHome:  []location{{artifact.DeepSeekDirectory, (*tree).deepSeekHome}},
		relocated:    []location{{".", (*tree).deepSeekHome}},
		project: []location{
			{".agents/skills", (*tree).deepSeekSkills},
			{".dsh/skills", (*tree).deepSeekSkills},
			{"AGENTS.md", (*tree).geminiContext},
			{"AGENTS.local.md", (*tree).geminiContext},
			{"CLAUDE.md", (*tree).geminiContext},
			{"CLAUDE.local.md", (*tree).geminiContext},
			{artifact.DeepSeekCordis, (*tree).deepSeekConfig},
			{artifact.DeepSeekPatch, (*tree).deepSeekConfig},
			{"package.json", (*tree).deepSeekManifest},
		},
	},
}

// AgentSelectors returns the discovery selectors in CLI help order.
func AgentSelectors() []string {
	result := make([]string, 1, len(agentLayouts)+1)

	result[0] = AllAgents
	for _, layout := range agentLayouts {
		result = append(result, layout.id)
	}

	return result
}

// ValidAgent reports whether the selector names a registered discovery layout or all agents.
func ValidAgent(selector string) bool { return len(selectedAgents(selector)) > 0 }

// HomeOverride binds one registered operator override to an Options value.
type HomeOverride struct {
	Agent, Flag, Env, Label string
	Path                    *string
}

// HomeOverrides returns the supported override flags and environment variables.
func (o *Options) HomeOverrides() []HomeOverride {
	overrides := make([]HomeOverride, 0, len(agentLayouts))
	for _, layout := range agentLayouts {
		overrides = append(overrides, HomeOverride{layout.id, layout.homeFlag, layout.homeEnv, layout.label, layout.homeOverride(o)})
	}

	return overrides
}

func selectedAgents(selector string) []agentLayout {
	if selector == AllAgents {
		return agentLayouts
	}

	if i := slices.IndexFunc(agentLayouts, func(layout agentLayout) bool { return layout.id == selector }); i >= 0 {
		return agentLayouts[i : i+1]
	}

	return nil
}

func (a agentLayout) systemRoot() string {
	switch runtime.GOOS {
	case "windows":
		if a.systemUnixOnly {
			return ""
		}

		if a.systemWindows != "" {
			return a.systemWindows
		}
	case "darwin":
		if a.systemDarwin != "" {
			return a.systemDarwin
		}
	}

	return a.systemDefault
}
