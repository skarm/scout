package discovery

import (
	"runtime"
	"slices"

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
	defaultHome       location
	project, system   []location
	systemDefault     string
	systemDarwin      string
	systemWindows     string
}

//nolint:gochecknoglobals // Read-only discovery layouts and their publication boundaries.
var agentLayouts = []agentLayout{
	{
		id: report.HostCodex, label: "Codex", homeFlag: "codex-home", homeEnv: "CODEX_HOME",
		homeOverride:  func(o *Options) *string { return &o.CodexHome },
		user:          []location{{".agents/skills", (*tree).skills}},
		defaultHome:   location{codexHomeDirectory, (*tree).codex},
		relocated:     []location{{".", (*tree).codex}},
		project:       []location{{codexHomeDirectory, (*tree).codexProject}, {".agents/skills", (*tree).skills}},
		system:        []location{{"config.toml", (*tree).codexConfig}, {"skills", (*tree).skills}},
		systemDefault: "/etc/codex", systemWindows: `C:\ProgramData\OpenAI\Codex`,
	},
	{
		id: report.HostClaudeCode, label: "Claude Code", homeFlag: "claude-home", homeEnv: "CLAUDE_CONFIG_DIR",
		homeOverride:  func(o *Options) *string { return &o.ClaudeHome },
		user:          []location{{claudeGlobalConfig, (*tree).claudeGlobal}},
		defaultHome:   location{claudeHomeDirectory, (*tree).claude},
		relocated:     []location{{claudeGlobalConfig, (*tree).claudeGlobal}, {".", (*tree).claude}},
		project:       []location{{artifact.MCPConfig, (*tree).mcpFile}, {claudeHomeDirectory, (*tree).claudeProject}},
		system:        []location{{"managed-mcp.json", (*tree).mcpFile}, {"managed-settings.json", (*tree).settings}},
		systemDefault: "/etc/claude-code", systemDarwin: "/Library/Application Support/ClaudeCode", systemWindows: `C:\Program Files\ClaudeCode`,
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
