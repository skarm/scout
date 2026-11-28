package report

// Host identifiers select the interpretation contract for captured declarations.
const (
	// HostAuto identifies auto.
	HostAuto = "auto"
	// HostClaudeCode identifies claude-code.
	HostClaudeCode = "claude-code"
	// HostCodex identifies codex.
	HostCodex = "codex"
	// HostGeminiCLI identifies Gemini CLI extensions.
	HostGeminiCLI = "gemini-cli"
	// HostAgentSkills identifies agent-skills.
	HostAgentSkills = "agent-skills"
	// HostAgentPlugins identifies host-independent portable plugin interpretation.
	HostAgentPlugins = "agent-plugins"
)
