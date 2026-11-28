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
	// HostCursor identifies Cursor plugin and workspace declarations.
	HostCursor = "cursor"
	// HostCopilotCLI identifies GitHub Copilot CLI declarations.
	HostCopilotCLI = "copilot-cli"
	// HostOpenCode identifies OpenCode configuration and extensions.
	HostOpenCode = "opencode"
	// HostOpenClaw identifies OpenClaw configuration and native packages.
	HostOpenClaw = "openclaw"
	// HostGrokCLI identifies Grok Build CLI declarations.
	HostGrokCLI = "grok-cli"
	// HostDeepSeekHarness identifies DeepSeek Harness profiles and Cordis declarations.
	HostDeepSeekHarness = "deepseek-harness"
	// HostZCode identifies Z.ai ZCode runtime and plugin declarations.
	HostZCode = "zcode"

	// HostQwenCode identifies Qwen Code workspaces and extensions.
	HostQwenCode = "qwen-code"
)
