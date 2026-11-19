package artifact

// Names shared by discovery, capture and analysis of host declarations.
const (
	SkillManifest              = "SKILL.md"
	ClaudePluginManifest       = ".claude-plugin/plugin.json"
	CodexPluginManifest        = ".codex-plugin/plugin.json"
	ClaudeSettings             = "settings.json"
	ClaudeLocalSettings        = "settings.local.json"
	ClaudeProjectSettings      = ".claude/" + ClaudeSettings
	ClaudeProjectLocalSettings = ".claude/" + ClaudeLocalSettings
)
