// Package hookevent defines the supported hook event names.
package hookevent

// Known reports whether a name is part of the supported hook event grammar.
func Known(name string) bool {
	switch name {
	case "ConfigChange", "CwdChanged", "DirectoryAdded", "Elicitation", "ElicitationResult", "FileChanged", "InstructionsLoaded", "MessageDisplay", "Notification", "PermissionDenied", "PermissionRequest", "PostCompact", "PostToolBatch", "PostToolUse", "PostToolUseFailure", "PreCompact", "PreToolUse", "SessionEnd", "SessionStart", "Setup", "Stop", "StopFailure", "SubagentStart", "SubagentStop", "TaskCompleted", "TaskCreated", "TeammateIdle", "UserPromptExpansion", "UserPromptSubmit", "WorktreeCreate", "WorktreeRemove":
		return true
	default:
		return false
	}
}

// Gemini reports whether a name is a Gemini CLI hook event.
func Gemini(name string) bool {
	switch name {
	case "AfterAgent", "AfterModel", "AfterTool", "BeforeAgent", "BeforeModel", "BeforeTool", "BeforeToolSelection", "Notification", "PreCompress", "SessionEnd", "SessionStart":
		return true
	default:
		return false
	}
}

// Grok recognizes the supported Grok lifecycle events and documented Cursor aliases.
func Grok(name string) bool {
	switch name {
	case "SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure",
		"PermissionDenied", "Stop", "StopCancelled", "StopFailure", "Notification", "SubagentStart", "SubagentStop",
		"SubagentEnd", "PreCompact", "PostCompact",
		"sessionStart", "sessionEnd", "preToolUse", "postToolUse", "postToolUseFailure", "beforeShellExecution",
		"beforeMCPExecution", "beforeReadFile", "afterShellExecution", "afterMCPExecution", "afterFileEdit",
		"afterAgentResponse", "afterAgentThought", "beforeSubmitPrompt", "subagentStart", "subagentStop", "preCompact", "stop":
		return true
	default:
		return false
	}
}
