package agentconfig

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

var kimiPluginID = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*(@[A-Za-z0-9_-]+)?$`)

func KimiPluginID(id string) bool { return kimiPluginID.MatchString(id) }

func KimiManifests() []string {
	return []string{artifact.KimiPluginManifest, artifact.KimiPluginDotManifest}
}

func KimiHookEvent(name string) bool {
	switch name {
	case "PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "PermissionResult",
		"UserPromptSubmit", "UserPromptQueued", "TurnStarted", "Stop", "StopFailure", "Interrupt",
		"SessionStart", "SessionEnd", "SessionHeartbeat", "SubagentStart", "SubagentStop", "TaskStarted",
		"PreCompact", "PostCompact", "Notification":
		return true
	default:
		return false
	}
}

// KimiHookCommand returns the command of a valid flat hook declaration.
func KimiHookCommand(n *jsonconfig.Node) *jsonconfig.Node {
	event, _ := n.Get("event").Text()
	command := n.Get("command")

	if text, ok := command.Text(); !KimiHookEvent(event) || !ok || strings.TrimSpace(text) == "" {
		return nil
	}

	for _, member := range n.Members {
		switch member.Key {
		case "event", "command":
		case "matcher":
			if member.Value.Kind != jsonconfig.KindString {
				return nil
			}
		case "timeout":
			value, err := strconv.ParseFloat(member.Value.String, 64)
			if member.Value.Kind != jsonconfig.KindNumber || err != nil || math.Trunc(value) != value || value < 1 || value > 600 {
				return nil
			}
		default:
			return nil
		}
	}

	return command
}

// KimiInstalledRecord reads the stable part of one installed.json record.
func KimiInstalledRecord(n *jsonconfig.Node) (id, root string, enabled, valid bool) {
	id, _ = n.Get("id").Text()
	root, _ = n.Get("root").Text()
	state := n.Get("enabled")

	return id, root, state != nil && state.Bool, KimiPluginID(id) && root != "" && state != nil && state.Kind == jsonconfig.KindBool
}

func KimiRemoteMCP(n *jsonconfig.Node) bool {
	environment, _ := n.Get("environment_id").Text()
	executor, _ := n.Get("executor").Text()

	return environment != "" && environment != "local" || environment == "" && executor == "kaos"
}

// KimiMCPTransport mirrors the transport discriminator and its defaults.
func KimiMCPTransport(n *jsonconfig.Node) string {
	if transport := n.Get("transport"); transport != nil {
		switch transport.String {
		case "stdio", "http", "sse":
			return transport.String
		default:
			return ""
		}
	}

	if _, ok := n.Get("command").Text(); ok {
		return "stdio"
	}

	if _, ok := n.Get("url").Text(); ok {
		return "http"
	}

	return ""
}

type KimiInstruction struct {
	Name, Key string
	Node      *jsonconfig.Node
}

// KimiPluginInstructions selects prompt contributions and session-start skill
// declarations. The referenced skill name remains a declaration.
func KimiPluginInstructions(n *jsonconfig.Node) []KimiInstruction {
	var found []KimiInstruction

	for _, value := range []KimiInstruction{
		{"systemPrompt", "/systemPrompt", n.Get("systemPrompt")},
		{"skillInstructions", "/skillInstructions", n.Get("skillInstructions")},
		{"sessionStart.skill", "/sessionStart/skill", n.Get("sessionStart").Get("skill")},
	} {
		if text, ok := value.Node.Text(); ok && strings.TrimSpace(text) != "" {
			found = append(found, value)
		}
	}

	return found
}
