package agentconfig

import (
	"iter"
	"slices"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

// ZCodeManifests lists the native and compatibility package manifests in order.
func ZCodeManifests() []string {
	return []string{artifact.ZCodePluginManifest, artifact.ClaudePluginManifest}
}

func ZCodeMCP(root *jsonconfig.Node) *jsonconfig.Node {
	return root.Get("mcp").Get("servers")
}

// ZCodeHasMCP reports whether a native map contains a usable transport
// declaration and can therefore shadow the shared .agents map in its scope.
func ZCodeHasMCP(servers *jsonconfig.Node) bool {
	return servers != nil && slices.ContainsFunc(servers.Members, func(server jsonconfig.Member) bool {
		n := server.Value
		if enabled := n.Get("enabled"); enabled != nil && enabled.Kind != jsonconfig.KindBool {
			return false
		}

		typ, typed := n.Get("type").Text()
		if n.Get("type") != nil && !typed {
			return false
		}

		command, _ := n.Get("command").Text()
		endpoint, _ := n.Get("url").Text()

		switch typ {
		case "stdio":
			return strings.TrimSpace(command) != ""
		case "http", "sse":
			return strings.TrimSpace(endpoint) != ""
		case "":
			return !typed && (strings.TrimSpace(command) != "" || strings.TrimSpace(endpoint) != "")
		default:
			return false
		}
	})
}

func ZCodeRuntimeHooks(root *jsonconfig.Node) bool {
	return root.Get("hooks").Get("events") != nil
}

type ZCodeHook struct {
	Node, Launch *jsonconfig.Node
	Event, Key   string
	Args         []string
	Process      bool
	Disabled     bool
}

// ZCodeHooks reads native events and grouped plugin hooks from their original
// JSON nodes. Invalid declarations carry a nil launch and remain observable.
func ZCodeHooks(root *jsonconfig.Node) iter.Seq[ZCodeHook] {
	return func(yield func(ZCodeHook) bool) {
		key := ""

		n := root
		if wrapped := n.Get("hooks"); wrapped != nil {
			n, key = wrapped, "/hooks"
		}

		disabled := zcodeDisabled(n)
		if events := n.Get("events"); events != nil {
			n, key = events, key+"/events"
		}

		if n == nil {
			return
		}

		if n.Kind != jsonconfig.KindObject {
			yield(ZCodeHook{Node: n, Key: key})
			return
		}

		for _, m := range n.Members {
			if zcodeHookEvent(m.Key) && !zcodeHookGroups(m, key+"/"+m.Key, disabled, yield) {
				return
			}
		}
	}
}

func zcodeHookGroups(event jsonconfig.Member, key string, disabled bool, yield func(ZCodeHook) bool) bool {
	if event.Value.Kind != jsonconfig.KindArray {
		return yield(ZCodeHook{Node: event.Value, Event: event.Key, Key: key})
	}

	for i, group := range event.Value.Elements {
		groupKey := key + "/" + strconv.Itoa(i) + "/hooks"

		handlers := group.Get("hooks")
		if handlers == nil || handlers.Kind != jsonconfig.KindArray {
			if !yield(ZCodeHook{Node: group, Event: event.Key, Key: groupKey}) {
				return false
			}

			continue
		}

		for j, handler := range handlers.Elements {
			hook := ZCodeHook{Node: handler, Event: event.Key, Key: groupKey + "/" + strconv.Itoa(j), Disabled: disabled || zcodeDisabled(handler)}
			hook.readLaunch()

			if !yield(hook) {
				return false
			}
		}
	}

	return true
}

func (h *ZCodeHook) readLaunch() {
	kind, _ := h.Node.Get("type").Text()
	if kind != "process" && kind != "command" {
		return
	}

	launch := h.Node.Get("command")

	raw, ok := launch.Text()
	if !ok || strings.TrimSpace(raw) == "" {
		return
	}

	if h.Process = kind == "process"; h.Process {
		if args := h.Node.Get("args"); args != nil {
			if args.Kind != jsonconfig.KindArray {
				return
			}

			for _, arg := range args.Elements {
				word, ok := arg.Text()
				if !ok {
					return
				}

				h.Args = append(h.Args, word)
			}
		}
	}

	h.Launch = launch
}

func zcodeDisabled(n *jsonconfig.Node) bool {
	enabled := n.Get("enabled")
	return enabled != nil && enabled.Kind == jsonconfig.KindBool && !enabled.Bool
}

func zcodeHookEvent(name string) bool {
	switch name {
	case "SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "PostToolUseFailure", "Stop":
		return true
	default:
		return false
	}
}
