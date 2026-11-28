package agentconfig

import (
	"iter"
	"regexp"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

const (
	DeepSeekMCP     = "mcp-server"
	DeepSeekPlugin  = "plugin"
	DeepSeekInclude = "include"
	DeepSeekInvalid = "invalid"
	deepSeekManager = "@deepseek-ai/dsh-mcp-manager"
	deepSeekClient  = "@deepseek-ai/dsh-mcp-client"
)

var dshServerName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// DeepSeekDeclaration is a local Cordis declaration. Its state records
// literal configuration and does not model plugin resolution or patch stacking.
type DeepSeekDeclaration struct {
	Kind, Name, Key, State string
	Node                   *jsonconfig.Node
}

// DeepSeekRows walks the entry-list dialect shared by Cordis trees and patches.
// An insert is an entry list; config is only traversed as rows for Cordis groups.
func DeepSeekRows(root *jsonconfig.Node) iter.Seq[DeepSeekDeclaration] {
	return func(yield func(DeepSeekDeclaration) bool) {
		deepSeekRows(root, "", "unknown", yield)
	}
}

func deepSeekRows(list *jsonconfig.Node, key, state string, yield func(DeepSeekDeclaration) bool) bool {
	if list == nil {
		return true
	}

	if list.Kind != jsonconfig.KindArray {
		return yield(DeepSeekDeclaration{Kind: DeepSeekInvalid, Key: key, Node: list})
	}

	for i, row := range list.Elements {
		if !deepSeekRow(row, key+"/"+strconv.Itoa(i), state, yield) {
			return false
		}
	}

	return true
}

func deepSeekRow(row *jsonconfig.Node, key, inherited string, yield func(DeepSeekDeclaration) bool) bool {
	if row.Kind != jsonconfig.KindObject {
		return yield(DeepSeekDeclaration{Kind: DeepSeekInvalid, Key: key, Node: row})
	}

	if insert := row.Get("insert"); insert != nil {
		return deepSeekRows(insert, key+"/insert", inherited, yield)
	}

	name, _ := row.Get("name").Text()
	id, _ := row.Get("id").Text()
	config := row.Get("config")
	state := deepSeekRowState(row, inherited)

	switch name {
	case "cordis:group", "@deepseek-ai/cordis-plugin-group":
		return deepSeekRows(config, key+"/config", state, yield)
	case "cordis:include", "@deepseek-ai/cordis-plugin-include":
		return yield(DeepSeekDeclaration{Kind: DeepSeekInclude, Name: name, Key: key, State: state, Node: row})
	case deepSeekClient, deepSeekManager + "/server":
		label, _ := config.Get("serverName").Text()
		return deepSeekServer(label, key+"/config", state, config, yield)
	case deepSeekManager:
		return deepSeekServers(config.Get("servers"), key+"/config/servers", state, yield)
	case "":
		// The shipped profiles use this ID for the manager. A nameless
		// override has no authority to supply the effective plugin identity.
		if row.Get("name") == nil && id == "mcp-manager" && config.Get("servers") != nil {
			return deepSeekServers(config.Get("servers"), key+"/config/servers", state, yield)
		}

		name = id
	}

	return name == "" || yield(DeepSeekDeclaration{Kind: DeepSeekPlugin, Name: name, Key: key, State: state, Node: row})
}

func deepSeekRowState(row *jsonconfig.Node, inherited string) string {
	if inherited == "disabled" {
		return inherited
	}

	if disabled := row.Get("disabled"); disabled != nil && disabled.Kind == jsonconfig.KindBool {
		if disabled.Bool {
			return "disabled"
		}

		return "enabled"
	}

	return "unknown"
}

func deepSeekServers(servers *jsonconfig.Node, key, state string, yield func(DeepSeekDeclaration) bool) bool {
	if servers == nil {
		return true
	}

	if servers.Kind != jsonconfig.KindObject {
		if servers.Kind == jsonconfig.KindExpression {
			return true
		}

		return yield(DeepSeekDeclaration{Kind: DeepSeekInvalid, Key: key, Node: servers})
	}

	for _, member := range servers.Members {
		enabled := member.Value.Get("enabled")

		local := state
		if state != "disabled" && enabled != nil && enabled.Kind == jsonconfig.KindBool {
			local = "enabled"
			if !enabled.Bool {
				local = "disabled"
			}
		}

		token := strings.ReplaceAll(strings.ReplaceAll(member.Key, "~", "~0"), "/", "~1")
		if !deepSeekServer(member.Key, key+"/"+token, local, member.Value, yield) {
			return false
		}
	}

	return true
}

func deepSeekServer(name, key, state string, config *jsonconfig.Node, yield func(DeepSeekDeclaration) bool) bool {
	if config == nil {
		return true
	}

	if config.Kind == jsonconfig.KindExpression {
		return true
	}

	if config.Kind != jsonconfig.KindObject || !dshServerName.MatchString(name) {
		return yield(DeepSeekDeclaration{Kind: DeepSeekInvalid, Key: key, Node: config})
	}

	return yield(DeepSeekDeclaration{Kind: DeepSeekMCP, Name: name, Key: key, State: state, Node: config})
}

// DeepSeekManifest distinguishes DSH package metadata from ordinary npm files.
func DeepSeekManifest(root *jsonconfig.Node) bool {
	dsh := root.Get("dsh")
	return dsh.Get("profile") != nil || dsh.Get("bundle") != nil
}

func DeepSeekBundles(root *jsonconfig.Node) *jsonconfig.Node {
	return root.Get("dsh").Get("profile").Get("bundles")
}

func DeepSeekPatchDeclarations(root *jsonconfig.Node) *jsonconfig.Node {
	return root.Get("dsh").Get("bundle").Get("patch")
}
