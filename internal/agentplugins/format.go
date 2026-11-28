// Package agentplugins interprets portable package declarations without I/O.
package agentplugins

import (
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

const (
	ManifestFile = "plugin.json"
	MCPFile      = "mcp.json"
	HooksFile    = "hooks.json"
	SkillsDir    = "skills"
	MCPField     = "mcpServers"
	HooksField   = "hooks"
	schemaField  = "$schema"
	schemaBase   = "https://agent-plugins.org/schemas/"
)

// Version is the schema revision selected by a manifest.
type Version string

const (
	V1_0        Version = "1.0.0"
	V1_1        Version = "1.1.0"
	Unsupported Version = "unsupported"
)

// ManifestVersion distinguishes portable manifests from other plugin.json files.
func ManifestVersion(root *jsonconfig.Node) Version {
	schema, _ := root.Get(schemaField).Text()
	switch schema {
	case V1_0.schema(ManifestFile):
		return V1_0
	case V1_1.schema(ManifestFile):
		return V1_1
	}

	if strings.HasPrefix(schema, schemaBase) {
		return Unsupported
	}

	return ""
}

func (v Version) schema(file string) string {
	return schemaBase + string(v) + "/" + strings.TrimSuffix(file, ".json") + ".schema.json"
}

// Manifest records which portable metadata was understood.
type Manifest struct {
	Name          string
	Valid         bool
	IgnoredFields bool
}

// ReadManifest validates the closed portable metadata. Unknown fields have no
// interpretation, but callers can retain valid components and report a gap.
func (v Version) ReadManifest(root *jsonconfig.Node) Manifest {
	name, _ := root.Get("name").Text()

	m := Manifest{Name: name, Valid: validName(name)}
	if !m.Valid {
		return m
	}

	for _, field := range root.Members {
		switch field.Key {
		case schemaField, "name":
		case "version", "description", "homepage", "repository", "license":
			m.Valid = m.Valid && field.Value.Kind == jsonconfig.KindString
		case "displayName":
			if v == V1_1 {
				m.Valid = m.Valid && field.Value.Kind == jsonconfig.KindString
			} else {
				m.IgnoredFields = true
			}
		case "keywords":
			m.Valid = m.Valid && optionalStrings(field.Value, jsonconfig.KindArray)
		case "author":
			m.Valid = m.Valid && validAuthor(field.Value)
		case "extensions":
			m.IgnoredFields = m.IgnoredFields || field.Value.Kind != jsonconfig.KindObject
		default:
			m.IgnoredFields = true
		}
	}

	return m
}

func validAuthor(n *jsonconfig.Node) bool {
	if n.Kind != jsonconfig.KindObject {
		return false
	}

	for _, field := range n.Members {
		switch field.Key {
		case "name", "email", "url":
			if field.Value.Kind == jsonconfig.KindString {
				continue
			}
		}

		return false
	}

	return true
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > 64 || !nameEnd(name[0]) || !nameEnd(name[len(name)-1]) ||
		strings.Contains(name, "--") || strings.Contains(name, "..") {
		return false
	}

	for i := range len(name) {
		if c := name[i]; !nameEnd(c) && c != '-' && c != '.' {
			return false
		}
	}

	return true
}

func nameEnd(c byte) bool { return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' }

// OpenAISettings returns the inline Codex settings, when present. An object,
// including an empty one, takes precedence over the compatibility manifest.
func OpenAISettings(root *jsonconfig.Node) *jsonconfig.Node {
	n := root.Get("extensions").Get("com.openai")
	if n != nil && n.Kind == jsonconfig.KindObject {
		return n
	}

	return nil
}

// SkillPath identifies a skill declaration relative to the fixed skills directory.
func SkillPath(name string) bool {
	dir, file, ok := strings.Cut(name, "/")
	return ok && dir != "" && file == "SKILL.md"
}

func (v Version) MCPServers(root *jsonconfig.Node) *jsonconfig.Node {
	return v.config(root, MCPFile, MCPField)
}

func (v Version) Hooks(root *jsonconfig.Node) *jsonconfig.Node {
	return v.config(root, HooksFile, HooksField)
}

func (v Version) config(root *jsonconfig.Node, file, field string) *jsonconfig.Node {
	if root == nil || root.Kind != jsonconfig.KindObject || len(root.Members) != 2 {
		return nil
	}

	schema, _ := root.Get(schemaField).Text()

	items := root.Get(field)
	if schema != v.schema(file) || items == nil || items.Kind != jsonconfig.KindObject {
		return nil
	}

	return items
}

// ValidMCPServer checks the portable transport and its static declaration.
// Connection and platform-dependent resolution are outside this check.
func ValidMCPServer(n *jsonconfig.Node) bool {
	transport, _ := n.Get("type").Text()
	switch transport {
	case "stdio":
		return validCommand(n.Get("command")) && optionalStrings(n.Get("args"), jsonconfig.KindArray) &&
			optionalStrings(n.Get("env"), jsonconfig.KindObject) && validWorkingDir(n.Get("cwd")) &&
			validFields(n, "type", "command", "args", "env", "cwd")
	case "streamable-http", "sse":
		return validRemoteURL(n.Get("url")) && optionalStrings(n.Get("headers"), jsonconfig.KindObject) && validFields(n, "type", "url", "headers")
	default:
		return false
	}
}

func validRemoteURL(n *jsonconfig.Node) bool {
	address, ok := n.Text()
	if !ok || strings.ContainsRune(address, '#') {
		return false
	}

	u, err := url.Parse(address)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return false
	}

	if u.Scheme == "https" {
		return true
	}

	ip, err := netip.ParseAddr(u.Hostname())

	return u.Scheme == "http" && (u.Hostname() == "localhost" || err == nil && ip.IsLoopback())
}

func ValidHookEvent(event jsonconfig.Member) bool {
	switch event.Key {
	case "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop":
		return event.Value.Kind == jsonconfig.KindArray && len(event.Value.Elements) != 0
	default:
		return false
	}
}

func ValidHook(n *jsonconfig.Node) bool {
	return validCommand(n.Get("command")) && optionalStrings(n.Get("args"), jsonconfig.KindArray) && validFields(n, "command", "args")
}

func validCommand(n *jsonconfig.Node) bool {
	command, ok := n.Text()
	if !ok || command == "" || strings.ContainsFunc(command, unicode.IsControl) {
		return false
	}

	if strings.HasPrefix(command, "./") {
		rel, reason := artifactpath.Reference(command, true)
		return reason == "" && rel != "." && !strings.HasSuffix(command, "/")
	}

	return command != "." && command != ".." && !strings.ContainsAny(command, `/\:${}`) &&
		!strings.ContainsFunc(command, unicode.IsSpace)
}

func validWorkingDir(n *jsonconfig.Node) bool {
	if n == nil {
		return true
	}

	dir, ok := n.Text()
	if !ok {
		return false
	}

	for _, root := range []string{"${PLUGIN_ROOT}", "${PLUGIN_DATA}"} {
		if dir == root {
			return true
		}

		if rest, found := strings.CutPrefix(dir, root+"/"); found {
			dir = "./" + rest
			break
		}
	}

	if !strings.HasPrefix(dir, "./") {
		return false
	}

	_, reason := artifactpath.Reference(dir, true)

	return reason == ""
}

func validFields(n *jsonconfig.Node, fields ...string) bool {
	if n == nil || n.Kind != jsonconfig.KindObject {
		return false
	}

	for _, m := range n.Members {
		if m.Key == "extensions" {
			if m.Value.Kind != jsonconfig.KindObject {
				return false
			}

			continue
		}

		if !slices.Contains(fields, m.Key) {
			return false
		}
	}

	return true
}

func optionalStrings(n *jsonconfig.Node, kind string) bool {
	if n == nil {
		return true
	}

	if n.Kind != kind {
		return false
	}

	for _, item := range n.Elements {
		if _, ok := item.Text(); !ok {
			return false
		}
	}

	for _, m := range n.Members {
		if _, ok := m.Value.Text(); !ok {
			return false
		}
	}

	return true
}
