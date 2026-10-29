// Package harness interprets captured packages without filesystem, process,
// environment or network access. Adapters describe declarations, not execution.
package harness

import (
	"context"
	"encoding/json"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/hookpolicy"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const version = "2"

type entry struct {
	meta report.File
	doc  *document.File
	name string
}
type namespace struct {
	id      string
	entries map[string]*entry
	names   []string
}
type builder struct {
	ctx            context.Context
	r              report.ComponentGraph
	spaces         []*namespace
	nodes          map[string]int
	edges          map[string]bool
	issues         map[string]bool
	references     map[string]bool
	containerRoots map[string]bool
	operations     int
	stopped        bool
	hooks          hookpolicy.Policy
}
type candidate struct {
	ns                   *namespace
	root, host, manifest string
}
type plugin struct {
	manifest                   *entry
	b                          *builder
	ns                         *namespace
	root, host, id, activation string
	index                      int
	processedConfigs           map[string]bool
	rootNode                   string
}

type candidateSet struct {
	b      *builder
	seen   map[string]bool
	values []candidate
}

func Limits() report.HarnessLimits {
	return report.HarnessLimits{Plugins: 128, Components: 4096, Edges: 8192, References: 4096, Operations: 500000}
}

// Discover reuses whole-file JSON trees from bounded preparation. Fenced JSON is
// never mistaken for an installed manifest. Only actual archive members form
// virtual directory namespaces; decoded strings and metadata cannot impersonate files.
func Discover(ctx context.Context, inventory []report.File, docs []document.File, extraction report.ExtractionReport, opts report.HarnessOptions) report.ComponentGraph {
	host := opts.Host
	if host == "" {
		host = report.HostAuto
	}

	b := builder{
		ctx:            ctx,
		nodes:          map[string]int{},
		edges:          map[string]bool{},
		references:     map[string]bool{},
		containerRoots: map[string]bool{},
		issues:         map[string]bool{},
		r: report.ComponentGraph{
			RequestedHost: host,
			FormatScope:   "documented-subset-not-runtime-loader-validation",
			Limits:        Limits(),
			Plugins:       []report.PluginInterpretation{},
			Components:    []report.Component{},
			Edges:         []report.ComponentEdge{},
			References:    []report.ComponentReference{},
			Issues:        []report.HarnessIssue{},
		},
	}
	if opts.Validate() != nil {
		b.issue("invalid_harness_request", "", "", "invalid")
		return b.r
	}

	b.spaces = namespaces(inventory, docs, extraction)

	b.hooks = hookpolicy.Bind(ctx, docs, extraction)
	for _, space := range b.spaces {
		if space.id != "snapshot" {
			b.containerRoots[space.id] = true
		}
	}

	candidates := b.candidates(host)
	for _, c := range candidates {
		if !b.step() {
			break
		}

		p := b.plugin(c)
		p.discover()
	}

	b.standaloneSkills()
	b.finish()

	return b.r
}

func (b *builder) candidates(host string) []candidate {
	set := candidateSet{b: b, seen: map[string]bool{}}

	for _, ns := range b.spaces {
		found := false

		for _, name := range ns.names {
			if !b.step() {
				break
			}

			base := path.Base(name)
			if base == "plugin.json" {
				root, loader := manifestLayout(name)
				set.add(ns, root, loader, name)

				found = true
			}

			b.marketplace(ns, name)
		}
		// Manifestless Claude plugins require explicit caller intent. Auto cannot
		// distinguish a plugin directory from an arbitrary repository with hooks.
		if !found && !b.containerCollection(ns) && slices.Contains([]string{report.HostClaudeCode, report.HostCodex}, host) {
			set.add(ns, ".", host, "")
		}
	}

	sort.Slice(set.values, func(i, j int) bool { return candidateLess(set.values[i], set.values[j]) })

	return set.values
}

func (b *builder) marketplace(ns *namespace, name string) {
	base := path.Base(name)
	if base == "marketplace.json" && (strings.Contains(name, ".claude-plugin/") || strings.Contains(name, ".agents/plugins/")) {
		e := ns.entries[name]
		b.node("", "marketplace", e, "unknown", "unknown", whole(e), "catalog")
		b.issue("marketplace_install_closure_unverified", "", e.meta.Path, report.OutcomePartial)
	}
}

func (b *builder) standaloneSkills() {
	// Inventory skills independently of plugins. These are instruction candidates,
	// not assertions of schema validity or automatic model invocation.
	for _, ns := range b.spaces {
		for _, name := range ns.names {
			if !b.step() {
				break
			}

			if path.Base(name) == "SKILL.md" {
				e := ns.entries[name]
				b.node("", "skill", e, report.HostAgentSkills, "unknown", whole(e), "standalone")
			}
		}
	}
}

func (b *builder) step() bool {
	if b.stopped {
		return false
	}

	if b.ctx == nil || b.ctx.Err() != nil {
		b.stopped = true
		b.issue("harness_cancelled", "", "", report.OutcomePartial)

		return false
	}

	b.operations++
	if b.operations > b.r.Limits.Operations {
		b.stopped = true
		b.issue("harness_operation_limit", "", "", report.OutcomePartial)

		return false
	}

	return true
}

func (b *builder) issue(code, pid, file, status string) {
	if b.issues["issue_limit"] {
		return
	}

	key := identity(code, pid, file, status)
	if b.issues[key] {
		return
	}

	b.issues[key] = true
	if len(b.r.Issues) >= b.r.Limits.References {
		if !b.issues["issue_limit"] {
			b.issues["issue_limit"] = true
			b.r.Issues = append(b.r.Issues, report.HarnessIssue{Code: "harness_issue_limit", Status: report.OutcomePartial})
		}

		return
	}

	b.r.Issues = append(b.r.Issues, report.HarnessIssue{Code: code, PluginID: pid, Path: file, Status: status})
}

func (b *builder) node(pid, kind string, e *entry, host, activation string, s *report.SourceRef, salt string) string {
	file := ""
	name := ""

	if e != nil {
		file = e.meta.Path
		name = e.name
	}

	sourceID := ""

	if s != nil {
		raw, _ := json.Marshal(s)
		sourceID = string(raw)
	}

	id := identity("component-v1", pid, kind, file, host, activation, sourceID, salt)
	if _, ok := b.nodes[id]; ok {
		return id
	}

	if len(b.r.Components) >= b.r.Limits.Components {
		b.issue("component_limit", pid, file, report.OutcomePartial)
		return ""
	}

	b.nodes[id] = len(b.r.Components)
	b.r.Components = append(b.r.Components, report.Component{
		ID:          id,
		PluginID:    pid,
		Kind:        kind,
		Path:        file,
		PackagePath: name,
		Host:        host,
		Activation:  activation,
		Source:      s,
	})

	return id
}

func (b *builder) edge(from, to, relation, basis, activation string, s *report.SourceRef) {
	if from == "" || to == "" {
		return
	}

	raw, _ := json.Marshal(s)

	id := identity("edge-v1", from, to, relation, basis, activation, string(raw))
	if b.edges[id] {
		return
	}

	if len(b.r.Edges) >= b.r.Limits.Edges {
		b.issue("edge_limit", "", "", report.OutcomePartial)
		return
	}

	b.edges[id] = true
	b.r.Edges = append(b.r.Edges, report.ComponentEdge{
		ID:         id,
		From:       from,
		To:         to,
		Relation:   relation,
		Basis:      basis,
		Activation: activation,
		Source:     s,
	})
}

func (b *builder) plugin(c candidate) *plugin {
	id := identity("plugin-v1", c.ns.id, c.root, c.host)
	activation := "unknown"

	if b.r.RequestedHost != report.HostAuto && c.host != "unknown" {
		if b.r.RequestedHost == c.host {
			activation = "conditional"
		} else {
			activation = "inactive_for_profile"
		}
	}

	manifests := make([]string, 0)

	var e *entry
	if c.manifest != "" {
		e = c.ns.entries[c.manifest]
		manifests = append(manifests, e.meta.Path)
	}

	p := &plugin{
		manifest:         e,
		b:                b,
		ns:               c.ns,
		root:             c.root,
		host:             c.host,
		id:               id,
		activation:       activation,
		index:            len(b.r.Plugins),
		processedConfigs: map[string]bool{},
	}
	b.r.Plugins = append(b.r.Plugins, report.PluginInterpretation{
		ID:             id,
		Host:           c.host,
		Namespace:      c.ns.id,
		Root:           c.root,
		Manifests:      manifests,
		AdapterID:      c.host + "-layout-subset",
		AdapterVersion: version,
		Contract:       "docs-2026-10-26-subset",
		FormatStatus:   report.OutcomePartial,
		Activation:     activation,
		Assumptions:    []string{"No host binary/version, trust grants or installation are evaluated; only closed captured Claude hook-disable precedence is modeled.", "Paths are resolved only against this package namespace; external configuration is not read."},
	})
	p.rootNode = b.node(id, "plugin", e, c.host, activation, whole(e), c.ns.id+"/"+c.root)

	return p
}

func (b *builder) finish() {
	sort.Slice(b.r.Components, func(i, j int) bool { return b.r.Components[i].ID < b.r.Components[j].ID })
	sort.Slice(b.r.Edges, func(i, j int) bool { return b.r.Edges[i].ID < b.r.Edges[j].ID })
	sort.Slice(b.r.References, func(i, j int) bool { return b.r.References[i].ID < b.r.References[j].ID })
	sort.Slice(b.r.Issues, func(i, j int) bool {
		a, c := b.r.Issues[i], b.r.Issues[j]
		if a.PluginID != c.PluginID {
			return a.PluginID < c.PluginID
		}

		if a.Path != c.Path {
			return a.Path < c.Path
		}

		return a.Code < c.Code
	})
}

// A scan of a bundle is not an instruction to install an invented outer plugin.
// Manifestless default-layout candidates remain supported inside each namespace.
func (b *builder) containerCollection(ns *namespace) bool {
	for _, name := range []string{"SKILL.md", "hooks/hooks.json", ".mcp.json", ".lsp.json"} {
		if ns.entries[name] != nil {
			return false
		}
	}

	for _, name := range []string{"skills", "commands", "agents"} {
		if len(ns.descendants(name)) > 0 {
			return false
		}
	}

	for _, e := range ns.entries {
		if !b.step() {
			return true
		}

		if b.containerRoots[e.meta.Path] {
			return true
		}
	}

	return false
}

func (s *candidateSet) add(ns *namespace, root, host, manifest string) {
	key := ns.id + "\x00" + root + "\x00" + host
	if s.seen[key] {
		return
	}

	s.seen[key] = true
	if len(s.values) >= s.b.r.Limits.Plugins {
		s.b.issue("plugin_limit", "", "", report.OutcomePartial)
		return
	}

	s.values = append(s.values, candidate{ns: ns, root: root, host: host, manifest: manifest})
}

func manifestLayout(name string) (string, string) {
	dir := path.Dir(name)
	switch path.Base(dir) {
	case ".claude-plugin":
		return path.Dir(dir), report.HostClaudeCode
	case ".codex-plugin":
		return path.Dir(dir), report.HostCodex
	default:
		return dir, "unknown"
	}
}

func candidateLess(a, c candidate) bool {
	if a.ns.id != c.ns.id {
		return a.ns.id < c.ns.id
	}

	if a.root != c.root {
		return a.root < c.root
	}

	return a.host < c.host
}

func (p *plugin) issue(code, file, status string) {
	p.b.issue(code, p.id, file, status)

	if status == "invalid" {
		p.b.r.Plugins[p.index].FormatStatus = "invalid"
	}
}
func (p *plugin) entry(name string) *entry { return p.ns.entries[path.Join(p.root, name)] }
func (p *plugin) object(e *entry) *jsonconfig.Node {
	if e == nil {
		return nil
	}

	if e.doc == nil {
		p.issue("plugin_input_unavailable", e.meta.Path, report.OutcomePartial)
		return nil
	}

	for _, u := range e.doc.Units() {
		if u.Origin == "file" && u.Language == language.JSON {
			return p.jsonObject(e, u)
		}
	}

	p.issue("plugin_json_unavailable", e.meta.Path, report.OutcomePartial)

	return nil
}

func (p *plugin) jsonObject(e *entry, u document.Unit) *jsonconfig.Node {
	if t, ok := u.Tree.(parse.JSONTree); ok && t.Root != nil {
		if t.Root.Kind != jsonconfig.KindObject {
			p.issue("plugin_object_expected", e.meta.Path, "invalid")
			return nil
		}

		return t.Root
	}

	status := report.OutcomePartial
	code := "plugin_json_unavailable"

	if u.Status == report.OutcomeFailed || u.Status == report.UnitParseError {
		status = "invalid"
		code = "plugin_json_invalid"
	}

	p.issue(code, e.meta.Path, status)

	return nil
}

func namespaces(inventory []report.File, docs []document.File, extraction report.ExtractionReport) []*namespace {
	byPath := make(map[string]*document.File, len(docs))
	for i := range docs {
		byPath[docs[i].Artifact().Metadata().Path] = &docs[i]
	}

	spaces := map[string]*namespace{}

	for _, m := range inventory {
		putNamespace(spaces, byPath, "snapshot", m.Path, m)
	}

	for _, o := range extraction.Objects {
		if archiveNamespaceMember(o.Role, o.ExtractorID) {
			putNamespace(spaces, byPath, o.ParentPath, o.MemberName, o.File)
		}
	}

	for _, o := range extraction.Skipped {
		if archiveNamespaceMember(o.Role, o.ExtractorID) {
			putNamespace(spaces, byPath, o.ParentPath, o.MemberName, report.File{
				Path:   o.ParentPath + "#unread-member/" + o.MemberName,
				Size:   o.DeclaredSize,
				Status: "skipped",
				Reason: o.Reason,
			})
		}
	}

	ids := make([]string, 0, len(spaces))
	for id := range spaces {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	out := make([]*namespace, 0, len(ids))
	for _, id := range ids {
		n := spaces[id]
		sort.Strings(n.names)
		out = append(out, n)
	}

	return out
}

func putNamespace(spaces map[string]*namespace, byPath map[string]*document.File, id, name string, m report.File) {
	n := spaces[id]
	if n == nil {
		n = &namespace{id: id, entries: map[string]*entry{}}
		spaces[id] = n
	}
	// Input paths have already been validated by capture/extraction. Do not
	// normalize ambiguous duplicate names into a trusted entry.
	if _, ok := n.entries[name]; ok {
		return
	}

	n.entries[name] = &entry{meta: m, doc: byPath[m.Path], name: name}
	n.names = append(n.names, name)
}
func identity(v ...string) string { raw, _ := json.Marshal(v); return artifact.Hash(raw) }
func whole(e *entry) *report.SourceRef {
	if e == nil || e.doc == nil {
		return nil
	}

	return &report.SourceRef{
		Path:       e.meta.Path,
		SHA256:     e.meta.SHA256,
		ByteEnd:    len(e.doc.Artifact().Content()),
		SpanSHA256: e.meta.SHA256,
	}
}

func ref(e *entry, s source.Span) *report.SourceRef {
	if e == nil || e.doc == nil {
		return nil
	}

	f := e.doc.Artifact()

	text := f.Content()
	if s.Start < 0 || s.End < s.Start || s.End > len(text) {
		return nil
	}

	return &report.SourceRef{
		Path:       e.meta.Path,
		SHA256:     e.meta.SHA256,
		ByteStart:  s.Start,
		ByteEnd:    s.End,
		SpanSHA256: artifact.Hash([]byte(text[s.Start:s.End])),
	}
}

// descendants slices the sorted namespace with two prefix searches. Only the
// selected subtree is visited and charged against the interpretation budget.
func (n *namespace) descendants(name string) []string {
	prefix := name + "/"
	start := sort.SearchStrings(n.names, prefix)
	end := start + sort.Search(len(n.names)-start, func(i int) bool { return !strings.HasPrefix(n.names[start+i], prefix) })

	return n.names[start:end]
}

func (n *namespace) selectNames(name string) []string {
	if name == "." {
		// Captured paths are portable, but preserve the root selector's exclusion
		// of parent-relative names for caller-provided inventories as well.
		out := make([]string, 0, len(n.names))
		for _, key := range n.names {
			if !strings.HasPrefix(key, "../") {
				out = append(out, key)
			}
		}

		return out
	}

	children := n.descendants(name)
	if n.entries[name] == nil {
		return children
	}
	// An exact file sorts before its descendants, even if other sibling names
	// intervene. Those siblings must not enter the selected range.
	return append([]string{name}, children...)
}

func archiveNamespaceMember(role, extractor string) bool {
	return role == "archive_member" && slices.Contains([]string{"zip32", "tar"}, extractor)
}
