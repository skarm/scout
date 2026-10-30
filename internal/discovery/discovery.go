// Package discovery inventories local agent components without executing them.
package discovery

import (
	"cmp"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
)

// Options selects operator-owned roots. Configuration cannot expand these roots.
type Options struct {
	Home, CodexHome, ClaudeHome string
	Agent                       string
	Projects                    []string
	System                      bool
	MaxEntries, MaxDepth        int
	MaxBytes                    int64
}

// DefaultOptions selects both agents and bounded discovery of known locations.
// Projects and environment overrides are supplied explicitly by the caller.
func DefaultOptions(home string) Options {
	return Options{Home: home, Agent: "all", System: true, MaxEntries: 10000, MaxDepth: 12, MaxBytes: 8 << 20}
}

// Snapshot is an inventory, not evidence that a component is active or safe.
// Complete concerns only the documented on-disk discovery surface.
type Snapshot struct {
	Schema      string       `json:"schema"`
	Complete    bool         `json:"complete"`
	Components  []Component  `json:"components"`
	Sources     []Source     `json:"sources"`
	Targets     []string     `json:"scan_targets"`
	Enablement  []Enablement `json:"enablement"`
	Issues      []Issue      `json:"issues"`
	Limitations []string     `json:"limitations"`

	protectedInputs []string
}

// ProtectedInputs returns local boundaries for report publication, including
// selected configuration locations that discovery could not read. These guards
// belong to this in-memory discovery run and are not imported from inventory JSON.
func (s Snapshot) ProtectedInputs() []string {
	return append(slices.Clone(s.protectedInputs), s.Targets...)
}

// Component records one declaration. Names and paths are untrusted metadata.
// State is the local declaration's enabled/disabled/unknown value, never runtime state.
type Component struct {
	Agent   string `json:"agent"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Scope   string `json:"scope"`
	Path    string `json:"path"`
	Source  string `json:"source"`
	Key     string `json:"key,omitempty"`
	State   string `json:"state"`
	Plugin  string `json:"plugin,omitempty"`
	Project string `json:"project,omitempty"`
}

// Source identifies exact bytes read for a configuration or manifest.
type Source struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Issue records a missing part of discovery without copying configuration values.
type Issue struct {
	Code string `json:"code"`
	Path string `json:"path"`
}

// Enablement retains a setting independently of runtime precedence and loading.
// Selector is a plugin identifier, skill path or MCP name, not executable input.
type Enablement struct {
	Agent    string `json:"agent"`
	Kind     string `json:"kind"`
	Selector string `json:"selector"`
	State    string `json:"state"`
	Source   string `json:"source"`
	Key      string `json:"key"`
	Scope    string `json:"scope"`
	Project  string `json:"project,omitempty"`
}

type builder struct {
	ctx                        context.Context
	options                    Options
	out                        Snapshot
	entries                    int
	bytes                      int64
	stopped                    bool
	seen                       map[Component]bool
	sources                    map[string]string
	roots                      map[string]bool
	protected                  map[string]bool
	projectRoots, projectNames []string
}

// Discover reads only selected homes, selected project ancestors and fixed system
// locations. It never runs commands, contacts MCP servers or loads Scout settings.
// Operational failures retain a partial Snapshot; invalid options return no inventory.
func Discover(ctx context.Context, options Options) (Snapshot, error) {
	if ctx == nil || options.Home == "" || !slices.Contains([]string{"all", "codex", "claude-code"}, options.Agent) ||
		options.MaxEntries < 1 || options.MaxEntries > 100000 || options.MaxDepth < 1 || options.MaxDepth > 32 ||
		options.MaxBytes < 1 || options.MaxBytes > 64<<20 || len(options.Projects) > 32 {
		return Snapshot{}, errors.New("invalid discovery options")
	}

	b := &builder{ctx: ctx, options: options, seen: map[Component]bool{}, sources: map[string]string{}, roots: map[string]bool{}, out: Snapshot{
		Schema: "scout.environment/v1", Complete: true,
		Components: []Component{}, Sources: []Source{}, Targets: []string{}, Issues: []Issue{}, Enablement: []Enablement{},
		Limitations: []string{
			"On-disk declarations only; activation, precedence, approvals and runtime tool availability are not resolved.",
			"Only selected projects and known local locations are searched; saved project paths and external references are not followed.",
			"Plugin caches may include disabled or obsolete versions. Cloud, MDM, CLI overrides, linked skills and MCP bundle extraction are outside discovery coverage.",
			"Scan targets are configuration files and skill/plugin roots, including disabled declarations; discovery is not a transactional filesystem snapshot.",
		},
	}}
	b.protectLocations()
	b.prepareProjects()
	b.user()
	b.projects()

	if options.System {
		b.system()
	}

	return b.finish()
}

func (b *builder) selects(agent string) bool {
	return b.options.Agent == "all" || b.options.Agent == agent
}

func (b *builder) issue(code, name string) {
	b.out.Complete = false

	issue := Issue{Code: code, Path: name}
	if !slices.Contains(b.out.Issues, issue) {
		b.out.Issues = append(b.out.Issues, issue)
	}
}

func (b *builder) step(name string) bool {
	if b.stopped || b.ctx.Err() != nil {
		return false
	}

	b.entries++
	if b.entries > b.options.MaxEntries {
		b.stopped = true
		b.issue("entry_limit", name)

		return false
	}

	return true
}

func (b *builder) add(c Component) {
	if !b.seen[c] {
		b.seen[c] = true
		b.out.Components = append(b.out.Components, c)
	}
}

func (b *builder) target(name string) {
	if !slices.Contains(b.out.Targets, name) {
		b.out.Targets = append(b.out.Targets, name)
	}
}

func (b *builder) finish() (Snapshot, error) {
	slices.SortFunc(b.out.Components, func(a, c Component) int {
		return cmp.Or(cmp.Compare(a.Agent, c.Agent), cmp.Compare(a.Scope, c.Scope), cmp.Compare(a.Source, c.Source), cmp.Compare(a.Key, c.Key), cmp.Compare(a.Path, c.Path), cmp.Compare(a.Kind, c.Kind))
	})
	slices.SortFunc(b.out.Sources, func(a, c Source) int { return cmp.Compare(a.Path, c.Path) })
	slices.SortFunc(b.out.Issues, func(a, c Issue) int { return cmp.Or(cmp.Compare(a.Path, c.Path), cmp.Compare(a.Code, c.Code)) })
	slices.SortFunc(b.out.Enablement, func(a, c Enablement) int {
		return cmp.Or(cmp.Compare(a.Agent, c.Agent), cmp.Compare(a.Source, c.Source), cmp.Compare(a.Key, c.Key))
	})
	slices.Sort(b.out.Targets)
	slices.Sort(b.out.protectedInputs)

	if err := b.compactTargets(); err != nil {
		b.issue("cancelled", "")
		return b.out, err
	}

	return b.out, nil
}

func (b *builder) compactTargets() error {
	targets := make([]string, 0, len(b.out.Targets))
	for _, name := range b.out.Targets {
		if err := b.ctx.Err(); err != nil {
			return err
		}

		covered := false

		for _, parent := range targets {
			if err := b.ctx.Err(); err != nil {
				return err
			}

			if within(parent, name) {
				covered = true
				break
			}
		}

		if !covered {
			targets = append(targets, name)
		}
	}

	if err := b.ctx.Err(); err != nil {
		return err
	}

	b.out.Targets = targets

	return nil
}

func within(root, name string) bool {
	rel, err := filepath.Rel(root, name)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
