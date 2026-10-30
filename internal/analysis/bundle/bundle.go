// Package bundle inspects bounded relationships across captured local source files.
package bundle

import (
	"context"
	"errors"
	"path"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/rendertext"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

type (
	analyzer = check.Analyzer
	match    = check.Match
	result   = check.Result
)

type bundleCheck struct {
	id    string
	facts map[string]result
	err   error
}
type bundleScope struct {
	file, ns, root string
	hosts          map[string]bool
}
type bundleAnalysis struct {
	ctx               context.Context
	docs              map[string]document.File
	addresses         map[string]document.Address
	scopes            []bundleScope
	programs          map[string]*bundleProgram
	results           map[string]map[string]result
	limit, operations int
	err               error
	gap               error
	active            map[*bundleFunction]bool
	endpoints         map[string][]bundleEndpoint
	secrets           map[string][]report.SourceRef
	surface           *Surface
	surfaceSeen       map[SurfaceFact]bool
}
type bundleEndpoint struct {
	value string
	ref   report.SourceRef
}

func Rules() []analyzer {
	out := make([]analyzer, 0, 5)
	for _, id := range []string{ruleNET001, ruleSC004, ruleCrossFile, ruleTC001, ruleTC002} {
		out = append(out, bundleCheck{id: id})
	}

	return out
}

func (a bundleCheck) Rule() report.Rule {
	title, category := "", ""

	switch a.id {
	case ruleNET001:
		title, category = "Network destination is absent from visible skill declarations", "network-scope"
	case ruleSC004:
		title, category = "Installation declares an automatic code entry point", "supply-chain"
	case ruleCrossFile:
		title, category = "Sensitive or downloaded data reaches a sink across local files", "cross-file-flow"
	case ruleTC001:
		title, category = "Captured tools share a colliding identifier", "tool-poisoning"
	case ruleTC002:
		title, category = "Skill combines sensitive-data access and outbound network capabilities", "capability-combination"
	}

	severity := report.Medium
	if a.id == ruleCrossFile {
		severity = report.High
	}

	return report.Rule{
		ID:          a.id,
		Version:     "2",
		Title:       title,
		Description: title,
		Severity:    severity,
		Category:    category,
		Method:      "bounded-captured-bundle-analysis",
		Limitation:  "Offline, same captured namespace; nearest SKILL scope controls declarations and capability aggregation, not explicit local call flows. Selected literal endpoints, installation declarations and Go/JS/TS/Python local imports/functions only; syntactic API candidates, no type checking, dependency resolution or proof of execution. Unresolved dynamic network destinations and exhausted budgets remain incomplete. Declared hosts confer no trust and suppress no other rules. Capability combinations and tool collisions require review; they are not proven flows.",
	}
}

func (a bundleCheck) AppliesTo(d document.File) bool {
	_, ok := a.facts[d.Artifact().Metadata().Path]
	return ok || a.err != nil
}

func (a bundleCheck) Find(ctx context.Context, d document.File, budget int) (result, error) {
	out := a.facts[d.Artifact().Metadata().Path]
	if len(out.Matches) > budget {
		out.Matches = out.Matches[:max(0, budget)]
		out.Truncated = true
	}

	return out, errors.Join(a.err, ctx.Err())
}

func Consumers(checks []analyzer) int {
	for _, a := range checks {
		if _, ok := a.(bundleCheck); ok {
			return 1
		}
	}

	return 0
}

// Bind owns one quota-charged prepass. Its observations are immutable
// before parallel checks start, and never persist in a Scanner across runs.
func Bind(ctx context.Context, checks []analyzer, docs []document.File, extraction report.ExtractionReport, limit int) []analyzer {
	return bind(ctx, checks, docs, extraction, limit, nil)
}

func bind(ctx context.Context, checks []analyzer, docs []document.File, extraction report.ExtractionReport, limit int, surface *Surface) []analyzer {
	if Consumers(checks) == 0 && surface == nil {
		return checks
	}

	b := &bundleAnalysis{
		ctx:       ctx,
		docs:      map[string]document.File{},
		addresses: document.CapturedAddresses(docs, extraction),
		programs:  map[string]*bundleProgram{},
		results:   map[string]map[string]result{},
		limit:     limit,
		active:    map[*bundleFunction]bool{},
		endpoints: map[string][]bundleEndpoint{},
		secrets:   map[string][]report.SourceRef{},
		surface:   surface,
	}

	for _, a := range checks {
		if a, ok := a.(bundleCheck); ok {
			b.results[a.id] = map[string]result{}
		}
	}

	for _, d := range docs {
		b.docs[d.Artifact().Metadata().Path] = d
	}

	b.discover(docs)

	if surface != nil {
		b.surfaceSkills(docs)
	}

	for _, d := range docs {
		if !b.step() {
			break
		}

		b.installHooks(d)
		b.toolCollisions(d)
		b.buildPrograms(d)
		b.shellEndpoints(d)
		b.sqlEndpoints(d)
	}

	for _, d := range docs {
		if !b.step() {
			break
		}

		name := d.Artifact().Metadata().Path
		if p := b.programs[name]; p != nil {
			b.inspectProgram(p)
		}
	}

	b.finishScopes()

	if surface != nil {
		surface.Complete = b.err == nil && b.gap == nil && !surface.Limited && ctx.Err() == nil
	}

	out := append([]analyzer(nil), checks...)
	for i, a := range out {
		if a, ok := a.(bundleCheck); ok {
			a.facts = b.results[a.id]
			a.err = errors.Join(b.err, b.gap)
			out[i] = a
		}
	}

	return out
}

func (b *bundleAnalysis) step() bool {
	if b.err != nil {
		return false
	}

	b.operations++
	if b.ctx.Err() != nil || b.operations > 100000 || !analysisbudget.Consume(b.ctx, 1) {
		b.err = errors.New("captured bundle analysis budget exceeded")
		return false
	}

	return true
}

func (b *bundleAnalysis) emit(id string, ref report.SourceRef, related ...report.SourceRef) {
	facts := b.results[id]
	if facts == nil {
		return
	}

	out := facts[ref.Path]
	for _, m := range out.Matches {
		if m.Start == ref.ByteStart && m.End == ref.ByteEnd {
			return
		}
	}

	if len(out.Matches) >= b.limit {
		out.Truncated = true
	} else {
		m := match{Start: ref.ByteStart, End: ref.ByteEnd}
		for _, r := range related {
			if r.Path != "" && r != ref {
				m.Related = append(m.Related, r)
				if len(m.Related) == 8 {
					break
				}
			}
		}

		out.Matches = append(out.Matches, m)
	}

	facts[ref.Path] = out
}

func (b *bundleAnalysis) reference(file string, start, end int) report.SourceRef {
	d, ok := b.docs[file]
	if !ok || start < 0 || end <= start || end > len(d.Artifact().Content()) {
		b.err = errors.New("bundle source mapping failed")
		return report.SourceRef{}
	}

	meta := d.Artifact().Metadata()

	return report.SourceRef{
		Path:       file,
		SHA256:     meta.SHA256,
		ByteStart:  start,
		ByteEnd:    end,
		SpanSHA256: artifact.Hash([]byte(d.Artifact().Content()[start:end])),
	}
}

func (b *bundleAnalysis) discover(docs []document.File) {
	for _, d := range docs {
		if !b.step() {
			return
		}

		name := d.Artifact().Metadata().Path

		addr, ok := b.addresses[name]
		if !ok || !strings.EqualFold(path.Base(addr.Name), "SKILL.md") {
			continue
		}

		visible, err := rendertext.Visible(b.ctx, d.Artifact().Content())
		if err != nil {
			b.err = err
			return
		}

		hosts := map[string]bool{}

		for _, raw := range bundleURLs.FindAllString(visible, -1) {
			if host := canonicalHost(raw); host != "" {
				hosts[host] = true
			}
		}

		b.scopes = append(b.scopes, bundleScope{file: name, ns: addr.Namespace, root: path.Dir(addr.Name), hosts: hosts})
	}

	sort.SliceStable(b.scopes, func(i, j int) bool { return scopeDepth(b.scopes[i].root) > scopeDepth(b.scopes[j].root) })
}

func scopeDepth(root string) int {
	if root == "." {
		return 0
	}

	return strings.Count(root, "/") + 1
}

func (b *bundleAnalysis) scope(file string) *bundleScope {
	addr, ok := b.addresses[file]
	if !ok {
		return nil
	}

	for i := range b.scopes {
		s := &b.scopes[i]
		if s.ns == addr.Namespace && (s.root == "." || addr.Name == s.root || strings.HasPrefix(addr.Name, s.root+"/")) {
			return s
		}
	}

	return nil
}

func (b *bundleAnalysis) sameScope(a, c string) bool {
	x, y := b.scope(a), b.scope(c)
	if x != nil || y != nil {
		return x != nil && y != nil && x.file == y.file
	}

	xa, xok := b.addresses[a]
	ya, yok := b.addresses[c]

	return xok && yok && xa.Namespace == ya.Namespace
}

func (b *bundleAnalysis) endpoint(file, value string, ref report.SourceRef) {
	b.surfaceFact("network", "", file, ref)

	s := b.scope(file)
	if s == nil {
		return
	}

	if canonicalHost(value) == "" {
		b.gap = errors.New("dynamic network destination is unresolved")
		return
	}

	b.endpoints[s.file] = append(b.endpoints[s.file], bundleEndpoint{value: value, ref: ref})
	if !s.hosts[canonicalHost(value)] {
		b.emit(ruleNET001, ref, b.reference(s.file, 0, len(b.docs[s.file].Artifact().Content())))
	}
}

func (b *bundleAnalysis) secret(file string, ref report.SourceRef) {
	b.surfaceFact("sensitive_read", "", file, ref)

	if s := b.scope(file); s != nil {
		b.secrets[s.file] = append(b.secrets[s.file], ref)
	}
}

func (b *bundleAnalysis) finishScopes() {
	for _, s := range b.scopes {
		if len(b.secrets[s.file]) > 0 && len(b.endpoints[s.file]) > 0 {
			b.emit(ruleTC002, b.endpoints[s.file][0].ref, b.secrets[s.file][0])
		}
	}
}
