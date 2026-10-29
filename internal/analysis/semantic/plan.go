// Package semantic builds bounded evidence scopes before any model invocation.
// Discovery receives no static findings. Assessment is a separate task kind;
// model responses cannot change the input plan, evidence, or deterministic results.
package semantic

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

const excerptBytes = 768

type work struct {
	request  review.Request
	raw      []byte
	metadata report.SemanticTask
}
type planner struct {
	ctx         context.Context
	options     review.Options
	graph       report.ComponentGraph
	snapshot    string
	files       map[string]artifact.File
	components  map[string][]string
	works       []work
	gaps        []report.SemanticGap
	bytes       int
	omittedGaps int
	extraction  report.ExtractionReport
}

type exactEvidence struct {
	excerpts  []review.Excerpt
	citations []review.Citation
	seen      map[string]bool
	bytes     int
	valid     bool
}

func (p *planner) request(mode string) review.Request {
	d, _ := knowledge.Describe(mode)

	return review.Request{
		PromptSHA256:   d.SHA256,
		SchemaVersion:  review.ProtocolVersion,
		PromptVersion:  review.PromptVersion,
		Mode:           mode,
		SnapshotSHA256: p.snapshot,
		Harness:        p.graph.RequestedHost,
		Excerpts:       []review.Excerpt{},
		Findings:       []review.Finding{},
		Links:          []review.Link{},
	}
}

func (p *planner) gap(code, path string, start, end int, finding, plugin string) {
	if len(p.gaps) >= 4096 {
		p.omittedGaps++
		return
	}

	p.gaps = append(p.gaps, report.SemanticGap{
		Code:      code,
		Path:      path,
		ByteStart: start,
		ByteEnd:   end,
		FindingID: finding,
		PluginID:  plugin,
	})
}

func (p *planner) excerpt(f artifact.File, start, end int) review.Excerpt {
	m := f.Metadata()
	text := f.Content()[start:end]
	hash := artifact.Hash([]byte(text))
	raw, _ := json.Marshal([]string{"semantic-excerpt-v1", m.Path, m.SHA256, strconv.Itoa(start), strconv.Itoa(end), hash})
	// Component IDs may be large for hostile manifests: never silently truncate a
	// scope. Omitting an overly large request later becomes a request_limit gap.
	return review.Excerpt{
		ContentKind:  contentKind(m.Path, f.Content()),
		ID:           artifact.Hash(raw),
		Path:         m.Path,
		ObjectSHA256: m.SHA256,
		ByteStart:    start,
		ByteEnd:      end,
		SHA256:       hash,
		Text:         text,
		Components:   append([]string{}, p.components[m.Path]...),
	}
}

func (p *planner) excerpts(f artifact.File, start, end int) []review.Excerpt {
	var out []review.Excerpt

	for start < end {
		next := boundary(f.Content(), start, min(end, start+excerptBytes))
		out = append(out, p.excerpt(f, start, next))
		start = next
	}

	return out
}

func (p *planner) links(excerpts []review.Excerpt) []review.Link {
	out := make([]review.Link, 0)
	index := indexEvidence(excerpts)

	for _, edge := range p.graph.Edges {
		if !index.components[edge.From] || !index.components[edge.To] || edge.Source == nil {
			continue
		}

		citations := index.containing(*edge.Source)

		if len(citations) > 0 {
			out = append(out, review.Link{
				ID:         edge.ID,
				From:       edge.From,
				To:         edge.To,
				Relation:   edge.Relation,
				Activation: edge.Activation,
				Evidence:   citations,
			})
		}
	}

	return out
}

func (p *planner) add(req review.Request) string {
	if len(p.works) >= p.options.MaxRequests {
		return "request_budget"
	}

	if len(req.Excerpts) > review.MaxSegments {
		return "context_segment_limit"
	}
	// Identical scopes are distinct when mode/finding differs. Repeated source
	// text from different objects retains its original path-based evidence ID.
	req.Components = []review.Component{}
	selected := map[string]bool{}

	for _, ex := range req.Excerpts {
		for _, id := range ex.Components {
			selected[id] = true
		}
	}

	for _, c := range p.graph.Components {
		if selected[c.ID] {
			req.Components = append(req.Components, review.Component{
				ID:         c.ID,
				Kind:       c.Kind,
				Host:       c.Host,
				Activation: c.Activation,
			})
		}
	}

	seed, _ := json.Marshal(req)
	req.RequestID = artifact.Hash(seed)

	raw, _ := json.Marshal(req)
	if len(raw) > p.options.MaxRequestBytes {
		return "request_byte_limit"
	}

	if p.bytes+len(raw) > p.options.MaxInputBytes {
		return "aggregate_request_budget"
	}

	meta := taskMetadata(req, raw)

	p.bytes += len(raw)
	p.works = append(p.works, work{request: req, raw: raw, metadata: meta})

	return ""
}

func (p *planner) planDiscovery(f artifact.File) {
	o := p.options
	m := f.Metadata()

	text := f.Content()
	if m.Kind != "text" || !utf8.ValidString(text) {
		p.gap("non_text_semantics_unsupported", m.Path, 0, len(text), "", "")
		return
	}

	for start := 0; start < len(text); {
		if p.ctx.Err() != nil {
			p.gap("planning_cancelled", m.Path, start, len(text), "", "")
			break
		}

		if len(p.works) >= o.MaxRequests || p.bytes >= o.MaxInputBytes {
			p.gap("request_budget", m.Path, start, len(text), "", "")
			break
		}

		end := boundary(text, start, min(len(text), start+o.ChunkBytes))
		req := p.request(knowledge.ModeDiscovery)

		req.Excerpts = p.excerpts(f, start, end)
		if code := p.add(req); code != "" {
			p.gap(code, m.Path, start, len(text), "", "")
			break
		}

		if end == len(text) {
			start = end
		} else {
			// Small overlap reduces simple seam misses, without claiming general
			// cross-chunk reasoning. Every byte remains covered by a discovery scope.
			start = end - min(512, o.ChunkBytes/8)
			start = boundaryBefore(text, start)
		}
	}
}

// Quality review is a distinct opt-in mode, never silently conflated with
// the security discovery task. It shares the same request/input budgets.

func (p *planner) planQuality() {
	initial := append([]work(nil), p.works...)
	for _, w := range initial {
		if w.request.Mode != knowledge.ModeDiscovery {
			continue
		}

		req := p.request(knowledge.ModeQuality)
		req.Excerpts = append([]review.Excerpt(nil), w.request.Excerpts...)

		req.ScopeID = w.request.ScopeID
		if code := p.add(req); code != "" {
			for _, ex := range req.Excerpts {
				p.gap(code, ex.Path, ex.ByteStart, ex.ByteEnd, "", "")
			}
		}
	}
	// Plugin intent review has a separate bounded scope. If all contributing
	// component bytes do not fit, report a gap instead of pretending the whole
	// plugin was compared. The per-object discovery tasks above are retained.
}

func (p *planner) planPluginIntents() {
	for _, plugin := range p.graph.Plugins {
		p.planPluginIntent(plugin)
	}
}

func (p *planner) planPluginIntent(plugin report.PluginInterpretation) {
	if p.ctx.Err() != nil {
		p.gap("planning_cancelled", "", 0, 0, "", plugin.ID)
		return
	}

	names := p.pluginPaths(plugin)

	req := p.request(knowledge.ModeIntent)
	req.ScopeID = plugin.ID
	limited := p.pluginContext(&req, names)

	if limited {
		p.gap("intent_context_incomplete", "", 0, 0, "", plugin.ID)
	}

	req.Links = p.links(req.Excerpts)
	if len(req.Excerpts) == 0 {
		p.gap("intent_no_readable_context", "", 0, 0, "", plugin.ID)
		return
	}

	if code := p.add(req); code != "" {
		p.gap(code, "", 0, 0, "", plugin.ID)
	}
	// A standalone skill gets an intent task over its own document. We do not
	// invent ownership of unrelated siblings or cross-archive relationships.
}

func (p *planner) planSkillIntents() {
	owned := map[string]bool{}

	for _, c := range p.graph.Components {
		if c.PluginID != "" {
			owned[c.Path] = true
		}
	}

	for _, c := range p.graph.Components {
		if c.Kind != "skill" || c.PluginID != "" || owned[c.Path] {
			continue
		}

		p.planSkillIntent(c)
	}
}

// Each finding has its own planned assessment, including all main/trace
// evidence. Findings themselves are never passed to discovery or intent.

func (p *planner) planAssessment(finding report.Finding) {
	o := p.options
	if p.ctx.Err() != nil {
		p.gap("planning_cancelled", finding.Location.Path, 0, 0, finding.ID, "")
		return
	}

	req := p.request(knowledge.ModeAssessment)

	refs := make([]report.Location, 1, 1+len(finding.RelatedEvidence)+len(finding.Trace))

	refs[0] = finding.Location
	for _, related := range finding.RelatedEvidence {
		refs = append(refs, report.Location{Path: related.Path, ByteStart: related.ByteStart, ByteEnd: related.ByteEnd})
	}

	for _, trace := range finding.Trace {
		refs = append(refs, trace.Location)
	}

	scope := p.assessmentEvidence(refs)
	evidence, seen, bytes, valid := scope.citations, scope.seen, scope.bytes, scope.valid
	req.Excerpts = append(req.Excerpts, scope.excerpts...)

	if !valid || len(evidence) > review.MaxEvidence || bytes > o.ChunkBytes {
		p.gap("assessment_evidence_unsupported", finding.Location.Path, 0, 0, finding.ID, "")
		return
	}
	// Add a bounded window around the primary span; over-budget extra context is
	// explicitly reported. This review is not claimed to cover arbitrary callers.
	p.assessmentContext(&req, finding, seen, bytes)

	req.Findings = []review.Finding{{
		ID:          finding.ID,
		Origin:      "static",
		RuleID:      finding.RuleID,
		Category:    finding.Category,
		Method:      finding.Method,
		Description: finding.Message,
		Severity:    string(finding.Severity),
		Evidence:    evidence,
	}}
	if g, ok := knowledge.Lookup(finding.RuleID); ok {
		req.Findings[0].Guidance = &g
	}

	req.Findings[0].ContextSignals = append([]string(nil), finding.ContextSignals...)

	req.Links = p.links(req.Excerpts)
	if code := p.add(req); code != "" {
		p.gap(code, finding.Location.Path, 0, 0, finding.ID, "")
	}
}

func (p *planner) assessmentContext(req *review.Request, finding report.Finding, seen map[string]bool, bytes int) {
	o := p.options
	if f, ok := p.files[finding.Location.Path]; ok {
		start := max(0, finding.Location.ByteStart-384)
		start = boundaryBefore(f.Content(), start)

		end := min(len(f.Content()), finding.Location.ByteEnd+384)
		for end < len(f.Content()) && !boundaryAt(f.Content(), end) {
			end++
		}

		for _, ex := range p.excerpts(f, start, end) {
			if !seen[ex.ID] && bytes+len(ex.Text) <= o.ChunkBytes && len(req.Excerpts) < review.MaxSegments {
				req.Excerpts = append(req.Excerpts, ex)
				seen[ex.ID] = true
				bytes += len(ex.Text)
			}
		}
	}
}

func (p *planner) sortGaps() {
	sort.Slice(p.gaps, func(i, j int) bool {
		a, b := p.gaps[i], p.gaps[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}

		if a.Path != b.Path {
			return a.Path < b.Path
		}

		if a.PluginID != b.PluginID {
			return a.PluginID < b.PluginID
		}

		if a.FindingID != b.FindingID {
			return a.FindingID < b.FindingID
		}

		if a.ByteStart != b.ByteStart {
			return a.ByteStart < b.ByteStart
		}

		return a.ByteEnd < b.ByteEnd
	})
}

func (p *planner) indexComponents() {
	for _, c := range p.graph.Components {
		if c.Path != "" {
			p.components[c.Path] = append(p.components[c.Path], c.ID)
		}
	}

	for path, ids := range p.components {
		sort.Strings(ids)

		if len(ids) > 32 {
			p.gap("component_context_limit", path, 0, 0, "", "")

			ids = ids[:32]
		}

		p.components[path] = ids
	}
}

func (p *planner) pluginPaths(plugin report.PluginInterpretation) []string {
	paths := map[string]bool{}

	for _, c := range p.graph.Components {
		if c.PluginID == plugin.ID && c.Path != "" {
			paths[c.Path] = true
		}
	}

	for _, m := range plugin.Manifests {
		paths[m] = true
	}

	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

func (p *planner) pluginContext(req *review.Request, names []string) bool {
	total := 0
	limited := false

	for _, name := range names {
		f, ok := p.files[name]
		if !ok || f.Metadata().Kind != "text" {
			limited = true
			continue
		}

		if total+len(f.Content()) > p.options.ChunkBytes || len(req.Excerpts)+(len(f.Content())+excerptBytes-1)/excerptBytes > review.MaxSegments {
			limited = true
			continue
		}

		req.Excerpts = append(req.Excerpts, p.excerpts(f, 0, len(f.Content()))...)
		total += len(f.Content())
	}

	return limited
}

func (p *planner) planSkillIntent(c report.Component) {
	o := p.options

	f, ok := p.files[c.Path]
	if !ok || f.Metadata().Kind != "text" || len(f.Content()) > o.ChunkBytes {
		p.gap("skill_intent_context_incomplete", c.Path, 0, 0, "", "")
		return
	}

	if len(f.Content()) == 0 {
		return
	}

	req := p.request(knowledge.ModeIntent)
	req.ScopeID = c.ID

	req.Excerpts = p.excerpts(f, 0, len(f.Content()))
	if code := p.add(req); code != "" {
		p.gap(code, c.Path, 0, len(f.Content()), "", "")
	}
}

func (p *planner) assessmentEvidence(refs []report.Location) exactEvidence {
	scope := exactEvidence{citations: []review.Citation{}, seen: map[string]bool{}, valid: true}

	for _, loc := range refs {
		ex, ok := p.evidenceExcerpt(loc)
		if !ok {
			scope.valid = false
			break
		}

		if !scope.seen[ex.ID] {
			scope.excerpts = append(scope.excerpts, ex)
			scope.citations = append(scope.citations, review.Citation{ExcerptID: ex.ID, SHA256: ex.SHA256})
			scope.seen[ex.ID] = true
			scope.bytes += len(ex.Text)
		}
	}

	return scope
}

func (p *planner) evidenceExcerpt(loc report.Location) (review.Excerpt, bool) {
	f, ok := p.files[loc.Path]
	if !ok || f.Metadata().Kind != "text" || loc.ByteStart < 0 || loc.ByteEnd <= loc.ByteStart || loc.ByteEnd > len(f.Content()) || !boundaryAt(f.Content(), loc.ByteStart) || !boundaryAt(f.Content(), loc.ByteEnd) {
		return review.Excerpt{}, false
	}
	// Main evidence is exact; contextual windows cannot replace or obscure it.
	ex := p.excerpt(f, loc.ByteStart, loc.ByteEnd)
	if len(ex.Text) > p.options.ChunkBytes {
		return review.Excerpt{}, false
	}

	return ex, true
}

func build(ctx context.Context, files []artifact.File, g report.ComponentGraph, findings []report.Finding, snapshot string, o review.Options, extraction report.ExtractionReport) *planner {
	p := &planner{
		ctx:        ctx,
		options:    o,
		graph:      g,
		snapshot:   snapshot,
		files:      map[string]artifact.File{},
		components: map[string][]string{},
		works:      []work{},
		gaps:       []report.SemanticGap{},
	}
	p.extraction = extraction

	fs := append([]artifact.File(nil), files...)
	for _, f := range fs {
		p.files[f.Metadata().Path] = f
	}

	p.indexComponents()

	// Stable priority: declared components first, then every other text object.
	// Neither file names nor inactivity suppress whole-artifact discovery.
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i].Metadata().Path, fs[j].Metadata().Path

		ac, bc := len(p.components[a]) > 0, len(p.components[b]) > 0
		if ac != bc {
			return ac
		}

		return a < b
	})

	for _, f := range fs {
		p.planDiscovery(f)
	}

	if o.QualityPolicy {
		p.planQuality()
	}

	p.planPluginIntents()
	p.planSkillIntents()
	p.planToolConsistency()

	for _, finding := range findings {
		p.planAssessment(finding)
	}

	p.sortGaps()

	return p
}

func boundaryAt(text string, offset int) bool {
	return offset == len(text) || offset >= 0 && offset < len(text) && utf8.RuneStart(text[offset])
}

// Prefer complete lines where possible; never split a UTF-8 code point. Very
// long lines are segmented, not truncated. End is always strictly after start.
func boundary(text string, start, end int) int {
	for end < len(text) && end > start && !utf8.RuneStart(text[end]) {
		end--
	}

	if end <= start {
		_, n := utf8.DecodeRuneInString(text[start:])
		return start + n
	}

	if end < len(text) {
		if at := strings.LastIndexByte(text[start:end], '\n'); at >= ((end - start) / 2) {
			return start + at + 1
		}
	}

	return end
}

func sourceRef(s review.Excerpt) report.SourceRef {
	return report.SourceRef{
		Path:       s.Path,
		SHA256:     s.ObjectSHA256,
		ByteStart:  s.ByteStart,
		ByteEnd:    s.ByteEnd,
		SpanSHA256: s.SHA256,
	}
}

func taskMetadata(req review.Request, raw []byte) report.SemanticTask {
	pd, _ := knowledge.Describe(req.Mode)

	meta := report.SemanticTask{
		KnowledgeTopicIDs: knowledge.ReviewTopicIDs(req.Mode),
		PromptSHA256:      pd.SHA256,
		PromptBytes:       pd.Bytes,
		ScopeID:           req.ScopeID,
		ID:                req.RequestID,
		Mode:              req.Mode,
		RequestSHA256:     artifact.Hash(raw),
		RequestBytes:      len(raw),
		Inputs:            []report.SemanticInput{},
		FindingIDs:        []string{},
		LinkIDs:           []string{},
	}
	for _, s := range req.Excerpts {
		meta.Inputs = append(meta.Inputs, report.SemanticInput{ID: s.ID, Source: sourceRef(s)})
	}

	for _, f := range req.Findings {
		if req.Mode == knowledge.ModeProposalAssessment {
			meta.ProposalIDs = append(meta.ProposalIDs, f.ID)
		} else {
			meta.FindingIDs = append(meta.FindingIDs, f.ID)
		}
	}

	for _, l := range req.Links {
		meta.LinkIDs = append(meta.LinkIDs, l.ID)
	}

	if req.ParentTaskID != "" {
		meta.DependsOn = []string{req.ParentTaskID}
	}

	return meta
}

func boundaryBefore(text string, offset int) int {
	for offset > 0 && !boundaryAt(text, offset) {
		offset--
	}

	return offset
}
