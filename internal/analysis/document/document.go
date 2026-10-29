// Package document prepares bounded, source-mapped analysis units. Markdown
// support is deliberately a block-envelope subset, NOT a CommonMark/YAML parser.
// Unhandled executable containers and frontmatter prevent automatic admission.
package document

import (
	"context"
	"go/ast"
	"go/token"
	"strings"

	"github.com/skarm/scout/internal/analysis/securitytext"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/filetype"
	"github.com/skarm/scout/internal/syntax/gobind"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

const (
	MaxRegions        = 512
	MaxUnitBytes      = parse.MaxUnitBytes
	MaxScanBytes      = parse.MaxScanBytes
	MaxSourceSegments = 8192
)

//nolint:gochecknoglobals // Read-only parser failure classifications shared by document preparation.
var parserFailureStatus = map[string]string{
	"unsupported_syntax":  "unsupported_syntax",
	"backend_unavailable": "unavailable",
	"parser_limit":        "budget_exceeded",
}

type region struct {
	Kind     string
	Language string // normalized allowlisted label; never untrusted metadata
	Span     source.Span
}

// GoUnit contains a tree and token set owned by the preparation stage. Trusted
// analyzers must not mutate them. They never invoke a compiler or importer.
type GoUnit struct {
	View     source.View
	Tree     *ast.File
	Tokens   *token.FileSet
	Bindings gobind.Bindings
}

// Unit is language-neutral. Unsupported units are retained, rather than being
// silently discarded. A parser tree is private to its matching trusted backend.
type Unit struct {
	Language, Origin, ParserID, ParserVersion, Status string
	Span                                              source.Span
	View                                              source.View
	Tree                                              any
	failureCategory                                   string
	preparationDiagnostic                             report.Diagnostic
}

// ConfigScope is a non-authoritative structural role attached by harness discovery.
// It grants no exemptions, does not imply activation and always uses physical bytes.
type ConfigScope struct {
	Role string
	Host string
	Span source.Span
}

type File struct {
	securityViews  []source.View
	configScopes   []ConfigScope
	file           artifact.File
	index          source.Index
	regions        []region
	units          []Unit
	classification filetype.Description
	registry       parse.Registry
	diagnostics    []report.Diagnostic
	budget         *parseBudget
	derived        []derivedConfig
	derivedReady   bool
	derivedGap     bool
	shellReady     bool
	shellGap       bool
	shellUnits     []Unit
}

// filePreparation confines mutation to the preparation phase; File values remain snapshots.
type filePreparation File

type parseBudget struct {
	consumed      map[string]int
	securityBytes int
}

type line struct{ start, end, next int }

type frontmatterEnvelope struct {
	span, body source.Span
	closed     bool
}

// A fenced mapping has one monotone budget: once a line exceeds it, no later
// line can re-enter the view. Content presence still tracks the physical body.
type fenceMapping struct {
	spans            []source.Span
	bytes            int
	content, limited bool
}

// PrepareAll enforces an additional aggregate per-backend parser budget per scan, not
// merely a per-file limit. It shares no cache or mutable state between scans.
func PrepareAll(ctx context.Context, files []artifact.File) []File {
	return PrepareAllWithRegistry(ctx, files, parse.Defaults())
}

// PrepareAllWithRegistry allows future languages without language switches in
// the preparation engine. A registered parser does not imply semantic coverage.
func PrepareAllWithRegistry(ctx context.Context, files []artifact.File, registry parse.Registry) []File {
	budget := parseBudget{consumed: make(map[string]int)}

	documents := make([]File, len(files))
	for i, file := range files {
		documents[i] = prepare(ctx, file, &budget, registry)
	}

	return documents
}

// Prepare retains the raw file even if parsing fails: literal checks must still
// run. Diagnostics contain neither parser errors nor source excerpts.
func Prepare(ctx context.Context, file artifact.File) (out File) {
	return prepare(ctx, file, &parseBudget{consumed: make(map[string]int)}, parse.Defaults())
}

func (f File) WithConfigScopes(scopes []ConfigScope) File {
	f.configScopes = append([]ConfigScope(nil), scopes...)
	return f
}
func (f File) ConfigScopes() []ConfigScope { return append([]ConfigScope(nil), f.configScopes...) }

func (f File) Artifact() artifact.File      { return f.file }
func (f File) SecurityViews() []source.View { return append([]source.View(nil), f.securityViews...) }
func (f File) Index() source.Index          { return f.index }
func (f File) Regions() []region            { return append([]region(nil), f.regions...) }
func (f File) Units() []Unit                { return append([]Unit(nil), f.units...) }
func (f File) Classification() filetype.Description {
	d := f.classification
	d.Languages = append([]language.Hint(nil), d.Languages...)

	return d
}

func (f File) GoUnits() []GoUnit {
	var units []GoUnit
	for _, u := range f.units {
		if tree, ok := u.Tree.(parse.GoTree); ok {
			units = append(units, GoUnit{View: u.View, Tree: tree.Tree, Tokens: tree.Tokens, Bindings: tree.Bindings})
		}
	}

	return units
}

// HasParsedUnits is language neutral. A backend result does not establish
// semantic completeness; unit statuses and diagnostics remain authoritative.
func (f File) HasParsedUnits() bool {
	for _, u := range f.units {
		if u.ParserID != "" && u.Tree != nil {
			return true
		}
	}

	return false
}

func (f File) HasGo() bool {
	for _, u := range f.units {
		if _, ok := u.Tree.(parse.GoTree); ok {
			return true
		}
	}

	return false
}

func (f File) Diagnostics() []report.Diagnostic {
	return append([]report.Diagnostic(nil), f.diagnostics...)
}

func (f File) Context(s source.Span) (kind, language string) {
	for _, r := range f.regions {
		if s.Start >= r.Span.Start && s.End <= r.Span.End {
			return r.Kind, r.Language
		}
	}

	for _, u := range f.units {
		if u.Origin == "file" && s.Start >= u.Span.Start && s.End <= u.Span.End {
			return "source-file", u.Language
		}
	}

	return "", ""
}

func (f *filePreparation) issue(code, message string) {
	// One diagnostic of a given kind per file bounds large malformed documents.
	for _, d := range f.diagnostics {
		if d.Code == code {
			return
		}
	}

	f.diagnostics = append(f.diagnostics, report.Diagnostic{
		Code:         code,
		Path:         f.file.Metadata().Path,
		Message:      message,
		AffectsScope: true,
	})
}

// advisory records a declared analysis boundary, not an unfinished selected task.
func (f *filePreparation) advisory(code, message string) {
	for _, d := range f.diagnostics {
		if d.Code == code {
			return
		}
	}

	f.diagnostics = append(f.diagnostics, report.Diagnostic{Code: code, Path: f.file.Metadata().Path, Message: message})
}

func (f *filePreparation) region(r region) bool {
	if len(f.regions) >= MaxRegions {
		f.issue("document_region_limit", "Document region budget exhausted; remaining structure is unknown.")
		return false
	}

	f.regions = append(f.regions, r)

	return true
}

func (f *filePreparation) addUnit(ctx context.Context, lang, origin string, span source.Span, v source.View) {
	if len(f.units)+len(f.shellUnits) >= MaxRegions {
		f.issue("analysis_unit_limit", "Analysis unit budget exhausted; remaining units are unverified.")
		return
	}

	unit := f.parseUnit(ctx, lang, origin, span, v)
	f.publishUnit(ctx, unit)
}

// Parser admission belongs to the preparation owner. Ordinary, derived and
// candidate units all spend the same backend byte quota before a parser runs.
func (f *filePreparation) admitUnit(ctx context.Context, descriptor parse.Descriptor, unit *Unit) bool {
	unit.ParserID, unit.ParserVersion, unit.Status = descriptor.ID, descriptor.Version, report.OutcomeNotRun

	if ctx.Err() != nil {
		return false
	}

	bytes := len(unit.View.Text())
	if bytes > descriptor.UnitBytes {
		unit.Status = "budget_exceeded"
		unit.preparationDiagnostic = report.Diagnostic{
			Code:    unit.Language + "_source_limit",
			Message: "Analysis unit exceeds the parser byte budget.",
		}

		return false
	}

	if bytes > descriptor.ScanBytes-f.budget.consumed[descriptor.ID] {
		unit.Status = "budget_exceeded"
		unit.preparationDiagnostic = report.Diagnostic{
			Code:    unit.Language + "_scan_budget",
			Message: "Aggregate parser byte budget exhausted; this unit was not parsed.",
		}

		return false
	}

	f.budget.consumed[descriptor.ID] += bytes

	return true
}

func (f *filePreparation) parseUnit(ctx context.Context, lang, origin string, span source.Span, view source.View) (unit Unit) {
	defer func() {
		if recover() != nil {
			unit.Status = report.OutcomeFailed

			unit.preparationDiagnostic = report.Diagnostic{
				Code:    "parser_panic",
				Message: "Document preparation failed; raw-text checks remain available.",
			}
		}
	}()

	unit = Unit{Language: lang, Origin: origin, Span: span, View: view, Status: report.OutcomeUnsupported}

	backend, supported := f.registry.Lookup(lang)
	if !supported || !f.admitUnit(ctx, backend.Descriptor(), &unit) {
		return unit
	}

	unit.Status = "parsing"
	tree, err := backend.Parse(ctx, view)

	unit.Tree, unit.Status = tree, report.UnitParsedLimited
	if identity, ok := tree.(interface{ RuntimeIdentity() string }); ok && identity.RuntimeIdentity() != "" {
		unit.ParserVersion += ":" + identity.RuntimeIdentity()
	}

	if err != nil {
		unit.failureCategory = parse.FailureCategory(err)

		unit.Status = parserFailureStatus[unit.failureCategory]
		if unit.Status == "" {
			unit.Status = report.UnitParseError
		}
	}

	return unit
}

func (f *filePreparation) publishUnit(ctx context.Context, unit Unit) {
	f.units = append(f.units, unit)
	if diagnostic := unit.preparationDiagnostic; diagnostic.Code != "" {
		f.issue(diagnostic.Code, diagnostic.Message)
	}

	if unit.ParserID == "" {
		code := "structural_analysis_unavailable"
		if unit.Origin != "file" {
			code = "embedded_language_unsupported"
		}

		f.issue(code, "No parser is installed for an analysis unit; raw checks still run and its semantics remain unverified.")

		return
	}

	f.advisory(unit.Language+"_semantics_limited", "A syntax parser and selected rules do not establish complete behavior, variable flow or cross-file semantics.")

	if category := unit.failureCategory; category != "" {
		f.issue(unit.Language+"_"+category, "Syntax was not fully parsed; preceding usable syntax is still checked and unparsed content remains unverified.")
	}

	if unit.Language == language.TOML {
		f.issue("toml_coarse_evidence", "The trusted TOML parser supplies values without token positions; evidence covers the complete unit, not invented per-field locations.")
	}

	if ctx.Err() != nil {
		f.issue("preparation_cancelled", "Document preparation was cancelled.")
	}
}

func (f *filePreparation) markdown(ctx context.Context) {
	text := f.file.Content()
	at := 0
	// UTF-8 BOM is retained in raw source and mapping.
	if strings.HasPrefix(text, "\ufeff") {
		at = len("\ufeff")
	}

	at, proceed := f.markdownFrontmatter(ctx, text, at)
	if !proceed {
		return
	}

	f.markdownBody(ctx, text, at)
}

func readFrontmatter(ctx context.Context, text string, at int) (frontmatterEnvelope, bool) {
	first := nextLine(text, at)

	envelope := frontmatterEnvelope{
		span: source.Span{Start: at, End: len(text)},
		body: source.Span{
			Start: first.next,
			End:   len(text),
		},
	}
	for at = first.next; at < len(text); {
		if ctx.Err() != nil {
			return envelope, false
		}

		line := nextLine(text, at)

		at = line.next
		if text[line.start:line.end] == "---" || text[line.start:line.end] == "..." {
			envelope.span.End, envelope.body.End, envelope.closed = at, line.start, true
			break
		}
	}

	return envelope, true
}

func (f *filePreparation) markdownFrontmatter(ctx context.Context, text string, at int) (int, bool) {
	if at >= len(text) {
		return at, true
	}

	first := nextLine(text, at)
	if text[first.start:first.end] != "---" {
		return at, true
	}

	envelope, proceed := readFrontmatter(ctx, text, at)
	if !proceed {
		f.issue("preparation_cancelled", "Document preparation was cancelled.")
		return at, false
	}

	f.region(region{Kind: "frontmatter", Language: language.YAML, Span: envelope.span})

	_, supported := f.registry.Lookup(language.YAML)
	if supported && envelope.closed && envelope.body.End > envelope.body.Start {
		view, err := source.NewView(text, []source.Span{envelope.body})
		if err != nil {
			f.issue("source_map_error", "Frontmatter mapping failed.")
		} else {
			f.addUnit(ctx, language.YAML, "frontmatter", envelope.body, view)
		}
	} else {
		f.issue("frontmatter_semantics_unavailable", "Frontmatter YAML interpretation is unavailable; raw bytes remain subject to all rules.")
	}

	if !envelope.closed {
		f.issue("unterminated_frontmatter", "Frontmatter has no closing delimiter; structure is uncertain.")
	}

	return envelope.span.End, true
}

func (f *filePreparation) markdownBody(ctx context.Context, text string, at int) {
	for at < len(text) {
		if ctx.Err() != nil {
			f.issue("preparation_cancelled", "Document preparation was cancelled.")
			return
		}

		l := nextLine(text, at)
		s := text[l.start:l.end]

		indent, ch, width, info, ok := openingFence(s)
		if ok {
			var proceed bool

			at, proceed = f.markdownFence(ctx, text, l, indent, ch, width, info)
			if !proceed {
				return
			}

			continue
		}

		if !f.markdownOpaqueLine(text, l) {
			return
		}

		at = l.next
	}
}

func (f *filePreparation) markdownFence(ctx context.Context, text string, l line, indent int, ch byte, width int, info string) (int, bool) {
	start := l.start
	lang := fenceLanguage(info)
	at := l.next
	mapping := fenceMapping{}
	closed := false

	for at < len(text) {
		if ctx.Err() != nil {
			f.issue("preparation_cancelled", "Document preparation was cancelled.")
			return at, false
		}

		body := nextLine(text, at)

		at = body.next
		if closingFence(text[body.start:body.end], ch, width) {
			closed = true
			break
		}

		mapping.add(f, text, body, indent, lang)
	}

	if !f.region(region{Kind: "fenced-code", Language: lang, Span: source.Span{Start: start, End: at}}) {
		return at, false
	}

	if !closed {
		f.issue("unclosed_fence", "A fence extends to end of file; its content is not treated as safe text.")
	}

	if !mapping.content || mapping.limited {
		return at, true
	}
	{
		view, err := source.NewView(text, mapping.spans)
		if err != nil {
			f.issue("source_map_error", "Embedded source mapping failed.")
			return at, true
		}

		f.addUnit(ctx, lang, "fenced-code", source.Span{Start: start, End: at}, view)
	}

	return at, true
}

func prepare(ctx context.Context, file artifact.File, budget *parseBudget, registry parse.Registry) (out File) {
	out = File{
		file: file, budget: budget, registry: registry,
		classification: filetype.Inspect(file.Metadata().Path, file.Content(), file.Metadata().Executable),
	}

	projection := (*filePreparation)(&out)
	if file.GeneratedName() {
		// A synthetic .txt label cannot establish filename deception. Keep all
		// detected languages, executable hints and raw/decoded analysis intact.
		out.classification.Conflict = false
	}

	if ctx == nil || ctx.Err() != nil {
		projection.issue("preparation_cancelled", "Document preparation was cancelled.")
		return out
	}

	if file.Metadata().Kind != "text" {
		return out
	}

	out.index = source.NewIndex(file.Content())

	projection.prepareSecurityViews(ctx)

	projection.prepareFileUnits(ctx)

	// Any text file may contain an embedded document, including LICENSE, JSON
	// or source code. This conservative envelope pass never grants trust.
	projection.markdown(ctx)

	return out
}

func nextLine(text string, start int) line {
	n := strings.IndexByte(text[start:], '\n')

	end, next := len(text), len(text)
	if n >= 0 {
		end = start + n
		next = end + 1
	}

	if end > start && text[end-1] == '\r' {
		end--
	}

	return line{start: start, end: end, next: next}
}

func openingFence(s string) (indent int, ch byte, width int, info string, ok bool) {
	trimmed := strings.TrimLeft(s, " ")

	n := len(s) - len(trimmed)
	if n > 3 {
		return
	}

	marker, count := textmatch.FencePrefix(trimmed)
	if count == 0 {
		return
	}

	indent, ch, width, info = n, marker, count, strings.TrimSpace(trimmed[count:])
	ok = ch != '`' || !strings.ContainsRune(info, '`')

	return
}

func closingFence(s string, ch byte, width int) bool {
	trimmed := strings.TrimLeft(s, " ")
	indent := len(s) - len(trimmed)
	rest := strings.TrimLeft(trimmed, string(ch))

	return indent <= 3 && len(trimmed)-len(rest) >= width && strings.TrimSpace(rest) == ""
}

func fenceLanguage(info string) string {
	fields := strings.Fields(info)
	if len(fields) == 0 {
		return language.Unknown
	}

	return language.Normalize(fields[0])
}

func (f *filePreparation) prepareSecurityViews(ctx context.Context) {
	if len(f.file.Content()) > securitytext.MaxScanBytes-f.budget.securityBytes {
		f.issue("security_reconstruction_limit", "Aggregate security-text reconstruction budget exhausted; raw checks remain available.")
	} else {
		f.budget.securityBytes += len(f.file.Content())

		var limited bool

		f.securityViews, limited = securitytext.Views(ctx, f.file.Content())
		if limited {
			f.issue("security_reconstruction_limit", "Security-text reconstruction exceeded its source, mapping or runtime budget; raw checks remain available.")
		}
	}
}

func (f *filePreparation) markdownOpaqueLine(text string, l line) bool {
	s := text[l.start:l.end]
	// Conservatively account for constructs requiring full CommonMark parsing.
	trim := strings.TrimLeft(s, " \t")
	if strings.HasPrefix(s, "    ") || strings.HasPrefix(s, "\t") {
		if strings.TrimSpace(s) != "" {
			if !f.region(region{
				Kind:     "indented-content",
				Language: language.Unknown,
				Span: source.Span{
					Start: l.start,
					End:   l.next,
				},
			}) {
				return false
			}

			f.issue("markdown_container_unsupported", "Indented content requires a full Markdown/container parser; literal checks still run.")
		}
	}

	if strings.HasPrefix(trim, ">") || strings.HasPrefix(trim, "<") ||
		(strings.Contains(trim, "```") || strings.Contains(trim, "~~~")) {
		f.issue("markdown_container_unsupported", "Nested, inline-fenced or HTML content is outside the block-envelope parser; literal checks still run.")
	}

	return true
}

// Every whole-file language candidate shares one immutable mapping. A renamed
// or conflicting source can select several backends without rebuilding bytes.
func (f *filePreparation) prepareFileUnits(ctx context.Context) {
	seen := map[string]bool{}

	var languages []string

	for _, hint := range f.classification.Languages {
		if !language.Structured(hint.Language) || seen[hint.Language] {
			continue
		}

		seen[hint.Language] = true
		languages = append(languages, hint.Language)
	}

	if len(languages) == 0 {
		return
	}

	span := source.Span{End: len(f.file.Content())}

	view, err := source.NewView(f.file.Content(), []source.Span{span})
	if err != nil {
		f.issue("source_map_error", "Source mapping could not be constructed.")
		return
	}

	for _, lang := range languages {
		f.addUnit(ctx, lang, "file", span, view)
	}
}

func (m *fenceMapping) add(f *filePreparation, text string, body line, indent int, lang string) {
	m.content = m.content || strings.TrimSpace(text[body.start:body.end]) != ""
	prefix := min(indent, len(text[body.start:body.end])-len(strings.TrimLeft(text[body.start:body.end], " ")))

	m.bytes += body.next - body.start - prefix
	if m.bytes > MaxUnitBytes {
		m.limited = true

		f.issue(lang+"_source_limit", "Embedded analysis unit exceeds the source byte budget.")
	} else if len(m.spans) >= MaxSourceSegments {
		m.limited = true

		f.issue("document_segment_limit", "Embedded source mapping exceeds its segment budget.")
	}

	if !m.limited {
		m.spans = append(m.spans, source.Span{Start: body.start + prefix, End: body.next})
	}
}
