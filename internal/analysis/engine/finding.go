package engine

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/filetype"

	"github.com/skarm/scout/internal/analysis/document"

	"github.com/skarm/scout/internal/syntax/source"

	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
)

func makeFinding(rule report.Rule, doc document.File, m check.Match) (report.Finding, error) {
	severity, err := findingSeverity(rule, m)
	if err != nil {
		return report.Finding{}, err
	}

	f := doc.Artifact()
	s := f.Content()
	meta := f.Metadata()

	loc, err := location(doc, source.Span{Start: m.Start, End: m.End})
	if err != nil {
		return report.Finding{}, err
	}

	trace, err := findingTrace(doc, m.Trace)
	if err != nil {
		return report.Finding{}, err
	}

	identity := strings.Join([]string{"finding-v1", rule.ID, rule.Version, meta.Path, meta.SHA256, strconv.Itoa(m.Start), strconv.Itoa(m.End)}, "\x00")

	signals, err := findingContext(doc, m)
	if err != nil {
		return report.Finding{}, err
	}

	return report.Finding{
		ContextSignals: signals,
		ID:             artifact.Hash([]byte(identity)),
		RuleID:         rule.ID,
		RuleVersion:    rule.Version,
		Severity:       severity,
		Category:       rule.Category,
		Method:         rule.Method,
		Message:        rule.Title,
		Location:       loc,
		Evidence: report.Evidence{
			FileSHA256: meta.SHA256,
			SpanSHA256: artifact.Hash([]byte(s[m.Start:m.End])),
		},
		Trace: trace,
	}, nil
}

func location(doc document.File, span source.Span) (report.Location, error) {
	f := doc.Artifact()
	meta := f.Metadata()

	if err := validateLocationSpan(doc, span); err != nil {
		return report.Location{}, err
	}

	line, column, endLine, endColumn := 0, 0, 0, 0

	coordinates := "bytes"
	if meta.Kind == "text" {
		coordinates = "text"

		var err error

		line, column, err = doc.Index().Position(span.Start)
		if err != nil {
			return report.Location{}, err
		}

		endLine, endColumn, err = doc.Index().Position(span.End)
		if err != nil {
			return report.Location{}, err
		}
	}

	kind, language := doc.Context(span)

	return report.Location{
		Derived:     strings.HasPrefix(meta.Path, "scout-object://"),
		Path:        meta.Path,
		Coordinates: coordinates,
		ByteStart:   span.Start,
		ByteEnd:     span.End,
		StartLine:   line,
		StartColumn: column,
		EndLine:     endLine,
		EndColumn:   endColumn,
		Context:     filetype.Surface(meta.Path),
		Structure:   kind,
		Language:    language,
	}, nil
}

// Validate every cross-object reference against captured bytes. It is related
// evidence, not fabricated interprocedural taint or runtime execution.
func attachRelated(f *report.Finding, refs []report.SourceRef, docs map[string]document.File) error {
	if len(refs) > 8 {
		return errors.New("related evidence budget")
	}

	if len(refs) == 0 {
		return nil
	}

	var identity strings.Builder
	identity.WriteString(f.ID)

	for _, ref := range refs {
		doc, found := docs[ref.Path]
		if !found {
			return errors.New("unknown related object")
		}

		meta := doc.Artifact().Metadata()
		if meta.SHA256 != ref.SHA256 {
			return errors.New("related object digest")
		}

		if _, err := location(doc, source.Span{Start: ref.ByteStart, End: ref.ByteEnd}); err != nil {
			return err
		}

		if artifact.Hash([]byte(doc.Artifact().Content()[ref.ByteStart:ref.ByteEnd])) != ref.SpanSHA256 {
			return errors.New("related evidence digest")
		}

		f.RelatedEvidence = append(f.RelatedEvidence, ref)
		_, _ = fmt.Fprintf(&identity, "\x00%s\x00%s\x00%d\x00%d\x00%s", ref.Path, ref.SHA256, ref.ByteStart, ref.ByteEnd, ref.SpanSHA256)
	}
	// Commit the new identity only after every reference has been validated.
	f.ID = artifact.Hash([]byte(identity.String()))

	return nil
}

func findingSeverity(rule report.Rule, m check.Match) (report.Severity, error) {
	severity := rule.Severity
	if m.Severity != "" {
		if m.Severity.Rank() < 0 || m.Severity.Rank() > severity.Rank() {
			return "", errors.New("invalid finding severity")
		}

		severity = m.Severity
	}

	return severity, nil
}

func findingTrace(doc document.File, steps []check.Trace) ([]report.TraceStep, error) {
	f := doc.Artifact()
	s := f.Content()
	meta := f.Metadata()

	if len(steps) > 8 {
		return nil, errors.New("trace budget exceeded")
	}

	trace := make([]report.TraceStep, 0, len(steps))
	for _, step := range steps {
		if step.Role != "source" && step.Role != "sink" && step.Role != "transform" {
			return nil, errors.New("invalid trace role")
		}

		at, err := location(doc, source.Span{Start: step.Start, End: step.End})
		if err != nil {
			return nil, err
		}

		trace = append(trace, report.TraceStep{
			Role:     step.Role,
			Location: at,
			Evidence: report.Evidence{
				FileSHA256: meta.SHA256,
				SpanSHA256: artifact.Hash([]byte(s[step.Start:step.End])),
			},
		})
	}

	return trace, nil
}

func findingContext(doc document.File, m check.Match) ([]string, error) {
	s := doc.Artifact().Content()

	signals := knowledge.ContextSignals(s, m.Start, m.End)
	if len(m.ContextSignals) > 8 {
		return nil, errors.New("context signal budget exceeded")
	}

	for _, signal := range m.ContextSignals {
		switch signal {
		case "registry_assertion", "evidence_unavailable":
			signals = append(signals, signal)
		default:
			return nil, errors.New("invalid analyzer context signal")
		}
	}

	if m.InactiveForSurface {
		signals = append(signals, "ignored_by_supported_project_surface")
	}

	return signals, nil
}

func validateLocationSpan(doc document.File, span source.Span) error {
	f := doc.Artifact()
	s := f.Content()
	meta := f.Metadata()

	if span.Start < 0 || span.End < span.Start || span.End > len(s) || (span.Start == span.End && len(s) > 0) {
		return errors.New("invalid span")
	}

	if meta.Kind == "text" && (!runeBoundary(s, span.Start) || !runeBoundary(s, span.End)) {
		return errors.New("span bisects UTF-8")
	}

	return nil
}

func runeBoundary(text string, offset int) bool {
	return offset >= len(text) || utf8.RuneStart(text[offset])
}
