package engine

import (
	"context"
	"slices"

	"github.com/skarm/scout/internal/analysis/document"

	"github.com/skarm/scout/internal/syntax/filetype"

	"github.com/skarm/scout/report"
)

type coverageGap struct{ code, message string }

func initializeFileCoverage(r *report.Analysis, documents []document.File) map[string]int {
	inventory := append([]report.File(nil), r.Artifact.Files...)
	for _, object := range r.Extraction.Objects {
		inventory = append(inventory, object.File)
	}

	fileIndex := make(map[string]int, len(inventory))
	for _, m := range inventory {
		fc := report.FileCoverage{
			Path: m.Path, ReadStatus: m.Status, Completeness: report.Complete,
			Checks: []report.FileCheck{}, Units: []report.UnitCoverage{}, Gaps: []string{},
			Classification: filetype.Description{
				Format:   "unknown",
				Category: "unknown",
				Encoding: "not_read",
				Basis:    "not_inspected",
			},
		}
		if m.Status != report.CaptureCaptured {
			fc.Gaps = append(fc.Gaps, m.Reason)
		}

		fileIndex[m.Path] = len(r.Coverage.Files)
		r.Coverage.Files = append(r.Coverage.Files, fc)
	}

	extracted := make(map[string]bool)
	for _, step := range r.Extraction.Steps {
		extracted[step.ParentPath] = true
	}

	for _, diagnostic := range r.Diagnostics {
		if index, ok := fileIndex[diagnostic.Path]; ok && diagnostic.AffectsScope {
			r.Coverage.Files[index].Gaps = append(r.Coverage.Files[index].Gaps, diagnostic.Code)
		}
	}

	for _, doc := range documents {
		f := doc.Artifact()
		fc := &r.Coverage.Files[fileIndex[f.Metadata().Path]]
		classifyCoverage(r, fc, doc, extracted)
	}

	return fileIndex
}

func classifyCoverage(r *report.Analysis, fc *report.FileCoverage, doc document.File, extracted map[string]bool) {
	f := doc.Artifact()

	fc.Classification = doc.Classification()
	for _, u := range doc.Units() {
		fc.Units = append(fc.Units, report.UnitCoverage{
			Language:      u.Language,
			Origin:        u.Origin,
			ParserID:      u.ParserID,
			ParserVersion: u.ParserVersion,
			Status:        u.Status,
			ByteStart:     u.Span.Start,
			ByteEnd:       u.Span.End,
		})
	}

	for _, d := range doc.Diagnostics() {
		r.Diagnostics = append(r.Diagnostics, d)
		if d.AffectsScope {
			fc.Gaps = append(fc.Gaps, d.Code)
		}
	}

	m := f.Metadata()
	if m.Kind == "text" {
		r.Coverage.TextFiles++
	}

	c := fc.Classification
	// Container boundaries take precedence over the generic byte/syntax gap.
	gap := containerCoverageGap(c.Category, extracted[m.Path])
	if gap.code == "" {
		gap = contentCoverageGap(c, m.Kind, doc.HasParsedUnits())
	}

	if gap.code != "" && !slices.Contains(fc.Gaps, gap.code) {
		fc.Gaps = append(fc.Gaps, gap.code)
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
			Code:         gap.code,
			Path:         m.Path,
			Message:      gap.message,
			AffectsScope: true,
		})
	}

	if c.Conflict {
		fc.Gaps = append(fc.Gaps, "conflicting_content_hints")
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
			Code:         "conflicting_content_hints",
			Path:         m.Path,
			Message:      "Filename, signature or language declarations conflict; none grants a security exemption.",
			AffectsScope: true,
		})
	}
}

// Container coverage describes extraction, independently of text/parser status.
func containerCoverageGap(category string, extracted bool) coverageGap {
	switch category {
	case "archive":
		if extracted {
			return coverageGap{
				code:    "container_semantics_limited",
				message: "Extraction was attempted for supported members and metadata; see extraction statuses. This is not complete container or behavior analysis.",
			}
		}

		return coverageGap{
			code:    "nested_archive_unsupported",
			message: "This archive format has no extractor; raw bytes remain subject to checks.",
		}
	case "image", "document", "database", "media":
		if extracted {
			return coverageGap{
				code:    "container_semantics_limited",
				message: "Selected metadata was extracted; pixels, arbitrary attachments and full format semantics remain unverified.",
			}
		}

		return coverageGap{
			code:    "container_semantics_unavailable",
			message: "Raw bytes were checked but this format's text, metadata, attachments and encoded contents were not extracted.",
		}
	default:
		return coverageGap{}
	}
}

func contentCoverageGap(c filetype.Description, kind string, parsed bool) coverageGap {
	switch {
	case kind == "binary" || c.Executable:
		return coverageGap{
			code:    "opaque_content",
			message: "Raw byte patterns were checked, but encoded contents, embedded objects and behavior remain unverified.",
		}
	case c.Structured && !parsed:
		return coverageGap{
			code:    "structural_analysis_unavailable",
			message: "Literal patterns were checked; required code/configuration semantics are not implemented in this prototype.",
		}
	case c.Category == "unknown":
		return coverageGap{
			code:    "unrecognized_content",
			message: "Unknown file format: raw patterns were checked, but syntax and encoded or embedded content remain unverified.",
		}
	default:
		return coverageGap{}
	}
}

func reduceCoverage(ctx context.Context, r *report.Analysis) {
	r.Coverage.Completeness = report.Complete
	if !completeChildren(*r) || !completeServices(*r) {
		r.Coverage.Completeness = report.Partial
	}

	for i := range r.Coverage.Files {
		file := &r.Coverage.Files[i]

		file.Completeness = report.Complete
		if !completeFile(*file) {
			file.Completeness = report.Partial
			r.Coverage.Completeness = report.Partial
		}
	}

	if !completeChecks(r.Coverage.Checks) || slices.ContainsFunc(r.Diagnostics, func(d report.Diagnostic) bool { return d.AffectsScope }) {
		r.Coverage.Completeness = report.Partial
	}

	if len(r.Coverage.Files) == 0 || ctx.Err() != nil {
		r.Coverage.Completeness = report.Failed
	}
}

func completeChildren(r report.Analysis) bool {
	return r.Artifact.InventoryComplete && r.Metadata.Completeness == report.Complete && r.Validation.Completeness == report.Complete && completeExtraction(r.Extraction) && completeDependencies(r.Dependencies)
}

func completeDependencies(dependencies report.DependencyReport) bool {
	for _, manifest := range dependencies.Manifests {
		if !manifest.InventoryComplete() {
			return false
		}
	}

	return true
}

func completeExtraction(extraction report.ExtractionReport) bool {
	if len(extraction.Skipped) > 0 {
		return false
	}

	for _, step := range extraction.Steps {
		if step.Status != report.OutcomeCompleted {
			return false
		}
	}

	return true
}

func completeServices(r report.Analysis) bool {
	return (!r.Signatures.Enabled || r.Signatures.Completeness == string(report.Complete)) && (!r.Semantic.Enabled || r.Semantic.Completeness == report.Complete) && (!r.Vulnerabilities.Enabled || r.Vulnerabilities.Completeness == report.Complete)
}

func completedStatus(status string) bool {
	return status == report.OutcomeCompleted || status == report.OutcomeNotApplicable || status == report.OutcomeCached
}

func completeFile(file report.FileCoverage) bool {
	if file.ReadStatus != report.CaptureCaptured || len(file.Gaps) > 0 {
		return false
	}

	for _, check := range file.Checks {
		if !completedStatus(check.Status) {
			return false
		}
	}

	return true
}

func completeChecks(checks []report.Check) bool {
	for _, check := range checks {
		if !completedStatus(check.Status) {
			return false
		}
	}

	return true
}
