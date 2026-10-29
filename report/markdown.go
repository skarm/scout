package report

import (
	"fmt"
	"html"
	"io"
	"sort"
	"strconv"
	"strings"
)

// mdCode prevents file names, source-owned identifiers and control characters
// from becoming Markdown links, HTML or terminal control sequences. Reports do
// not contain source excerpts or arbitrary model-generated prose.
func mdCode(s string) string {
	s = strconv.QuoteToASCII(s)
	return "<code>" + strings.ReplaceAll(html.EscapeString(s), "`", "&#96;") + "</code>"
}

func markdown(w io.Writer, r Analysis, evaluation Evaluation) error {
	var b strings.Builder
	b.WriteString("# Scout security review\n\n")
	_, _ = fmt.Fprintf(&b, "**Decision:** %s. **Completeness:** %s.\n\n", mdCode(string(evaluation.Decision)), mdCode(string(r.Coverage.Completeness)))
	_, _ = fmt.Fprintf(&b, "Engine %s; profile %s.\n\n", mdCode(r.EngineVersion), mdCode(r.Profile))

	if r.Inspection.Name != "" {
		_, _ = fmt.Fprintf(&b, "Inspection preset: %s. Selection is not execution; outcomes appear in coverage.\n\n", mdCode(r.Inspection.Name))

		writeInspectionChecks(&b, r.Inspection.Checks, true)

		b.WriteString("\n")
	}

	_, _ = fmt.Fprintf(&b, "Snapshot: %s.\n\n", mdCode(r.Artifact.SnapshotSHA256))
	b.WriteString("This is a review of captured content under the named profile, not permission to install or proof of safe execution. A completed check is not a guarantee that all threats were detected.\n\n")
	_, _ = fmt.Fprintf(&b, "Captured files: **%d**; derived objects: **%d**; plugin interpretations: **%d**; static findings: **%d**.\n\n", r.Coverage.CapturedFiles, len(r.Extraction.Objects), len(r.Components.Plugins), len(r.Findings))

	if r.Source != nil {
		b.WriteString("## Remote input\n\n")
		_, _ = fmt.Fprintf(&b, "Status: %s; received byte digest: %s; supplied checksum verified: **%t**.\n\n", mdCode(r.Source.Status), mdCode(r.Source.BytesSHA256), r.Source.ExpectedChecksumVerified)

		if r.Source.Revision != "" {
			_, _ = fmt.Fprintf(&b, "Requested immutable Git revision: %s. The revision is provenance supplied to the transport, not a signature verification.\n\n", mdCode(r.Source.Revision))
		}
	}

	_, _ = fmt.Fprintf(&b, "Validation instructions: %s; SHA-256: %s. This digest identifies this adapted instruction pack, not an upstream checkout.\n\n", mdCode(r.Knowledge.Version), mdCode(r.Knowledge.SHA256))
	writeExtras(&b, r, evaluation, true)
	writeMarkdownFindings(&b, r)

	writeMarkdownSemantic(&b, r)

	if len(r.Dependencies.Manifests) > 0 {
		b.WriteString("## Declared dependencies\n\n")
		b.WriteString("These are declarations, not the resolved install graph. Go require versions are minimums under MVS. Exact-coordinate vulnerability results, when explicitly requested, are shown separately.\n\n")

		for _, d := range r.Dependencies.Declarations {
			_, _ = fmt.Fprintf(&b, "%s at declared version %s; replacement %s; source %s.\n\n", mdCode(d.Module), mdCode(d.DeclaredVersion), mdCode(d.Replacement), mdCode(d.Source.Path))
		}
	}

	b.WriteString("## Coverage gaps\n\n")
	writeMarkdownGaps(&b, r.Diagnostics)
	_, _ = fmt.Fprintf(&b, "Validation tasks: %d; recorded outcomes: %d; status: %s.\n\n", len(r.Validation.Tasks), len(r.Validation.Outcomes), mdCode(string(r.Validation.Completeness)))
	b.WriteString("## Limits of this result\n\n")

	for _, s := range r.Limitations {
		_, _ = fmt.Fprintf(&b, "%s\n\n", html.EscapeString(s))
	}

	_, err := io.WriteString(w, b.String())

	return err
}

func writeMarkdownGaps(b *strings.Builder, diagnostics []Diagnostic) {
	codes := map[string]int{}

	for _, d := range diagnostics {
		if d.AffectsScope {
			codes[d.Code]++
		}
	}

	names := make([]string, 0, len(codes))
	for k := range codes {
		names = append(names, k)
	}

	sort.Strings(names)

	for _, k := range names {
		_, _ = fmt.Fprintf(b, "%s: %d occurrence(s).\n\n", mdCode(k), codes[k])
	}

	if len(names) == 0 {
		b.WriteString("No additional scope diagnostic. This refers only to this profile; see limitations below.\n\n")
	}
}

func writeMarkdownFindings(b *strings.Builder, r Analysis) {
	b.WriteString("## Static findings\n\n")

	if len(r.Findings) == 0 {
		b.WriteString("No configured static rule produced a retained finding. Inspect completeness and limitations before drawing conclusions.\n\n")
	}

	findings := append([]Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Severity.Rank() > findings[j].Severity.Rank() })

	guides := ruleGuides(r.Rules)

	for _, f := range findings {
		_, _ = fmt.Fprintf(b, "### %s — %s\n\n", mdCode(f.RuleID), html.EscapeString(f.Message))
		_, _ = fmt.Fprintf(b, "Severity: **%s**; method: %s.\n\n", mdCode(string(f.Severity)), mdCode(f.Method))
		_, _ = fmt.Fprintf(b, "Location: %s, bytes %d–%d", mdCode(f.Location.Path), f.Location.ByteStart, f.Location.ByteEnd)

		if f.Location.Coordinates == "text" {
			_, _ = fmt.Fprintf(b, ", line %d, column %d", f.Location.StartLine, f.Location.StartColumn)
		}

		b.WriteString(".\n\n")
		_, _ = fmt.Fprintf(b, "Finding: %s. Evidence SHA-256: %s.\n\n", mdCode(f.ID), mdCode(f.Evidence.SpanSHA256))
		writeRuleGuidance(b, guides[f.RuleID], f.ContextSignals, true)

		for _, c := range f.Contexts {
			_, _ = fmt.Fprintf(b, "Component %s; relationship %s; activation %s.\n\n", mdCode(c.ComponentID), mdCode(c.Relation), mdCode(c.Activation))
		}

		for _, s := range f.Trace {
			_, _ = fmt.Fprintf(b, "Trace %s: %s, bytes %d–%d.\n\n", mdCode(s.Role), mdCode(s.Location.Path), s.Location.ByteStart, s.Location.ByteEnd)
		}
	}
}

func writeMarkdownSemantic(b *strings.Builder, r Analysis) {
	b.WriteString("## Semantic review\n\n")

	if !r.Semantic.Enabled {
		b.WriteString("Disabled. No source was uploaded to a reviewer by this scan. Static-only review does not establish absence of semantic prompt injection.\n\n")
	} else {
		_, _ = fmt.Fprintf(b, "Completeness: %s; validated requests: **%d**; proposals: **%d**. Model classifications are advisory, not proof of malicious intent.\n\n", mdCode(string(r.Semantic.Completeness)), r.Semantic.CompletedRequests, len(r.Semantic.Proposals))

		for _, p := range r.Semantic.Proposals {
			_, _ = fmt.Fprintf(b, "Proposal %s: %s; suggested severity %s.\n\n", mdCode(p.ID), mdCode(p.Reason), mdCode(string(p.SuggestedSeverity)))

			if p.KnowledgeTopicID != "" {
				_, _ = fmt.Fprintf(b, "Knowledge topic: %s.\n\n", mdCode(p.KnowledgeTopicID))
				writeRuleGuidance(b, p.Guidance, nil, true)
			}

			if p.UpstreamRuleID != "" {
				_, _ = fmt.Fprintf(b, "Adapted upstream taxonomy: %s.\n\n", mdCode(p.UpstreamRuleID))
			}
		}

		for _, a := range r.Semantic.Assessments {
			_, _ = fmt.Fprintf(b, "Assessment of %s: %s (%s). Original finding retained.\n\n", mdCode(a.FindingID), mdCode(a.Verdict), mdCode(a.Reason))
		}

		for _, a := range r.Semantic.ProposalAssessments {
			_, _ = fmt.Fprintf(b, "Recheck of proposal %s: %s (%s). Original proposal retained.\n\n", mdCode(a.ProposalID), mdCode(a.Verdict), mdCode(a.Reason))
		}
	}
}
