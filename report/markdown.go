package report

import (
	"fmt"
	"html"
	"io"
	"strconv"
	"strings"
)

// mdCode prevents file names, source-owned identifiers and control characters
// from becoming Markdown links, HTML or terminal control sequences. Reports do
// not contain source excerpts or arbitrary model-generated prose.
func mdCode(s string) string {
	s = strconv.Quote(s)
	if s == `""` {
		return "`" + s + "`"
	}

	s = s[1 : len(s)-1]

	longest, ticks := 0, 0

	for _, c := range s {
		if c == '`' {
			ticks++
			longest = max(longest, ticks)
		} else {
			ticks = 0
		}
	}

	delimiter := strings.Repeat("`", longest+1)
	// CommonMark trims one surrounding space from nonblank code spans. Padding
	// keeps edge backticks separate and preserves intentional edge spaces.
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") ||
		(strings.HasPrefix(s, " ") && strings.HasSuffix(s, " ") && strings.Trim(s, " ") != "") {
		s = " " + s + " "
	}

	return delimiter + s + delimiter
}

func markdown(w io.Writer, r Analysis, evaluation Evaluation) error {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "Completeness: %s. Captured files: **%d**; derived objects: **%d**; analyzed objects: **%d** (**%d** text).\n\n",
		mdCode(string(r.Coverage.Completeness)), r.Coverage.CapturedFiles, len(r.Extraction.Objects), r.Coverage.AnalyzedObjects, r.Coverage.TextFiles)
	_, _ = fmt.Fprintf(&b, "Static findings: **%d** (%s).\n\n", len(r.Findings), severitySummary(r.Findings))
	writeMarkdownFindings(&b, r, evaluation)
	writeMarkdownSemantic(&b, r)

	if r.Vulnerabilities.Enabled {
		b.WriteString("### Known vulnerabilities\n\n")
	}

	writeVulnerabilityExtras(&b, r, mdCode)
	writeHumanDiagnostics(&b, r.Diagnostics, true)
	writeValidationSummary(&b, r.Validation, true)

	b.WriteString("### Inspection details\n\n")

	_, _ = fmt.Fprintf(&b, "Engine %s; profile %s; harness %s.\n\n", mdCode(r.EngineVersion), mdCode(r.Profile), mdCode(r.Components.RequestedHost))
	if r.Inspection.Name != "" {
		_, _ = fmt.Fprintf(&b, "Inspection preset: %s. Selection is not execution; outcomes appear in coverage.\n\n", mdCode(r.Inspection.Name))
		writeInspectionChecks(&b, r.Inspection.Checks, true)
		b.WriteString("\n")
	}

	if r.Artifact.SnapshotSHA256 != "" {
		_, _ = fmt.Fprintf(&b, "Snapshot: %s.\n\n", mdCode(r.Artifact.SnapshotSHA256))
	}

	b.WriteString("This is a review of captured content under the named profile, not permission to install or proof of safe execution. A completed check is not a guarantee that all threats were detected.\n\n")

	_, _ = fmt.Fprintf(&b, "Plugin interpretations: **%d**; components: **%d**.\n\n", len(r.Components.Plugins), len(r.Components.Components))
	if r.Source != nil {
		b.WriteString("### Remote input\n\n")

		_, _ = fmt.Fprintf(&b, "Status: %s; received byte digest: %s; supplied checksum verified: **%t**.\n\n", mdCode(r.Source.Status), mdCode(r.Source.BytesSHA256), r.Source.ExpectedChecksumVerified)
		if r.Source.Revision != "" {
			_, _ = fmt.Fprintf(&b, "Requested immutable Git revision: %s. The revision is provenance supplied to the transport, not a signature verification.\n\n", mdCode(r.Source.Revision))
		}
	}

	_, _ = fmt.Fprintf(&b, "Validation instructions: %s; SHA-256: %s. This digest identifies this adapted instruction pack, not an upstream checkout.\n\n", mdCode(r.Knowledge.Version), mdCode(r.Knowledge.SHA256))
	writeExtras(&b, r, evaluation, true)

	if len(r.Dependencies.Manifests) > 0 {
		b.WriteString("### Declared dependencies\n\n")
		b.WriteString("These are declarations, not the resolved install graph. Go require versions are minimums under MVS. Exact-coordinate vulnerability results, when explicitly requested, are shown separately.\n\n")

		for _, d := range r.Dependencies.Declarations {
			_, _ = fmt.Fprintf(&b, "%s at declared version %s; replacement %s; source %s.\n\n", mdCode(d.Module), mdCode(d.DeclaredVersion), mdCode(d.Replacement), mdCode(d.Source.Path))
		}
	}

	b.WriteString("### Limits of this result\n\n")

	for _, s := range r.Limitations {
		_, _ = fmt.Fprintf(&b, "%s\n\n", html.EscapeString(s))
	}

	_, err := io.WriteString(w, b.String())

	return err
}

func writeMarkdownFindings(b *strings.Builder, r Analysis, evaluation Evaluation) {
	b.WriteString("### Static findings\n\n")

	if len(r.Findings) == 0 {
		b.WriteString("No configured static rule produced a retained finding. Inspect completeness and limitations before drawing conclusions.\n\n")
	}

	findings := sortedFindings(r.Findings)

	guides := ruleGuides(r.Rules)
	approved := approvedFindings(evaluation)

	for _, f := range findings {
		_, _ = fmt.Fprintf(b, "#### %s — %s\n\n", mdCode(f.RuleID), html.EscapeString(f.Message))
		_, _ = fmt.Fprintf(b, "Severity: **%s**; method: %s.\n\n", mdCode(string(f.Severity)), mdCode(f.Method))
		_, _ = fmt.Fprintf(b, "Location: %s, bytes %d–%d", mdCode(f.Location.Path), f.Location.ByteStart, f.Location.ByteEnd)

		if f.Location.Coordinates == "text" {
			_, _ = fmt.Fprintf(b, ", line %d, column %d", f.Location.StartLine, f.Location.StartColumn)
		}

		b.WriteString(".\n\n")
		writeRuleGuidance(b, guides[f.RuleID], f.ContextSignals, true)

		if approved[f.ID] {
			b.WriteString("**Operator approved:** this occurrence remains visible as evidence.\n\n")
		}

		for _, c := range f.Contexts {
			_, _ = fmt.Fprintf(b, "Component %s; relationship %s; activation %s.\n\n", mdCode(c.ComponentID), mdCode(c.Relation), mdCode(c.Activation))
		}

		for _, s := range f.Trace {
			_, _ = fmt.Fprintf(b, "Trace %s: %s, bytes %d–%d.\n\n", mdCode(s.Role), mdCode(s.Location.Path), s.Location.ByteStart, s.Location.ByteEnd)
		}

		_, _ = fmt.Fprintf(b, "Finding: %s. Evidence SHA-256: %s.\n\n", mdCode(f.ID), mdCode(f.Evidence.SpanSHA256))
	}
}

func writeMarkdownSemantic(b *strings.Builder, r Analysis) {
	b.WriteString("### Semantic review\n\n")

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
