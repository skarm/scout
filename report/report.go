package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

type (
	// Explicit types keep SARIF's schema separate from the native JSON contract.
	sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}

	run struct {
		Tool        tool           `json:"tool"`
		ColumnKind  string         `json:"columnKind"`
		Results     []result       `json:"results"`
		Invocations []invocation   `json:"invocations"`
		Properties  map[string]any `json:"properties"`
	}

	tool struct {
		Driver driver `json:"driver"`
	}

	driver struct {
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		Rules   []rule `json:"rules"`
	}

	rule struct {
		ID               string         `json:"id"`
		ShortDescription message        `json:"shortDescription"`
		FullDescription  message        `json:"fullDescription"`
		Help             *message       `json:"help,omitempty"`
		HelpURI          string         `json:"helpUri,omitempty"`
		Properties       map[string]any `json:"properties"`
	}

	message struct {
		Text string `json:"text"`
	}

	suppression struct {
		Kind   string `json:"kind"`
		Status string `json:"status"`
	}

	result struct {
		Suppressions        []suppression     `json:"suppressions,omitempty"`
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             message           `json:"message"`
		Locations           []location        `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          map[string]any    `json:"properties"`
		CodeFlows           []codeFlow        `json:"codeFlows,omitempty"`
	}

	codeFlow struct {
		ThreadFlows []threadFlow `json:"threadFlows"`
	}

	threadFlow struct {
		Locations []threadLocation `json:"locations"`
	}

	threadLocation struct {
		Location   location       `json:"location"`
		Kinds      []string       `json:"kinds"`
		Properties map[string]any `json:"properties,omitempty"`
	}

	location struct {
		PhysicalLocation physical `json:"physicalLocation"`
	}

	physical struct {
		ArtifactLocation artifactLocation `json:"artifactLocation"`
		Region           *region          `json:"region,omitempty"`
	}

	artifactLocation struct {
		URI string `json:"uri"`
	}

	region struct {
		StartLine   int  `json:"startLine,omitempty"`
		StartColumn int  `json:"startColumn,omitempty"`
		EndLine     int  `json:"endLine,omitempty"`
		EndColumn   int  `json:"endColumn,omitempty"`
		ByteOffset  *int `json:"byteOffset,omitempty"`
		ByteLength  *int `json:"byteLength,omitempty"`
	}

	invocation struct {
		ExecutionSuccessful        bool           `json:"executionSuccessful"`
		ToolExecutionNotifications []notification `json:"toolExecutionNotifications"`
	}

	notification struct {
		Level   string  `json:"level"`
		Message message `json:"message"`
	}
)

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(v)
}

func terminal(w io.Writer, r Analysis, evaluation Evaluation) error {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "Completeness: %s\nFiles: %d captured; derived objects: %d; analyzed objects: %d (%d text)\nFindings: %d (%s)\n",
		r.Coverage.Completeness, r.Coverage.CapturedFiles, len(r.Extraction.Objects), r.Coverage.AnalyzedObjects, r.Coverage.TextFiles, len(r.Findings), severitySummary(r.Findings))
	writeTerminalFindings(&b, r, evaluation)
	writeTerminalSemantic(&b, r)
	writeVulnerabilityExtras(&b, r, strconv.QuoteToASCII)
	writeHumanDiagnostics(&b, r.Diagnostics, false)
	writeValidationSummary(&b, r.Validation, false)

	_, _ = fmt.Fprintf(&b, "\nInspection details\nscout %s\nProfile: %s\n", r.EngineVersion, r.Profile)
	if r.Artifact.SnapshotSHA256 != "" {
		_, _ = fmt.Fprintf(&b, "Snapshot: %s\n", r.Artifact.SnapshotSHA256)
	}

	if r.Inspection.Name != "" {
		_, _ = fmt.Fprintf(&b, "Inspection: %s\n", strconv.QuoteToASCII(r.Inspection.Name))

		writeInspectionChecks(&b, r.Inspection.Checks, false)
	}

	_, _ = fmt.Fprintf(&b, "Harness: %s\nPlugin interpretations: %d; components: %d\n", r.Components.RequestedHost, len(r.Components.Plugins), len(r.Components.Components))

	_, _ = fmt.Fprintf(&b, "Dependency declarations: %d (not a resolved install graph; see separate vulnerability lookup status)\n", len(r.Dependencies.Declarations))

	if r.Source != nil {
		_, _ = fmt.Fprintf(&b, "Remote input: %s; bytes SHA256=%s; expected checksum verified=%t\n", r.Source.Status, r.Source.BytesSHA256, r.Source.ExpectedChecksumVerified)
	}

	_, _ = fmt.Fprintf(&b, "Validation instructions: %s; SHA256=%s\n", r.Knowledge.Version, r.Knowledge.SHA256)
	writeExtras(&b, r, evaluation, false)

	b.WriteString("\nLimits of this result:\n")

	for _, s := range r.Limitations {
		_, _ = fmt.Fprintf(&b, "  %s\n", s)
	}

	_, err := io.WriteString(w, b.String())

	return err
}

func toSARIF(r Analysis, evaluation Evaluation) sarif {
	rules := sarifRules(r)
	kinds := artifactKinds(r)
	results := sarifFindings(r, evaluation, kinds)

	if len(r.Semantic.Proposals) > 0 {
		rules = append(rules, rule{
			ID:               "SEMANTIC-PROPOSAL",
			ShortDescription: message{Text: "Evidence-linked model proposal; human review required"},
			FullDescription:  message{Text: "Model classification with validated excerpt references; not independently verified static evidence or proof of intent."},
			Properties: map[string]any{
				"version": r.Semantic.PromptVersion,
				"method":  "semantic_proposal",
			},
		})
	}

	results = append(results, sarifProposals(r.Semantic)...)

	notes := sarifDiagnostics(r.Diagnostics)

	return sarif{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:    "scout",
				Version: r.EngineVersion,
				Rules:   rules,
			}},
			ColumnKind: "unicodeCodePoints",
			Results:    results,
			Invocations: []invocation{{
				ExecutionSuccessful:        r.Coverage.Completeness == Complete,
				ToolExecutionNotifications: notes,
			}},
			Properties: map[string]any{
				"inspection":      r.Inspection,
				"knowledge":       r.Knowledge,
				"source":          r.Source,
				"dependencies":    r.Dependencies,
				"metadata":        r.Metadata,
				"vulnerabilities": r.Vulnerabilities,
				"signatures":      r.Signatures,
				"schemaVersion":   r.SchemaVersion,
				"profile":         r.Profile,
				"rulepackDigest":  r.RulepackDigest,
				"artifact":        r.Artifact,
				"coverage":        r.Coverage,
				"evaluation":      evaluation,
				"limits":          r.Limits,
				"analysisLimits":  r.AnalysisLimits,
				"extraction":      r.Extraction,
				"components":      r.Components,
				"validation":      r.Validation,
				"semantic":        r.Semantic,
				"limitations":     r.Limitations,
			},
		}},
	}
}

func writeInspectionChecks(b *strings.Builder, checks []InspectionCheck, markdown bool) {
	for _, check := range checks {
		state := "not selected"
		if check.Selected {
			state = "selected"
			if !check.Available {
				state = "selected, unavailable"
			}
		}

		if markdown {
			_, _ = fmt.Fprintf(b, "- %s: %s.\n", mdCode(check.ID), state)
		} else {
			_, _ = fmt.Fprintf(b, "  %s: %s\n", strconv.QuoteToASCII(check.ID), state)
		}
	}
}

func sarifCodeFlows(trace []TraceStep, kinds map[string]string) []codeFlow {
	if len(trace) == 0 {
		return nil
	}

	steps := make([]threadLocation, 0, len(trace))
	for _, step := range trace {
		l := step.Location

		loc := physical{ArtifactLocation: artifactLocation{URI: sourceURI(l.Path)}}
		if kinds[l.Path] == "text" && l.ByteEnd > l.ByteStart {
			loc.Region = &region{
				StartLine:   l.StartLine,
				StartColumn: l.StartColumn,
				EndLine:     l.EndLine,
				EndColumn:   l.EndColumn,
			}
		}

		steps = append(steps, threadLocation{
			Location:   location{PhysicalLocation: loc},
			Kinds:      []string{step.Role},
			Properties: map[string]any{"evidence": step.Evidence},
		})
	}

	return []codeFlow{{ThreadFlows: []threadFlow{{Locations: steps}}}}
}

// Derived URIs name virtual objects; they must not be rewritten as local paths.
func sourceURI(path string) string {
	if strings.HasPrefix(path, "scout-object://") {
		return path
	}

	return (&url.URL{Path: path}).String()
}

func writeTerminalSemantic(b *strings.Builder, r Analysis) {
	if !r.Semantic.Enabled {
		b.WriteString("Semantic review: disabled (no source upload)\n")
	} else {
		_, _ = fmt.Fprintf(b, "Semantic review: %s; planned=%d validated=%d; model proposals=%d; assessments=%d\n", r.Semantic.Completeness, len(r.Semantic.Tasks), r.Semantic.CompletedRequests, len(r.Semantic.Proposals), len(r.Semantic.Assessments))
		_, _ = fmt.Fprintf(b, "Proposal verification: %d assessments; a second model pass is not independent proof\n", len(r.Semantic.ProposalAssessments))

		for _, p := range r.Semantic.Proposals {
			_, _ = fmt.Fprintf(b, "\n[MODEL PROPOSAL — review required] %s; suggested severity=%s\n", p.Reason, p.SuggestedSeverity)

			if p.KnowledgeTopicID != "" {
				_, _ = fmt.Fprintf(b, "  Knowledge topic: %s\n", p.KnowledgeTopicID)
				writeRuleGuidance(b, p.Guidance, nil, false)
			}

			for _, e := range p.Evidence {
				_, _ = fmt.Fprintf(b, "  Evidence: %s bytes[%d:%d]\n", strconv.QuoteToASCII(e.Path), e.ByteStart, e.ByteEnd)
			}
		}

		for _, a := range r.Semantic.ProposalAssessments {
			_, _ = fmt.Fprintf(b, "  Model assessment of proposal %s: %s (%s); original hypothesis retained\n", a.ProposalID, a.Verdict, a.Reason)
		}

		for _, a := range r.Semantic.Assessments {
			_, _ = fmt.Fprintf(b, "  Model assessment of %s: %s (%s); static finding retained\n", a.FindingID, a.Verdict, a.Reason)
		}
	}
}

func writeTerminalFindings(b *strings.Builder, r Analysis, evaluation Evaluation) {
	b.WriteString("\nStatic findings\n")

	if len(r.Findings) == 0 {
		b.WriteString("No retained static findings. Check completeness and coverage before treating this as a clean result.\n\n")
	}

	guides := ruleGuides(r.Rules)
	approved := approvedFindings(evaluation)

	provenance := make(map[string]DerivedObject, len(r.Extraction.Objects))
	for _, object := range r.Extraction.Objects {
		provenance[object.File.Path] = object
	}

	for _, f := range sortedFindings(r.Findings) {
		if object, ok := provenance[f.Location.Path]; ok {
			_, _ = fmt.Fprintf(b, "\nDerived object %s via %s from %s (offsets below refer to decoded bytes)\n", strconv.QuoteToASCII(object.MemberName), object.ExtractorID, strconv.QuoteToASCII(object.ParentPath))
		}

		if f.Location.Coordinates == "bytes" {
			_, _ = fmt.Fprintf(b, "\n[%s] %s %s bytes[%d:%d] (%s)\n  %s\n", f.Severity, f.RuleID, strconv.QuoteToASCII(f.Location.Path), f.Location.ByteStart, f.Location.ByteEnd, f.Location.Context, f.Message)
		} else {
			_, _ = fmt.Fprintf(b, "\n[%s] %s %s:%d:%d (%s)\n  %s\n", f.Severity, f.RuleID, strconv.QuoteToASCII(f.Location.Path), f.Location.StartLine, f.Location.StartColumn, f.Location.Context, f.Message)
		}

		writeRuleGuidance(b, guides[f.RuleID], f.ContextSignals, false)

		if approved[f.ID] {
			b.WriteString("  Operator approved: this occurrence remains visible as evidence.\n")
		}

		for _, c := range f.Contexts {
			_, _ = fmt.Fprintf(b, "  Component: %s host=%s relation=%s activation=%s\n", c.ComponentID, c.Host, c.Relation, c.Activation)
		}

		for _, step := range f.Trace {
			_, _ = fmt.Fprintf(b, "  %s: %s:%d:%d\n", step.Role, strconv.QuoteToASCII(step.Location.Path), step.Location.StartLine, step.Location.StartColumn)
		}
	}
}

func sarifRules(r Analysis) []rule {
	rules := make([]rule, 0, len(r.Rules))
	for _, x := range r.Rules {
		item := rule{
			ID:               x.ID,
			ShortDescription: message{Text: x.Title},
			FullDescription:  message{Text: x.Description},
			Properties: map[string]any{
				"severity":   x.Severity,
				"version":    x.Version,
				"method":     x.Method,
				"limitation": x.Limitation,
			},
		}
		if x.Guidance != nil {
			item.Help = &message{Text: x.Guidance.Explanation + "\nRemediation: " + x.Guidance.Remediation + "\nReview: " + strings.Join(x.Guidance.ReviewChecks, "; ") + "\nConsider: " + strings.Join(x.Guidance.BenignConsiderations, "; ")}

			item.Properties["guidance"] = x.Guidance
			if len(x.Guidance.Sources) > 0 {
				item.HelpURI = x.Guidance.Sources[0].URL
			}
		}

		rules = append(rules, item)
	}

	return rules
}

func artifactKinds(r Analysis) map[string]string {
	kinds := make(map[string]string, len(r.Artifact.Files))
	for _, f := range r.Artifact.Files {
		kinds[f.Path] = f.Kind
	}

	for _, object := range r.Extraction.Objects {
		kinds[object.File.Path] = object.File.Kind
	}

	return kinds
}

func sarifFindings(r Analysis, evaluation Evaluation, kinds map[string]string) []result {
	suppressed := map[string]bool{}
	for _, a := range evaluation.Suppressed {
		suppressed[a.FindingID] = true
	}

	results := make([]result, 0, len(r.Findings))
	for _, f := range r.Findings {
		level := "warning"
		if f.Severity.Rank() >= High.Rank() {
			level = "error"
		} else if f.Severity == Info {
			level = "note"
		}

		p := physical{ArtifactLocation: artifactLocation{URI: sourceURI(f.Location.Path)}}
		if kinds[f.Location.Path] == "text" && f.Location.ByteEnd > f.Location.ByteStart {
			p.Region = &region{
				StartLine:   f.Location.StartLine,
				StartColumn: f.Location.StartColumn,
				EndLine:     f.Location.EndLine,
				EndColumn:   f.Location.EndColumn,
			}
		} else if f.Location.ByteEnd > f.Location.ByteStart {
			start, length := f.Location.ByteStart, f.Location.ByteEnd-f.Location.ByteStart
			p.Region = &region{ByteOffset: &start, ByteLength: &length}
		}

		item := result{
			RuleID:              f.RuleID,
			Level:               level,
			Message:             message{Text: f.Message},
			Locations:           []location{{PhysicalLocation: p}},
			PartialFingerprints: map[string]string{"occurrence/v1": f.ID},
			Properties: map[string]any{
				"severity":          f.Severity,
				"category":          f.Category,
				"method":            f.Method,
				"ruleVersion":       f.RuleVersion,
				"evidence":          f.Evidence,
				"sourceLocation":    f.Location,
				"componentContexts": f.Contexts,
			},
		}
		if suppressed[f.ID] {
			item.Suppressions = []suppression{{Kind: "external", Status: "accepted"}}
		}

		item.Properties["contextSignals"] = f.ContextSignals
		item.Properties["advisoryIds"] = f.AdvisoryIDs
		item.Properties["relatedEvidence"] = f.RelatedEvidence
		item.Properties["signatureNames"] = f.SignatureNames
		item.CodeFlows = sarifCodeFlows(f.Trace, kinds)

		results = append(results, item)
	}

	return results
}

func sarifProposals(semantic SemanticReport) []result {
	results := make([]result, 0, len(semantic.Proposals))
	for _, p := range semantic.Proposals {
		locations := make([]location, 0, len(p.Evidence))
		for _, e := range p.Evidence {
			start, length := e.ByteStart, e.ByteEnd-e.ByteStart
			locations = append(locations, location{PhysicalLocation: physical{
				ArtifactLocation: artifactLocation{URI: sourceURI(e.Path)},
				Region: &region{
					ByteOffset: &start,
					ByteLength: &length,
				},
			}})
		}

		results = append(results, result{
			RuleID:              "SEMANTIC-PROPOSAL",
			Level:               "warning",
			Message:             message{Text: "Model proposal: " + p.Reason + ". Human review required; not a verified static finding."},
			Locations:           locations,
			PartialFingerprints: map[string]string{"semanticProposal/v1": p.ID},
			Properties: map[string]any{
				"method":            "semantic_proposal",
				"suggestedSeverity": p.SuggestedSeverity,
				"evidence":          p.Evidence,
				"taskID":            p.TaskID,
				"upstreamRuleID":    p.UpstreamRuleID,
				"knowledgeTopicID":  p.KnowledgeTopicID,
				"guidance":          p.Guidance,
			},
		})
	}

	return results
}

func sarifDiagnostics(diagnostics []Diagnostic) []notification {
	notes := make([]notification, 0, len(diagnostics))
	for _, d := range diagnostics {
		notes = append(notes, notification{
			Level:   "warning",
			Message: message{Text: d.Code + " " + strconv.QuoteToASCII(d.Path) + ": " + d.Message},
		})
	}

	return notes
}
