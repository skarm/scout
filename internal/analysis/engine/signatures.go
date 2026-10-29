package engine

import (
	"context"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/knowledge"

	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Read-only signature category metadata shared by all scan executions.
var signatureCategoryRule = map[string]int{"malware": 0, "webshell": 1, "cryptominer": 2, "hack_tool": 3, "exploit": 3}

func SignatureRules() []report.Rule {
	out := make([]report.Rule, 0, 5)

	for _, x := range []struct{ id, title string }{{id: ruleYR1, title: "YARA-X malware-category signature"}, {
		id:    ruleYR2,
		title: "YARA-X webshell-category signature",
	}, {
		id:    ruleYR3,
		title: "YARA-X cryptominer-category signature",
	}, {
		id:    ruleYR4,
		title: "YARA-X hack-tool or exploit-category signature",
	}, {
		id:    ruleYR5,
		title: "YARA-X uncategorized operator signature",
	}} {
		severity := report.High
		if x.id == ruleYR5 {
			severity = report.Medium
		}

		out = append(out, report.Rule{
			ID:          x.id,
			Version:     "7",
			Title:       x.title,
			Description: x.title,
			Severity:    severity,
			Category:    "signature-match",
			Method:      "embedded-yara-x",
			Limitation:  "Embedded YARA-X engine; native availability is explicit; 27 adapted SkillSpector rules and 8 adapted Cisco compound rules plus optional trusted operator rules. A match is not a verdict about intent; broad tool references/examples can match. Full external corpora are not bundled. Descriptor severity is a maximum; selected builtins use Scout-owned evidence tiers, never source-controlled severity metadata. Python alias/socket refinements use bounded literal spellings, not general scope or object resolution; WASM mining API combinations are Medium capability signals.",
		})
	}

	for i := range out {
		out[i] = knowledge.WithGuidance(out[i])
	}

	return out
}

func applySignatures(ctx context.Context, r *report.Analysis, docs []document.File, o signatures.Options, runtime *signatures.Runtime, collector *findingCollector, fileIndex map[string]int) {
	inputs := make([]signatures.Input, 0, len(docs))
	byPath := map[string]document.File{}

	for _, d := range docs {
		m := d.Artifact().Metadata()
		inputs = append(inputs, signatures.Input{Path: m.Path, SHA256: m.SHA256, Data: d.Artifact().Content()})
		byPath[m.Path] = d
	}

	var (
		out signatures.Report
		err error
	)
	if runtime == nil {
		out, err = signatures.Check(ctx, inputs, o)
	} else {
		out, err = runtime.Check(ctx, inputs)
	}

	r.Signatures = out

	if !o.Enabled {
		return
	}

	rules := SignatureRules()
	r.Rules = append(r.Rules, rules...)

	partial := err != nil || out.Completeness != string(report.Complete)
	for _, step := range out.Outcomes {
		if !collectSignatureMatches(step, byPath, rules, r.Signatures.RulesSHA256, collector) {
			partial = true
		}

		signatureFileCoverage(r, step, fileIndex)
	}

	status := report.OutcomeCompleted
	if partial {
		status = report.OutcomePartial

		r.Signatures.Completeness = string(report.Partial)
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
			Code:         "yara_incomplete",
			Message:      "Requested YARA-X inspection is unavailable, limited, failed or has invalid evidence; see its fixed input plan and outcomes.",
			AffectsScope: true,
		})
	}

	r.Coverage.Checks = append(r.Coverage.Checks, report.Check{
		AnalyzerID: "yara-x",
		Version:    "2",
		Status:     status,
		FilesTotal: len(inputs),
		Detail:     "Plan and per-object outcomes are in signatures; target contents were not executed.",
	})
}

func signatureFileCoverage(r *report.Analysis, step signatures.Outcome, fileIndex map[string]int) {
	if i, ok := fileIndex[step.Path]; ok {
		fc := &r.Coverage.Files[i]

		fc.Checks = append(fc.Checks, report.FileCheck{AnalyzerID: "yara-x", Status: step.Status})
		if step.Status != report.OutcomeCompleted || step.Truncated {
			fc.Gaps = append(fc.Gaps, "yara:"+step.Status)
		}

		return
	}
}

func collectSignatureMatches(step signatures.Outcome, byPath map[string]document.File, rules []report.Rule, rulesSHA string, collector *findingCollector) bool {
	complete := true

	for _, m := range step.Matches {
		i, ok := signatureCategoryRule[m.Category]
		if !ok {
			i = 4
		}

		doc, ok := byPath[step.Path]
		if !ok || len(m.Spans) == 0 {
			complete = false
			continue
		}
		// A complete YARA-X condition is supported by all reported string spans, not
		// by pretending that one substring independently establishes that condition.
		match, valid := signatureMatch(doc, step, m)
		match.Severity = m.Severity

		if !valid {
			complete = false
		}

		f, e := makeFinding(rules[i], doc, match)
		if e != nil {
			complete = false
			continue
		}

		f.ID = artifact.Hash([]byte(f.ID + "\x00" + rulesSHA + "\x00" + m.Rule))
		f.SignatureNames = []string{m.Rule}

		if description := signatures.Description(m); description != "" {
			f.Message = description
		}

		f.RelatedEvidence = append([]report.SourceRef(nil), match.Related...)
		collector.add(f)
	}

	return complete
}

// All reported string spans support one native condition. Invalid related spans
// are rejected while retaining the valid primary finding and partial status.
func signatureMatch(doc document.File, step signatures.Outcome, m signatures.Match) (check.Match, bool) {
	complete := true

	match := check.Match{Start: m.Spans[0].Start, End: m.Spans[0].End}
	for _, s := range m.Spans[1:] {
		b := doc.Artifact().Content()
		if s.Start < 0 || s.End > len(b) || s.Start >= s.End {
			complete = false
			continue
		}

		match.Related = append(match.Related, report.SourceRef{
			Path:       step.Path,
			SHA256:     step.SHA256,
			ByteStart:  s.Start,
			ByteEnd:    s.End,
			SpanSHA256: artifact.Hash([]byte(b[s.Start:s.End])),
		})
	}

	return match, complete
}
