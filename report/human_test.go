package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skarm/scout/report"
)

func TestHumanReportsExplainDecisionAndConcreteCoverageGaps(t *testing.T) {
	d := documentFixture(t, true)
	a := &d.Run.Targets[0].Analysis
	a.Diagnostics = []report.Diagnostic{{
		Code: "parser_failed", Path: "source.py", Message: "Python syntax could not be parsed.", AffectsScope: true,
	}, {
		Code: "go_semantics_limited", Path: "handler.go", Message: "Cross-file flows are outside the selected analysis.",
	}}
	a.Validation = report.ValidationReport{
		Completeness: report.Partial,
		Tasks: []report.AnalysisTask{
			{ID: "required", Kind: "syntax", Path: "source.py", Required: true},
			{ID: "optional", Kind: "optional_fixture", Required: false},
		},
		Outcomes: []report.TaskOutcome{
			{TaskID: "required", Status: report.OutcomeUnsupported, Reason: "backend_unavailable"},
			{TaskID: "optional", Status: report.OutcomeDisabled},
		},
	}
	d.Run.Problems = []report.Problem{{Code: "inspection_incomplete", Phase: "scan", Message: "A required backend was unavailable."}}
	d.Run = resealHumanRun(t, d.Run)
	d.Evaluation.RunDigest = d.Run.Digest
	d.Evaluation.Reasons = []string{"finding_threshold", "inspection_incomplete", "custom_policy_reason"}

	before, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}

	for _, format := range []report.Format{report.Text, report.Markdown} {
		var out bytes.Buffer
		if err := report.Write(&out, format, d); err != nil {
			t.Fatal(err)
		}

		text := out.String()
		for _, required := range []string{
			"2 retained (2 critical", "1 complete, 1 incomplete", "Operator-approved occurrences: 1",
			"meets the configured blocking threshold", "custom_policy_reason", "Operator approved",
			"A required backend was unavailable.", "Coverage gaps", "source.py", "Python syntax could not be parsed.",
			"Analysis notes", "handler.go", "Cross-file flows", "Required task", "backend_unavailable",
		} {
			if !strings.Contains(text, required) {
				t.Errorf("%s omitted %q", format, required)
			}
		}

		if strings.Contains(text, "optional_fixture") {
			t.Fatal("an intentionally disabled optional task was reported as a required gap")
		}
		if strings.Index(text, "Static findings") > strings.Index(text, "Inspection details") {
			t.Fatal("findings are still buried after inspection metadata")
		}
		if format == report.Markdown && (strings.Count(text, "\n# ") != 0 || strings.Contains(text, "# Scout security review")) {
			t.Fatal("per-target output starts a second top-level document")
		}
	}

	after, err := json.Marshal(d)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("human formatting mutated the caller's document")
	}
}

func TestHumanReportsPrioritizeSevereFindings(t *testing.T) {
	a := sample()
	low := a.Findings[0]
	low.ID, low.Severity, low.Message = "low-finding", report.Low, "Low priority finding"
	a.Findings[0].Message = "Critical priority finding"
	a.Findings = append([]report.Finding{low}, a.Findings...)
	d, err := sampleDocument(a)
	if err != nil {
		t.Fatal(err)
	}

	for _, format := range []report.Format{report.Text, report.Markdown} {
		var out bytes.Buffer
		if err := report.Write(&out, format, d); err != nil {
			t.Fatal(err)
		}

		if strings.Index(out.String(), "Critical priority finding") > strings.Index(out.String(), "Low priority finding") {
			t.Fatal("a low-severity finding preceded a critical finding")
		}
	}

	if d.Run.Targets[0].Analysis.Findings[0].ID != "low-finding" {
		t.Fatal("rendering reordered sealed evidence")
	}
}

func TestHumanReportsTreatCachedRequiredTasksAsFinished(t *testing.T) {
	a := sample()
	a.Validation = report.ValidationReport{
		Completeness: report.Complete,
		Tasks:        []report.AnalysisTask{{ID: "cached-task", Kind: "cached_check", Required: true}},
		Outcomes:     []report.TaskOutcome{{TaskID: "cached-task", Status: report.OutcomeCached}},
	}
	d, err := sampleDocument(a)
	if err != nil {
		t.Fatal(err)
	}

	for _, format := range []report.Format{report.Text, report.Markdown} {
		var out bytes.Buffer
		if err := report.Write(&out, format, d); err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(out.String(), "cached") || strings.Contains(out.String(), "Required task") {
			t.Fatalf("%s reported a cached result as unfinished work", format)
		}
	}
}

func TestComparisonSummaryCountsCandidateFindings(t *testing.T) {
	d := comparisonDocument(t)
	previous := d.Run.Targets[0].Analysis.Findings[0]
	previous.ID = "previous-only"
	d.Run.Targets[0].Analysis.Findings = append(d.Run.Targets[0].Analysis.Findings, previous)
	d.Run = resealHumanRun(t, d.Run)
	d.Evaluation.RunDigest = d.Run.Digest
	for _, format := range []report.Format{report.Text, report.Markdown} {
		var out bytes.Buffer
		if err := report.Write(&out, format, d); err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(out.String(), "Candidate findings: 1 retained") || strings.Contains(out.String(), "Candidate findings: 3") {
			t.Fatal("previous-version findings inflated the candidate summary")
		}
		if strings.Index(out.String(), "Target 1:") > strings.Index(out.String(), "Target 0:") {
			t.Fatal("previous-version details obscure the candidate findings")
		}
	}
	if d.Run.Targets[0].Role != "before" {
		t.Fatal("human target ordering mutated the sealed run")
	}
}

func TestMarkdownKeepsReadableUnicodeAndEscapesControls(t *testing.T) {
	d := documentFixture(t, false)
	d.Run.Targets[0].Label = "навык\u202e<script>\x1b[31m"
	var out bytes.Buffer
	if err := report.Write(&out, report.Markdown, d); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), "`навык\\u202e<script>\\x1b[31m`") {
		t.Fatal("readable Unicode or code-wrapped label was lost")
	}
	if strings.Contains(out.String(), "\u202e") || bytes.Contains(out.Bytes(), []byte{0x1b}) {
		t.Fatal("Markdown contains an unescaped directional or terminal control")
	}
}

func TestMarkdownUsesCodeSpansAndHeadings(t *testing.T) {
	cases := []struct {
		name, path, code string
	}{
		{"unicode", "навык/README.md", "`навык/README.md`"},
		{"backticks", "one`two``three.md", "```one`two``three.md```"},
		{"edge_backticks", "`name`", "`` `name` ``"},
		{"edge_spaces", " name ", "`  name  `"},
		{"spaces_only", "   ", "`   `"},
		{"markup", "[link](https://example.invalid) <img src=x>", "`[link](https://example.invalid) <img src=x>`"},
		{"html_entity", "a&amp;b.md", "`a&amp;b.md`"},
		{"empty_value", "", "`\"\"`"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := documentFixture(t, false)
			d.Run.Targets[0].Analysis.Findings[0].Location.Path = tc.path
			d.Run = resealHumanRun(t, d.Run)
			d.Evaluation.RunDigest = d.Run.Digest

			var out bytes.Buffer
			if err := report.Write(&out, report.Markdown, d); err != nil {
				t.Fatal(err)
			}

			if !strings.Contains(out.String(), "Location: "+tc.code+",") {
				t.Fatalf("path did not remain literal in a code span: %s", out.String())
			}
			if !strings.Contains(out.String(), "\n### Inspection details\n\n") ||
				!strings.Contains(out.String(), "\n### Limits of this result\n\n") {
				t.Fatal("inspection details or limitations lack a Markdown heading")
			}
			for _, tag := range []string{"<code>", "</code>", "<details>", "</details>", "<summary>", "</summary>"} {
				if strings.Contains(out.String(), tag) {
					t.Fatalf("Markdown still uses HTML formatting: %s", tag)
				}
			}
		})
	}
}

func resealHumanRun(t *testing.T, run report.Run) report.Run {
	t.Helper()
	sealed, err := report.SealRun(run)
	if err != nil {
		t.Fatal(err)
	}

	return sealed
}
