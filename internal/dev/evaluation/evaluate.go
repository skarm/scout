// Package evaluation measures labelled, read-only scan corpora. It never
// executes cases or treats known static blind spots as successful negatives.
package evaluation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"sort"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

const MaxCorpusBytes = 8 << 20

type Case struct {
	ID            string   `json:"id"`
	Category      string   `json:"category"`
	Label         string   `json:"label"`
	Path          string   `json:"path,omitempty"`
	Content       string   `json:"content,omitempty"`
	ExpectedRules []string `json:"expected_rules"`
	SourceID      string   `json:"source_id,omitempty"`
	Split         string   `json:"split,omitempty"`
	Files         []File   `json:"files,omitempty"`
}
type File struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	Executable bool   `json:"executable,omitempty"`
}
type Source struct {
	ID          string `json:"id"`
	Origin      string `json:"origin"`
	Revision    string `json:"revision"`
	License     string `json:"license"`
	LabelReview string `json:"label_review"`
}
type Corpus struct {
	SchemaVersion int      `json:"schema_version"`
	Kind          string   `json:"kind"`
	Cases         []Case   `json:"cases"`
	Sources       []Source `json:"sources,omitempty"`
}
type counts struct {
	DetectedPositive       int `json:"detected_positive"`
	MissedPositive         int `json:"missed_positive"`
	FalsePositiveBenign    int `json:"false_positive_benign"`
	CompleteNegativeBenign int `json:"complete_negative_benign"`
	UnresolvedBenign       int `json:"unresolved_benign"`
	Ambiguous              int `json:"ambiguous_excluded"`
	Incomplete             int `json:"incomplete"`
}
type Metrics struct {
	counts
	SignalPrecision   *float64 `json:"signal_precision"`
	SignalRecall      *float64 `json:"signal_recall"`
	FalsePositiveRate *float64 `json:"false_positive_rate"`
}
type Result struct {
	ID           string                `json:"id"`
	Category     string                `json:"category"`
	Label        string                `json:"label"`
	Rules        []string              `json:"rules"`
	Decision     string                `json:"decision"`
	Completeness string                `json:"completeness"`
	ScanFailed   bool                  `json:"scan_failed"`
	DurationNS   int64                 `json:"duration_ns"`
	SourceID     string                `json:"source_id,omitempty"`
	Split        string                `json:"split,omitempty"`
	Review       *ReviewResult         `json:"review,omitempty"`
	Engine       report.EngineIdentity `json:"engine"`
}
type Report struct {
	SchemaVersion int                   `json:"schema_version"`
	EngineVersion string                `json:"engine_version"`
	CorpusKind    string                `json:"corpus_kind"`
	CorpusSHA256  string                `json:"corpus_sha256"`
	Inspection    report.InspectionPlan `json:"inspection"`
	Overall       Metrics               `json:"overall"`
	Categories    map[string]Metrics    `json:"categories"`
	Splits        map[string]Metrics    `json:"splits"`
	SelectedSplit string                `json:"selected_split"`
	SelectedCases int                   `json:"selected_cases"`
	Completed     bool                  `json:"completed"`
	LLM           *LLMReport            `json:"llm,omitempty"`
	P50NS         int64                 `json:"p50_scan_ns"`
	P95NS         int64                 `json:"p95_scan_ns"`
	Results       []Result              `json:"results"`
	Limitations   []string              `json:"limitations"`
}

func Parse(data []byte) (Corpus, error) {
	if len(data) > MaxCorpusBytes {
		return Corpus{}, errors.New("corpus exceeds byte budget")
	}

	if err := validateJSON(data); err != nil {
		return Corpus{}, err
	}

	var c Corpus

	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()

	if err := d.Decode(&c); err != nil {
		return c, err
	}

	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("trailing corpus data")
	}

	return c, c.validate()
}

// Measure requires a caller-selected offline scanner and an independent
// high-severity policy. Source content is never reported.
func Measure(ctx context.Context, scanner *scout.Scanner, data []byte) (Report, error) {
	return MeasureWithOptions(ctx, scanner, data, Options{})
}

// MeasureWithOptions keeps the offline baseline separate from an optional,
// explicitly configured reviewer. Split validation always covers the full corpus.
func MeasureWithOptions(ctx context.Context, scanner *scout.Scanner, data []byte, options Options) (r Report, err error) {
	if ctx == nil || scanner == nil {
		return Report{}, errors.New("context and scanner required")
	}

	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	c, err := Parse(data)
	if err != nil {
		return Report{}, err
	}

	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	plan := scanner.InspectionPlan()
	if err := validateOfflinePlan(plan); err != nil {
		return Report{}, err
	}

	if err := options.validate(c); err != nil {
		return Report{}, err
	}

	gate, err := policy.New(policy.Options{FailAt: report.High})
	if err != nil {
		return Report{}, err
	}

	h := sha256.Sum256(data)

	r = Report{
		SchemaVersion: 2,
		EngineVersion: scout.Version(),
		CorpusKind:    c.Kind,
		CorpusSHA256:  hex.EncodeToString(h[:]),
		Inspection:    plan,
		Categories:    map[string]Metrics{},
		Splits:        map[string]Metrics{},
		SelectedSplit: options.Split,
		Results:       []Result{},
		Limitations: []string{
			"Case-level signal detection against caller-supplied labels, not proof of safe execution or full malware precision/recall.",
			"Known static gaps count as missed positives when no finding is emitted; incomplete benign cases never count as true negatives. Ambiguous cases are excluded from precision/recall.",
			"An authored regression corpus is not an independent holdout. A declared independent corpus still requires external provenance and label review.",
			"Durations are local single-run wall times, not a controlled benchmark. No native memory or upstream differential evaluation is measured.",
			"Split isolation checks declared source groups and exact nonempty file bytes, not source authenticity, semantic duplicates, external training contamination or label quality.",
		},
	}
	if options.Reviewer != nil {
		r.LLM = newLLMReport(options)
		r.Limitations = append(r.Limitations, "LLM metrics count validated model proposals, not static findings or proof of malicious intent. Usage is provider-reported; cost uses operator-supplied rates and is not a billing record.")
	}

	durations := make([]int64, 0)
	defer func() { r.finish(durations) }()

	for _, tc := range c.Cases {
		if options.Split == "" || tc.Split == options.Split {
			r.SelectedCases++
		}
	}

	for _, tc := range c.Cases {
		if options.Split != "" && tc.Split != options.Split {
			continue
		}

		if err := ctx.Err(); err != nil {
			return r, err
		}

		result, err := measureCase(ctx, scanner, gate, tc, options.Reviewer)
		if err != nil {
			return r, err
		}

		r.Results = append(r.Results, result)
		durations = append(durations, result.DurationNS)

		add(&r.Overall, result)
		m := r.Categories[tc.Category]
		add(&m, result)
		r.Categories[tc.Category] = m
		m = r.Splits[tc.Split]
		add(&m, result)

		r.Splits[tc.Split] = m
		if r.LLM != nil {
			r.LLM.add(result)
		}
	}

	err = ctx.Err()
	r.Completed = err == nil

	return r, err
}

func (r *Report) finish(durations []int64) {
	finish(&r.Overall)
	finishGroups(r.Categories)
	finishGroups(r.Splits)

	if r.LLM != nil {
		r.LLM.finish()
	}

	if len(durations) > 0 {
		slices.Sort(durations)
		r.P50NS = durations[(len(durations)-1)/2]
		r.P95NS = durations[(95*len(durations)+99)/100-1]
	}
}

func add(m *Metrics, r Result) {
	incomplete := r.ScanFailed || r.Completeness != string(report.Complete)
	if incomplete {
		m.Incomplete++
	}

	signal := len(r.Rules) > 0
	switch r.Label {
	case "signal", "known_static_gap":
		if signal {
			m.DetectedPositive++
		} else {
			m.MissedPositive++
		}
	case "benign":
		if signal {
			m.FalsePositiveBenign++
		} else if incomplete {
			m.UnresolvedBenign++
		} else {
			m.CompleteNegativeBenign++
		}
	case "ambiguous":
		m.Ambiguous++
	}
}

func finish(m *Metrics) {
	if n := m.DetectedPositive + m.FalsePositiveBenign; n > 0 {
		v := float64(m.DetectedPositive) / float64(n)
		m.SignalPrecision = &v
	}

	if n := m.DetectedPositive + m.MissedPositive; n > 0 {
		v := float64(m.DetectedPositive) / float64(n)
		m.SignalRecall = &v
	}

	if n := m.FalsePositiveBenign + m.CompleteNegativeBenign; n > 0 && m.UnresolvedBenign == 0 {
		v := float64(m.FalsePositiveBenign) / float64(n)
		m.FalsePositiveRate = &v
	}
}

func scanCase(ctx context.Context, scanner *scout.Scanner, gate *policy.Gate, tc Case, target scout.Target) (Result, report.SemanticReport) {
	start := time.Now()
	run, scanErr := scanner.Scan(ctx, target)
	elapsed := time.Since(start).Nanoseconds()
	evaluation := gate.Evaluate(run, time.Now())

	var analysis report.Analysis
	if len(run.Targets) == 1 {
		analysis = run.Targets[0].Analysis
	}

	result := Result{
		ID:           tc.ID,
		Category:     tc.Category,
		Label:        tc.Label,
		Decision:     string(evaluation.Decision),
		Completeness: string(analysis.Coverage.Completeness),
		ScanFailed:   scanErr != nil || run.State != report.RunComplete || len(run.Targets) != 1,
		DurationNS:   elapsed,
		Rules:        []string{},
		SourceID:     tc.SourceID,
		Split:        tc.Split,
		Engine:       run.Engine,
	}

	seen := map[string]bool{}
	for _, f := range analysis.Findings {
		if !seen[f.RuleID] {
			result.Rules = append(result.Rules, f.RuleID)
			seen[f.RuleID] = true
		}
	}

	sort.Strings(result.Rules)

	return result, analysis.Semantic
}

func finishGroups(groups map[string]Metrics) {
	for key, m := range groups {
		finish(&m)
		groups[key] = m
	}
}

func validateOfflinePlan(plan report.InspectionPlan) error {
	if plan.Egress.Enabled() {
		return errors.New("corpus evaluation requires offline configuration")
	}

	if plan.HasServiceChecks() {
		return errors.New("evaluate static checks separately from external services")
	}

	return nil
}
