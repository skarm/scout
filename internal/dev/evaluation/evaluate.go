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
	"strings"
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
	Path          string   `json:"path"`
	Content       string   `json:"content"`
	ExpectedRules []string `json:"expected_rules"`
}
type Corpus struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Cases         []Case `json:"cases"`
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
	SignalPrecision *float64 `json:"signal_precision"`
	SignalRecall    *float64 `json:"signal_recall"`
}
type Result struct {
	ID           string   `json:"id"`
	Category     string   `json:"category"`
	Label        string   `json:"label"`
	Rules        []string `json:"rules"`
	Decision     string   `json:"decision"`
	Completeness string   `json:"completeness"`
	ScanFailed   bool     `json:"scan_failed"`
	DurationNS   int64    `json:"duration_ns"`
}
type Report struct {
	SchemaVersion int                   `json:"schema_version"`
	EngineVersion string                `json:"engine_version"`
	CorpusKind    string                `json:"corpus_kind"`
	CorpusSHA256  string                `json:"corpus_sha256"`
	Inspection    report.InspectionPlan `json:"inspection"`
	Overall       Metrics               `json:"overall"`
	Categories    map[string]Metrics    `json:"categories"`
	P50NS         int64                 `json:"p50_scan_ns"`
	P95NS         int64                 `json:"p95_scan_ns"`
	Results       []Result              `json:"results"`
	Limitations   []string              `json:"limitations"`
}

func Parse(data []byte) (Corpus, error) {
	if len(data) > MaxCorpusBytes {
		return Corpus{}, errors.New("corpus exceeds byte budget")
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

// Measure requires a caller-selected offline scanner. Cases use reader targets
// and an independent high-severity policy. Source content is never reported.
func Measure(ctx context.Context, scanner *scout.Scanner, data []byte) (Report, error) {
	c, err := Parse(data)
	if err != nil {
		return Report{}, err
	}

	if ctx == nil || scanner == nil {
		return Report{}, errors.New("context and scanner required")
	}

	plan := scanner.InspectionPlan()
	if err := validateOfflinePlan(plan); err != nil {
		return Report{}, err
	}

	gate, err := policy.New(policy.Options{FailAt: report.High})
	if err != nil {
		return Report{}, err
	}

	h := sha256.Sum256(data)
	r := Report{
		SchemaVersion: 1,
		EngineVersion: scout.Version(),
		CorpusKind:    c.Kind,
		CorpusSHA256:  hex.EncodeToString(h[:]),
		Inspection:    plan,
		Categories:    map[string]Metrics{},
		Results:       []Result{},
		Limitations: []string{
			"Case-level signal detection against caller-supplied labels, not proof of safe execution or full malware precision/recall.",
			"Known static gaps count as missed positives when no finding is emitted; incomplete benign cases never count as true negatives. Ambiguous cases are excluded from precision/recall.",
			"An authored regression corpus is not an independent holdout. A declared independent corpus still requires external provenance and label review.",
			"Durations are local single-run wall times, not a controlled benchmark. No native memory, LLM quality, token cost or upstream differential evaluation is measured.",
		},
	}
	durations := make([]int64, 0)

	for _, tc := range c.Cases {
		if err := ctx.Err(); err != nil {
			return r, err
		}

		result := scanCase(ctx, scanner, gate, tc)

		r.Results = append(r.Results, result)
		durations = append(durations, result.DurationNS)

		add(&r.Overall, result)
		m := r.Categories[tc.Category]
		add(&m, result)
		r.Categories[tc.Category] = m
	}

	finish(&r.Overall)

	for key, m := range r.Categories {
		finish(&m)
		r.Categories[key] = m
	}

	slices.Sort(durations)
	r.P50NS = durations[(len(durations)-1)/2]
	r.P95NS = durations[(95*len(durations)+99)/100-1]

	return r, nil
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
}

func scanCase(ctx context.Context, scanner *scout.Scanner, gate *policy.Gate, tc Case) Result {
	start := time.Now()
	run, scanErr := scanner.Scan(ctx, scout.Reader(tc.Path, strings.NewReader(tc.Content)))
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
	}

	seen := map[string]bool{}
	for _, f := range analysis.Findings {
		if !seen[f.RuleID] {
			result.Rules = append(result.Rules, f.RuleID)
			seen[f.RuleID] = true
		}
	}

	sort.Strings(result.Rules)

	return result
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
