// Package engine executes trusted checks over one immutable artifact snapshot.
package engine

import (
	"context"
	"errors"
	"slices"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/semantic"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

// Engine holds immutable trusted analyzers and parser configuration shared by
// independent executions.
type Engine struct {
	signatures signatures.Options
	registry   parse.Registry
	analyzers  []analyzer.Analyzer
	rules      []report.Rule
	workers    int
}
type outcome struct {
	findings    []report.Finding
	check       report.Check
	diagnostics []report.Diagnostic
	fileChecks  []report.FileCheck
}

// RunOptions contains validated per-target configuration and borrowed services
// for one execution. Zero values do not enable services.
type RunOptions struct {
	// Engine records the Scanner build and selected rulepack identity for this
	// analysis.
	Engine report.EngineIdentity
	// Profile records the explicitly selected inspection profile.
	Profile string
	// Limits bounds this target's capture inventory and retained findings.
	Limits report.CaptureLimits
	// Extraction bounds extraction across this target's captured objects.
	Extraction report.ExtractionLimits
	// Harness selects host interpretation without granting execution authority.
	Harness report.HarnessOptions
	// Semantic supplies explicit review permissions and request budgets.
	Semantic review.Options
	// Provider is trusted operator code used only when semantic review is enabled.
	Provider review.Provider
	// Vulnerabilities configures exact-coordinate advisory lookup independently of
	// semantic review.
	Vulnerabilities osv.Options
	// SignatureRuntime borrows the Scanner-owned native runtime without closing
	// it.
	SignatureRuntime *signatures.Runtime
	// Slots shares analyzer admission capacity across targets in the same
	// operation.
	Slots chan struct{}
	// MaxOperations is this target's analysis work budget, divided among
	// preparation tasks and checks.
	MaxOperations uint64
	// MatchLimit bounds retained matches per check.
	MatchLimit int
	// SemanticQuota shares the admitted review budget assigned to this target.
	SemanticQuota *semantic.Quota
	// VulnerabilityQuota shares the admitted advisory request budget assigned to
	// this target.
	VulnerabilityQuota *int
}

// New validates analyzers and worker limits and uses the build's default
// parser registry.
func New(checks []analyzer.Analyzer, workers int) (*Engine, error) {
	return NewWithRegistry(checks, workers, parse.Defaults())
}

// NewWithRegistry copies trusted analyzer configuration, validates unique rule
// identities and binds an explicit parser registry.
func NewWithRegistry(checks []analyzer.Analyzer, workers int, r parse.Registry) (*Engine, error) {
	if workers < 1 || workers > 32 {
		return nil, errors.New("workers must be in 1..32")
	}

	if len(checks) == 0 || len(checks) > 256 {
		return nil, errors.New("need 1..256 analyzers")
	}

	seen := make(map[string]bool, len(checks))

	rules := make([]report.Rule, len(checks))
	for i, a := range checks {
		if a == nil {
			return nil, errors.New("nil analyzer")
		}

		r := knowledge.WithGuidance(a.Rule())
		if slices.Contains([]string{r.ID, r.Version}, "") || r.Severity.Rank() < 0 || seen[r.ID] {
			return nil, errors.New("invalid or duplicate analyzer descriptor")
		}

		seen[r.ID] = true
		rules[i] = r
	}

	return &Engine{
		signatures: signatures.DefaultOptions(),
		registry:   r,
		analyzers:  append([]analyzer.Analyzer(nil), checks...),
		rules:      rules,
		workers:    workers,
	}, nil
}

// WithSignatures returns a new immutable engine configuration.
func (e *Engine) WithSignatures(o signatures.Options) (*Engine, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	o.ExtraRules = append([]byte(nil), o.ExtraRules...)
	n := *e
	n.signatures = o

	return &n, nil
}

// Run executes one snapshot under the caller's explicit service selection.
func (e *Engine) Run(ctx context.Context, s artifact.Snapshot, options RunOptions) (report.Analysis, error) {
	if err := validateRunOptions(ctx, options); err != nil {
		return report.Analysis{}, err
	}

	run := execution{engine: e, ctx: ctx, snapshot: s, options: options}
	if err := run.prepare(); err != nil {
		return report.Analysis{}, err
	}

	run.executeChecks()
	run.buildAnalysis()

	return run.complete()
}

func validateRunOptions(ctx context.Context, options RunOptions) error {
	if err := options.Vulnerabilities.Validate(); err != nil {
		return err
	}

	if err := options.Semantic.Validate(); err != nil {
		return err
	}

	if err := options.Harness.Validate(); err != nil {
		return err
	}

	if ctx == nil {
		return errors.New("nil context")
	}

	if err := options.Limits.Validate(); err != nil {
		return err
	}

	return nil
}
