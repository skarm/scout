package analyzer

import (
	"context"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/python"
	"github.com/skarm/scout/internal/analysis/languages/shell"
)

const (
	shellTransmission = shell.PatternTransmission
	shellRemoval      = shell.PatternRemoval
	shellPersistence  = shell.PatternPersistence
	shellDownload     = shell.PatternDownload
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var patternPolicies = map[string]patternPolicy{
	ruleE1: {
		python:  ruleE1,
		shell:   shellTransmission,
		adapter: func(a familyAnalyzer) Analyzer { return transmissionCheck{familyAnalyzer: a} },
	},
	ruleTM1: {
		python:  ruleTM1,
		shell:   shellRemoval,
		adapter: func(a familyAnalyzer) Analyzer { return removalCheck{familyAnalyzer: a} },
	},
	ruleOH1: {
		python:  ruleOH1,
		filter:  regexpLiteralExec,
		adapter: func(a familyAnalyzer) Analyzer { return outputExecutionCheck{familyAnalyzer: a} },
	},
	ruleSC2: {shell: shellDownload, adapter: func(a familyAnalyzer) Analyzer { return downloadCheck{familyAnalyzer: a} }},
	ruleRA2: {
		shell:   shellPersistence,
		adapter: func(a familyAnalyzer) Analyzer { return persistenceCheck{familyAnalyzer: a} },
	},
	ruleEA5: {adapter: func(a familyAnalyzer) Analyzer { return modelSelectionCheck{familyAnalyzer: a} }},
	ruleP9:  {adapter: func(a familyAnalyzer) Analyzer { return paddingCheck{familyAnalyzer: a} }},
	ruleP2: {
		candidates: 65536,
		supplement: hiddenCarrierSignals,
		adapter:    func(a familyAnalyzer) Analyzer { return hiddenCarrierCheck{familyAnalyzer: a} },
	},
	ruleP5: {
		supplement: harmfulSubstanceMatches,
		adapter:    func(a familyAnalyzer) Analyzer { return harmfulInstructionCheck{familyAnalyzer: a} },
	},
	ruleMP2: {
		supplement: contextRepetitionSignals,
		adapter:    func(a familyAnalyzer) Analyzer { return repeatedContextCheck{familyAnalyzer: a} },
	},
	ruleMP3: {
		supplement: memoryAdoptionSignals,
		adapter:    func(a familyAnalyzer) Analyzer { return memoryAdoptionCheck{familyAnalyzer: a} },
	},
	ruleP6: {filter: promptPrecision}, rulePE3: {filter: credentialPrecision}, ruleSC7: {candidates: 65536},
}

// Pattern families describe literal observations. Rules requiring program facts
// have concrete adapters; the shared matcher does not dispatch on rule IDs.
type patternStages struct {
	before func(context.Context, document.File, int, *Result) error
	unit   func(document.Unit, *Result, int)
}

type (
	transmissionCheck       struct{ familyAnalyzer }
	removalCheck            struct{ familyAnalyzer }
	outputExecutionCheck    struct{ familyAnalyzer }
	downloadCheck           struct{ familyAnalyzer }
	persistenceCheck        struct{ familyAnalyzer }
	modelSelectionCheck     struct{ familyAnalyzer }
	paddingCheck            struct{ familyAnalyzer }
	hiddenCarrierCheck      struct{ familyAnalyzer }
	harmfulInstructionCheck struct{ familyAnalyzer }
	repeatedContextCheck    struct{ familyAnalyzer }
	memoryAdoptionCheck     struct{ familyAnalyzer }
)

// The only ID-to-implementation decision is catalog construction. Runtime
// matching, decoded values and fact projection contain no ID ladders.
type patternPolicy struct {
	python     string
	shell      shellPatternMode
	candidates int
	supplement func(context.Context, string, func(int, int) bool, *Result) bool
	filter     func(document.File, Match) bool
	adapter    func(familyAnalyzer) Analyzer
}

type pythonFactConsumer interface {
	pythonID() string
	withPython(python.Facts) Analyzer
}

type shellPatternMode = shell.PatternMode

func (a transmissionCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	return a.findDocument(ctx, d, budget, patternStages{before: a.observe})
}

func (a transmissionCheck) observe(ctx context.Context, d document.File, budget int, out *Result) error {
	if err := a.preferPython(ctx, d, budget, out, ruleE1); err != nil {
		return err
	}

	return a.addShell(ctx, d, budget, out)
}

func (transmissionCheck) pythonID() string { return ruleE1 }

func (a transmissionCheck) withPython(facts python.Facts) Analyzer { a.python = facts; return a }

func (a removalCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	return a.findDocument(ctx, d, budget, patternStages{before: a.observe})
}

func (a removalCheck) observe(ctx context.Context, d document.File, budget int, out *Result) error {
	if err := a.preferPython(ctx, d, budget, out, ruleTM1); err != nil {
		return err
	}

	return a.addShell(ctx, d, budget, out)
}

func (removalCheck) pythonID() string { return ruleTM1 }

func (a removalCheck) withPython(facts python.Facts) Analyzer { a.python = facts; return a }

func (a outputExecutionCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	return a.findDocument(ctx, d, budget, patternStages{before: func(ctx context.Context, d document.File, b int, out *Result) error {
		return a.preferPython(ctx, d, b, out, ruleOH1)
	}})
}

func (outputExecutionCheck) pythonID() string { return ruleOH1 }

func (a outputExecutionCheck) withPython(facts python.Facts) Analyzer { a.python = facts; return a }

func (a downloadCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	return a.findDocument(ctx, d, budget, patternStages{before: a.addShell})
}

func (a downloadCheck) WithLanguageFacts(facts languageFacts) Analyzer {
	a.languageFacts = facts
	return a
}

func (a persistenceCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	return a.findDocument(ctx, d, budget, patternStages{before: a.addShell})
}

func (a modelSelectionCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	return a.findDocument(ctx, d, budget, patternStages{unit: func(u document.Unit, out *Result, b int) {
		if u.Origin == "frontmatter" {
			appendModelDeclaration(u, out, b)
		}
	}})
}

func (a paddingCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	return paddingMatches(ctx, d.Artifact().Metadata().Path, d.Artifact().Content(), budget)
}

func (a familyAnalyzer) addShell(ctx context.Context, d document.File, budget int, out *Result) error {
	r, err := a.shellPatterns(ctx, d, budget-len(out.Matches))
	out.Matches = append(out.Matches, r.Matches...)
	out.Truncated = out.Truncated || r.Truncated

	return err
}

func specializePattern(a familyAnalyzer) Analyzer {
	policy := patternPolicies[a.spec.id]
	a.exempt = patternGuard(a.spec.id)

	a.pythonRule, a.shellMode, a.candidateLimit, a.supplement, a.filter = policy.python, policy.shell, policy.candidates, policy.supplement, policy.filter
	if policy.adapter != nil {
		return policy.adapter(a)
	}

	return a
}

func hiddenCarrierSignals(ctx context.Context, text string, emit func(int, int) bool, out *Result) bool {
	out.Truncated = referenceCommentSignals(ctx, text, emit) || out.Truncated
	return invisibleTagMatches(ctx, text, emit)
}

func contextRepetitionSignals(ctx context.Context, text string, emit func(int, int) bool, out *Result) bool {
	out.Truncated = repeatedContext(ctx, text, emit) || out.Truncated
	return true
}

func memoryAdoptionSignals(ctx context.Context, text string, emit func(int, int) bool, out *Result) bool {
	out.Truncated = memoryAdoptions(ctx, text, emit) || out.Truncated
	return true
}
