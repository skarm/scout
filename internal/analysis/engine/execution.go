package engine

import (
	"context"
	"sync"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/capture/artifact"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/extract"

	"github.com/skarm/scout/internal/analysis/harness"

	"github.com/skarm/scout/internal/analysis/validation"

	"github.com/skarm/scout/report"
)

type execution struct {
	engine                        *Engine
	ctx                           context.Context
	snapshot                      artifact.Snapshot
	options                       RunOptions
	files                         []artifact.File
	documents                     []document.File
	graph                         report.ComponentGraph
	expanded                      extract.Result
	inputs                        []report.File
	checks                        []analyzer.Analyzer
	ledger                        *validation.Ledger
	results                       []outcome
	collector                     *findingCollector
	byPath                        map[string]document.File
	fileIndex                     map[string]int
	operationTasks, capturedCount int
	analysis                      report.Analysis
}

func (run *execution) prepare() error {
	files := run.snapshot.Files()
	capturedCount := len(files)

	expanded, extractionErr := extract.Expand(run.ctx, files, run.options.Extraction)
	if extractionErr != nil && run.ctx.Err() == nil {
		return extractionErr
	}

	files = append(files, expanded.Files...)
	documents := document.PrepareAllWithRegistry(run.ctx, files, run.engine.registry)

	candidates := run.options.Limits.MaxFindings
	if run.options.MatchLimit > 0 {
		candidates = run.options.MatchLimit
	}

	documents, preparedChecks := analyzer.PrepareDerivedWithin(run.ctx, run.engine.analyzers, documents, candidates, run.options.MaxOperations)
	preparedChecks = analyzer.BindLanguage(run.ctx, preparedChecks, documents, candidates, run.options.MaxOperations)
	documents, preparedChecks = analyzer.PrepareShellPatternsWithin(run.ctx, preparedChecks, documents, candidates, run.options.MaxOperations)
	documents = document.Freeze(documents)
	graph := harness.Discover(run.ctx, run.snapshot.Metadata().Files, documents, expanded.Report, run.options.Harness)
	documents = harness.ApplyConfigScopes(documents, graph)
	checks := analyzer.BindContexts(run.ctx, preparedChecks, documents, expanded.Report)
	checks = analyzer.BindBundle(run.ctx, checks, documents, expanded.Report, candidates, run.options.MaxOperations)
	checks = analyzer.BindGraph(checks, documents, graph)
	operationTasks := analyzer.OperationTasks(checks)
	checks = analyzer.BindPython(run.ctx, checks, documents, candidates, run.options.MaxOperations)

	inputs := make([]report.File, len(files))
	for i, f := range files {
		inputs[i] = f.Metadata()
	}

	ledger := validation.NewWithSemantic(inputs, run.engine.rules, graph, run.options.Semantic.Enabled)

	results := make([]outcome, len(run.engine.analyzers))
	for i, rule := range run.engine.rules {
		results[i].check = report.Check{AnalyzerID: rule.ID, Version: rule.Version, Status: report.OutcomeCancelled}

		results[i].fileChecks = make([]report.FileCheck, len(documents))
		for j := range documents {
			results[i].fileChecks[j] = report.FileCheck{AnalyzerID: rule.ID, Status: report.OutcomeCancelled}
		}
	}

	collector := newFindingCollector(run.options.Limits.MaxFindings)
	run.files, run.documents, run.graph, run.expanded = files, documents, graph, expanded
	run.inputs, run.checks, run.ledger = inputs, checks, ledger
	run.results, run.collector, run.operationTasks, run.capturedCount = results, collector, operationTasks, capturedCount

	run.byPath = make(map[string]document.File, len(documents))
	for _, doc := range documents {
		run.byPath[doc.Artifact().Metadata().Path] = doc
	}

	return nil
}

func (run *execution) executeChecks() {
	type completedCheck struct {
		index   int
		outcome outcome
	}

	completed := make(chan completedCheck, run.engine.workers)

	jobs := make(chan int, len(run.checks))
	for i := range run.checks {
		jobs <- i
	}

	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < min(run.engine.workers, len(run.engine.analyzers)); w++ {
		wg.Go(func() {
			for i := range jobs {
				out, accepted := run.executeCheck(i)
				if !accepted {
					continue
				}

				completed <- completedCheck{index: i, outcome: out}
			}
		})
	}

	go func() { wg.Wait(); close(completed) }()

	for result := range completed {
		for _, finding := range result.outcome.findings {
			run.collector.add(finding)
		}

		result.outcome.findings = nil
		run.results[result.index] = result.outcome
	}
}

// executeCheck owns the concurrency slot and the per-check operation budget.
func (run *execution) executeCheck(i int) (outcome, bool) {
	if run.options.Slots != nil {
		select {
		case run.options.Slots <- struct{}{}:
		case <-run.ctx.Done():
			return outcome{}, false
		}
	}

	budget := run.options.Limits.MaxFindings
	if run.options.MatchLimit > 0 {
		budget = run.options.MatchLimit
	}

	task := run.ctx
	if run.options.MaxOperations > 0 {
		task = analysisbudget.WithLimit(run.ctx, run.options.MaxOperations/uint64(run.operationTasks)) //nolint:gosec // G115: OperationTasks counts this executing check plus nonnegative preparation tasks.
	}

	out := run.engine.runCheck(task, run.checks[i], run.engine.rules[i], run.documents, run.byPath, budget, run.ledger)
	if run.options.Slots != nil {
		<-run.options.Slots
	}

	return out, true
}
