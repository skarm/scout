package engine

import (
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const (
	maxHookContexts      = 8
	maxHookContextChecks = 1 << 20
)

func (run *execution) shellHookCoverage() *report.ShellHookCoverage {
	if len(run.hookSources.Commands) == 0 && len(run.hookSources.Diagnostics) == 0 {
		return nil
	}

	r := &run.analysis

	paths := make(map[string]bool)

	for _, command := range run.hookSources.Commands {
		if !command.FileArgv {
			paths[command.Path] = true
		}
	}

	for _, traced := range run.hookSources.Paths {
		if traced.Language == "" {
			paths[traced.Target] = true
		}
	}

	gaps := make(map[string]bool)
	if !run.snapshot.Complete() || run.ctx.Err() != nil || run.expanded.HookNamespacesIncomplete {
		gaps["capture_or_scan_incomplete"] = true
	}

	for _, d := range r.Diagnostics {
		if d.AffectsScope && affectsShellHookCoverage(d.Code) {
			gaps[d.Code] = true
		}
	}

	addHookReferenceGaps(r.Components, gaps)

	for _, rule := range []string{shell.HookEvalRule, shell.HookGeneratedExecutionRule} {
		if !slices.ContainsFunc(r.Coverage.Checks, func(check report.Check) bool { return check.AnalyzerID == rule }) {
			gaps[rule+":not_selected"] = true
		}
	}

	for _, file := range r.Coverage.Files {
		if paths[file.Path] {
			addShellFileGaps(file, run.byPath[file.Path], gaps)
			delete(paths, file.Path)
		}
	}

	if len(paths) > 0 {
		gaps["hook_source_coverage_missing"] = true
	}

	coverage := &report.ShellHookCoverage{Completeness: report.Complete}
	if len(gaps) > 0 {
		coverage.Completeness = report.Partial
		coverage.Gaps = slices.Sorted(maps.Keys(gaps))
	}

	return coverage
}

func affectsShellHookCoverage(code string) bool {
	return strings.HasPrefix(code, "hook_") || strings.HasPrefix(code, "harness_") || strings.HasPrefix(code, "plugin_hook") || code == "plugin_reference_limit"
}

func addHookReferenceGaps(graph report.ComponentGraph, gaps map[string]bool) {
	hooks := make(map[string]bool)

	for _, component := range graph.Components {
		if component.Kind == "hook" || component.Kind == "hook_config" {
			hooks[component.ID] = true
		}
	}

	for _, reference := range graph.References {
		if hooks[reference.ComponentID] && reference.Status != "resolved" && reference.Reason != "runtime_not_materialized" {
			gaps["hook_reference_unresolved"] = true
		}
	}
}

func addShellFileGaps(file report.FileCoverage, doc document.File, gaps map[string]bool) {
	if file.ReadStatus != report.CaptureCaptured {
		gaps["hook_source_not_captured"] = true
	}

	addHookShellUnitGaps(doc.Units(), gaps)

	for _, check := range file.Checks {
		if (check.AnalyzerID == shell.HookEvalRule || check.AnalyzerID == shell.HookGeneratedExecutionRule) && check.Status != report.OutcomeCompleted && check.Status != report.OutcomeNotApplicable {
			gaps[check.AnalyzerID+":"+check.Status] = true
		}
	}

	if !slices.ContainsFunc(file.Checks, func(check report.FileCheck) bool {
		return check.AnalyzerID == shell.HookEvalRule && check.Status == report.OutcomeCompleted
	}) {
		gaps[shell.HookEvalRule+":coverage_unavailable"] = true
	}

	for _, gap := range file.Gaps {
		if strings.HasPrefix(gap, "generated_shell_") || gap == "report_finding_limit" || gap == "analysis_unit_limit" || gap == "source_map_error" {
			gaps[gap] = true
		}
	}
}

func addHookShellUnitGaps(units []document.Unit, gaps map[string]bool) {
	parsed := false

	for _, unit := range units {
		if unit.Language != language.Shell || (unit.Origin != "file" && unit.Origin != document.OriginHookShell && unit.Origin != document.OriginGeneratedShell) {
			continue
		}

		parsed = true

		if unit.Status != report.UnitParsedLimited && !hookShellProjectionComplete(unit) {
			gaps["shell_unit:"+unit.Status] = true
		}
	}

	if !parsed {
		gaps["hook_shell_unit_missing"] = true
	}
}

func hookShellProjectionComplete(unit document.Unit) bool {
	if (unit.Status != "unsupported_syntax" && unit.Status != report.UnitParseError) ||
		(!unit.HookSource && unit.Origin != document.OriginHookShell && unit.Origin != document.OriginGeneratedShell) {
		return false
	}

	tree, ok := unit.Tree.(parse.ShellTree)

	return ok && tree.DeclarationError == nil && tree.Declarations != nil && !tree.Declarations.OmittedExecution
}

type scopedHookContext struct {
	context  report.HookSourceContext
	language string
	scope    source.Span
	exclude  []source.Span
}

func (c scopedHookContext) contains(loc report.Location) bool {
	if c.language != loc.Language || c.language != language.Shell && loc.Structure != "source-file" {
		return false
	}

	if c.scope != (source.Span{}) && (loc.ByteStart < c.scope.Start || loc.ByteEnd > c.scope.End) {
		return false
	}

	index := sort.Search(len(c.exclude), func(i int) bool { return c.exclude[i].End > loc.ByteStart })

	return index == len(c.exclude) || c.exclude[index].Start >= loc.ByteEnd
}

func (run *execution) attachHookSourceContexts() bool {
	if len(run.hookSources.Paths) == 0 {
		return false
	}

	byPath := run.indexHookSourceContexts()

	limited := false
	checks := 0

	for i := range run.analysis.Findings {
		finding := &run.analysis.Findings[i]

		for _, candidate := range byPath[finding.Location.Path] {
			checks++
			if checks > maxHookContextChecks || run.ctx.Err() != nil {
				return true
			}

			if !candidate.contains(finding.Location) || slices.ContainsFunc(finding.HookSources, func(other report.HookSourceContext) bool {
				return candidate.context.Event == other.Event && slices.Equal(candidate.context.Steps, other.Steps)
			}) {
				continue
			}

			if len(finding.HookSources) == maxHookContexts {
				limited = true
				break
			}

			finding.HookSources = append(finding.HookSources, candidate.context)
		}
	}

	return limited
}

func (run *execution) indexHookSourceContexts() map[string][]scopedHookContext {
	byPath := make(map[string][]scopedHookContext)

	for _, path := range run.hookSources.Paths {
		context := report.HookSourceContext{Event: path.Event, Steps: make([]report.Location, 0, len(path.Steps))}

		for _, step := range path.Steps {
			doc, ok := run.byPath[step.Path]
			if !ok || doc.Artifact().Metadata().SHA256 != step.SHA256 {
				break
			}

			loc, err := location(doc, source.Span{Start: step.ByteStart, End: step.ByteEnd})
			if err != nil || artifact.Hash([]byte(doc.Artifact().Content()[step.ByteStart:step.ByteEnd])) != step.SpanSHA256 {
				break
			}

			context.Steps = append(context.Steps, loc)
		}

		if len(context.Steps) == len(path.Steps) {
			lang := path.Language
			if lang == "" {
				lang = language.Shell
			}

			byPath[path.Target] = append(byPath[path.Target], scopedHookContext{
				context: context, language: lang, scope: path.Scope, exclude: path.Exclude,
			})
		}
	}

	return byPath
}
