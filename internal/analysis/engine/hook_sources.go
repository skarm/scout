package engine

import (
	"slices"
	"sort"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const (
	maxHookContexts      = 8
	maxHookContextChecks = 1 << 20
)

type scopedHookContext struct {
	context report.HookSourceContext
	scope   source.Span
	exclude []source.Span
}

func (c scopedHookContext) contains(loc report.Location) bool {
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
		if finding.Location.Language != language.Shell {
			continue
		}

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
			byPath[path.Target] = append(byPath[path.Target], scopedHookContext{context, path.Scope, path.Exclude})
		}
	}

	return byPath
}
