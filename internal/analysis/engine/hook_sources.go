package engine

import (
	"slices"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const maxHookContexts = 8

func (run *execution) attachHookSourceContexts() bool {
	if len(run.hookSources.Paths) == 0 {
		return false
	}

	byPath := make(map[string][]report.HookSourceContext)
	overflow := make(map[string]bool)

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

		known := byPath[path.Target]

		if len(context.Steps) != len(path.Steps) || slices.ContainsFunc(known, func(other report.HookSourceContext) bool {
			return context.Event == other.Event && slices.Equal(context.Steps, other.Steps)
		}) {
			continue
		}

		if len(known) >= maxHookContexts {
			overflow[path.Target] = true
			continue
		}

		byPath[path.Target] = append(known, context)
	}

	limited := false

	for i := range run.analysis.Findings {
		finding := &run.analysis.Findings[i]
		if finding.Location.Language == language.Shell {
			finding.HookSources = byPath[finding.Location.Path]
			limited = limited || overflow[finding.Location.Path]
		}
	}

	return limited
}
