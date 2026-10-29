package shell

import (
	"cmp"
	"context"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/source"
)

var (
	proseShellStart    = regexp.MustCompile("^[\\t ]*(?:[-*+][\\t ]+)?(?:['\"]?(?:curl|wget|r['\"]?m|chmod|git|cp|mv|install|env|command|sudo|bash|sh|echo|printf)\\b|cu\\\\|wg\\\\|\\$\\(|`)")
	proseCompoundStart = regexp.MustCompile(`^[\t ]*(?:if|for|while|until|case|time|function)\b|^[\t ]*[{(]|^[\t ]*[A-Za-z_][A-Za-z0-9_]*\(\)`)
)

var proseShellCandidate = regexp.MustCompile(proseShellStart.String() + "|" + proseCompoundStart.String())

// Typed source envelopes stay under their selected parser, including rejected
// units. Opaque and prose fences still receive bounded heuristic observations.
// Merge exclusions once for logarithmic lookup on each physical line.
type proseExclusions []source.Span

// CandidateSpans selects bounded prose candidates without reparsing typed source units.
func CandidateSpans(ctx context.Context, d document.File) ([]source.Span, bool) {
	for _, h := range d.Classification().Languages {
		if h.Language != language.Text && h.Language != language.Markdown {
			return nil, false
		}
	}

	text := d.Artifact().Content()

	var spans []source.Span

	excluded := proseExcludedRanges(d)
	offset := 0

	for line := range strings.Lines(text) {
		if !analysisbudget.Consume(ctx, 1) {
			return spans, true
		}

		span := source.Span{Start: offset, End: offset + len(line)}

		offset = span.End
		if !excluded.covers(span) && proseShellCandidate.MatchString(line) {
			if len(spans) >= document.MaxRegions {
				return spans, true
			}

			spans = append(spans, span)
		}
	}

	return spans, false
}

func proseExcludedRanges(d document.File) proseExclusions {
	var ranges []source.Span

	for _, unit := range d.Units() {
		if language.Structured(unit.Language) {
			ranges = append(ranges, unit.Span)
		}
	}

	for _, region := range d.Regions() {
		if language.Structured(region.Language) {
			ranges = append(ranges, region.Span)
		}
	}

	slices.SortFunc(ranges, func(a, b source.Span) int { return cmp.Compare(a.Start, b.Start) })

	var merged proseExclusions
	for _, at := range ranges {
		if len(merged) == 0 || merged[len(merged)-1].End < at.Start {
			merged = append(merged, at)
		} else {
			merged[len(merged)-1].End = max(merged[len(merged)-1].End, at.End)
		}
	}

	return merged
}

func (e proseExclusions) covers(at source.Span) bool {
	i := sort.Search(len(e), func(i int) bool { return e[i].End >= at.End })
	return i < len(e) && e[i].Start <= at.Start
}
