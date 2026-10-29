package analyzer

import "github.com/skarm/scout/internal/syntax/source"

// boundedMatches admits distinct source observations. A candidate becomes a
// finding only here, after its producer has applied source/grammar precision.
// Exhaustion preserves accepted evidence and records an explicit partial result.
type boundedMatches struct {
	out    *Result
	budget int
	seen   map[source.Span]bool
}

func collectMatches(out *Result, budget int) *boundedMatches {
	collection := &boundedMatches{out: out, budget: budget, seen: map[source.Span]bool{}}
	for _, m := range out.Matches {
		collection.seen[source.Span{Start: m.Start, End: m.End}] = true
	}

	return collection
}

func (c *boundedMatches) add(m Match) bool {
	at := source.Span{Start: m.Start, End: m.End}
	if c.seen[at] {
		return true
	}

	c.seen[at] = true
	if len(c.out.Matches) >= c.budget {
		c.out.Truncated = true
		return false
	}

	c.out.Matches = append(c.out.Matches, m)

	return true
}
func (c *boundedMatches) span(start, end int) bool { return c.add(Match{Start: start, End: end}) }

// addMapped returns whether traversal can continue. A mapping failure leaves
// accepted evidence intact and also continues, allowing callers whose contract
// skips malformed projections to ignore the error explicitly.
func (c *boundedMatches) addMapped(view source.View, span source.Span) (bool, error) {
	at, err := view.Original(span)
	if err != nil {
		return true, err
	}

	return c.span(at.Start, at.End), nil
}
