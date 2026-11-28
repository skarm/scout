package analyzer

import "github.com/skarm/scout/internal/syntax/source"

// boundedMatches admits distinct source observations. A candidate becomes a
// finding only here, after its producer has applied source/grammar precision.
// Exhaustion preserves accepted evidence and records an explicit partial result.
type boundedMatches struct {
	out    *Result
	budget int
	seen   map[source.Span]struct{}
}

func collectMatches(out *Result, budget int) *boundedMatches {
	collection := &boundedMatches{out: out, budget: budget}
	if len(out.Matches) > 0 {
		collection.seen = make(map[source.Span]struct{}, len(out.Matches))
	}

	for _, m := range out.Matches {
		collection.seen[source.Span{Start: m.Start, End: m.End}] = struct{}{}
	}

	return collection
}

func (c *boundedMatches) add(m Match) bool {
	at := source.Span{Start: m.Start, End: m.End}
	if _, seen := c.seen[at]; seen {
		return true
	}

	if len(c.out.Matches) >= c.budget {
		c.out.Truncated = true
		return false
	}

	if c.seen == nil {
		c.seen = make(map[source.Span]struct{})
	}

	c.seen[at] = struct{}{}
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
