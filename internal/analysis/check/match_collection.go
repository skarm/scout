package check

import "github.com/skarm/scout/internal/syntax/source"

// MatchCollector admits distinct source spans under the result budget.
// Rejection preserves accepted evidence and marks the result partial.
type MatchCollector struct {
	out    *Result
	budget int
	seen   map[source.Span]struct{}
}

// NewMatchCollector deduplicates matches against observations already in out.
func NewMatchCollector(out *Result, budget int) *MatchCollector {
	collection := &MatchCollector{out: out, budget: budget}
	if len(out.Matches) > 0 {
		collection.seen = make(map[source.Span]struct{}, len(out.Matches))
	}

	for _, m := range out.Matches {
		collection.seen[source.Span{Start: m.Start, End: m.End}] = struct{}{}
	}

	return collection
}

// Span admits a distinct original-source span under the result budget.
func (c *MatchCollector) Span(start, end int) bool {
	at := source.Span{Start: start, End: end}
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
	c.out.Matches = append(c.out.Matches, Match{Start: start, End: end})

	return true
}

// Mapped returns whether traversal can continue. A mapping failure leaves
// accepted evidence intact and also continues, allowing callers whose contract
// skips malformed projections to ignore the error explicitly.
func (c *MatchCollector) Mapped(view source.View, span source.Span) (bool, error) {
	at, err := view.Original(span)
	if err != nil {
		return true, err
	}

	return c.Span(at.Start, at.End), nil
}
