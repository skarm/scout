package check

import "slices"

type observationKind uint8

const (
	observationMatch observationKind = iota
	observationComplete
	observationLimited
	observationError
)

type observation struct {
	kind  observationKind
	match Match
	err   error
}

// Facts is a bounded, append-only observation stream. One preparation owner
// writes it; after Finish, concurrent consumers replay independent result copies.
type Facts struct {
	// events preserves match and terminal observations in their original order.
	events []observation
	// limit bounds admitted matches before collection records a terminal limit.
	limit int
	// count counts admitted match observations rather than terminal events.
	count int
	// done prevents further writes after the first terminal observation.
	done bool
}

// NewFacts creates an observation stream with a nonnegative match ceiling. A
// negative limit becomes zero.
func NewFacts(limit int) *Facts { return &Facts{limit: max(0, limit)} }

// Admit checks the collection budget before a caller maps or validates a new
// candidate. An earlier cap cannot be replaced by a later preparation failure.
func (f *Facts) Admit() bool {
	if f == nil || f.done {
		return false
	}

	if f.count >= f.limit {
		f.Finish(nil, true)
		return false
	}

	return true
}

// Add appends a match only while collection is admitted and the stream remains
// open.
func (f *Facts) Add(match Match) {
	if f.Admit() {
		f.events = append(f.events, observation{kind: observationMatch, match: match})
		f.count++
	}
}

// Finish preserves the first terminal observation. A simultaneous error is
// stronger than a semantic limitation, but never replaces an earlier cap.
func (f *Facts) Finish(err error, limited bool) {
	if f == nil || f.done {
		return
	}

	kind := observationComplete
	if limited {
		kind = observationLimited
	}

	if err != nil {
		kind = observationError
	}

	f.events = append(f.events, observation{kind: kind, err: err})
	f.done = true
}

// Done reports whether collection has reached a terminal observation. A nil
// stream is done.
func (f *Facts) Done() bool { return f == nil || f.done }

// MatchCount returns the number of admitted matches, or zero for a nil stream.
func (f *Facts) MatchCount() int {
	if f == nil {
		return 0
	}

	return f.count
}

// Result checks completion before the consumer budget, so an exact complete
// prefix remains complete. Budget exhaustion precedes later limitations/errors.
func (f *Facts) Result(limit int) (Result, error) {
	var out Result
	if f == nil {
		return out, nil
	}

	for _, event := range f.events {
		if event.kind == observationComplete {
			return out, nil
		}

		if len(out.Matches) >= limit {
			out.Truncated = true
			return out, nil
		}

		switch event.kind {
		case observationLimited:
			out.Truncated = true
			return out, nil
		case observationError:
			return out, event.err
		default:
			match := event.match
			match.Trace = slices.Clone(match.Trace)
			match.Related = slices.Clone(match.Related)
			match.ContextSignals = slices.Clone(match.ContextSignals)
			out.Matches = append(out.Matches, match)
		}
	}

	return out, nil
}
