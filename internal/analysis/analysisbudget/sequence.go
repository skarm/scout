package analysisbudget

import "context"

type StopReason uint8

const (
	Cancelled StopReason = iota + 1
	LimitReached
)

// StopObserver receives the first refusal of a shared operation quota.
type StopObserver interface {
	BudgetStopped(StopReason)
}

// Sequence shares one operation quota between sequential analysis stages.
type Sequence struct {
	Context  context.Context
	Limit    int
	Observer StopObserver
	used     int
	stopped  bool
}

func (q *Sequence) Used() int     { return q.used }
func (q *Sequence) Stopped() bool { return q.stopped }

// Spend reserves work before it starts. A refused reservation leaves prior
// results intact and stops the remaining stages of this sequence.
func (q *Sequence) Spend(n int) bool {
	if q.stopped {
		return false
	}

	switch {
	case q.Context == nil || q.Context.Err() != nil:
		return q.stop(Cancelled)
	case n > q.Limit-q.used:
		return q.stop(LimitReached)
	default:
		q.used += n
		return true
	}
}

func (q *Sequence) stop(reason StopReason) bool {
	q.stopped = true
	if q.Observer != nil {
		q.Observer.BudgetStopped(reason)
	}

	return false
}
