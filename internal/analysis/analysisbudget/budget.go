// Package analysisbudget attaches independent operation quotas to analysis tasks.
// Exhaustion records rejected work without cancelling the caller's context.
package analysisbudget

import (
	"context"
	"sync/atomic"
)

type contextKey struct{}

type counter struct {
	limit     uint64
	used      atomic.Uint64
	exhausted atomic.Bool
}

// WithLimit derives a context with a fresh task-local quota. A nested quota does
// not consume its parent's quota; the parent still supplies cancellation and
// deadlines. As with context.WithValue, a nil parent is invalid.
func WithLimit(parent context.Context, limit uint64) context.Context {
	budget := &counter{limit: limit}
	budget.exhausted.Store(limit == 0)

	return context.WithValue(parent, contextKey{}, budget)
}

// Consume admits units before the operation runs. Rejected work does not spend
// units and exhaustion is terminal. Reaching the exact limit successfully does
// not mark an otherwise completed task incomplete; a further positive request
// does. Zero units are a no-op unless the task is cancelled or already exhausted.
// An unbudgeted context admits work until its caller cancels it.
func Consume(ctx context.Context, units uint64) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}

	budget := lookup(ctx)
	if budget == nil {
		return true
	}

	for {
		if budget.exhausted.Load() || ctx.Err() != nil {
			return false
		}

		used := budget.used.Load()
		// Subtraction checks the remaining capacity without overflowing addition.
		if units > budget.limit-used {
			budget.exhausted.Store(true)
			return false
		}

		if budget.used.CompareAndSwap(used, used+units) {
			return true
		}
	}
}

// Used reports accepted units for this task, or zero without a task quota.
func Used(ctx context.Context) uint64 {
	if budget := lookup(ctx); budget != nil {
		return budget.used.Load()
	}

	return 0
}

// Exhausted reports a rejected capacity request, or an initial zero quota.
// Cancellation alone does not mark quota exhaustion. An exact successful final
// operation leaves Exhausted false until more work is requested.
func Exhausted(ctx context.Context) bool {
	if budget := lookup(ctx); budget != nil {
		return budget.exhausted.Load()
	}

	return false
}

func lookup(ctx context.Context) *counter {
	if ctx == nil {
		return nil
	}

	budget, _ := ctx.Value(contextKey{}).(*counter)

	return budget
}
