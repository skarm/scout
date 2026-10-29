package analysisbudget_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
)

func TestNoLimitIsTransparent(t *testing.T) {
	ctx := context.Background()
	if !analysisbudget.Consume(ctx, math.MaxUint64) || !analysisbudget.Consume(ctx, 1) {
		t.Fatal("unbudgeted task was limited")
	}
	if analysisbudget.Used(ctx) != 0 || analysisbudget.Exhausted(ctx) {
		t.Fatal("unbudgeted task acquired counter state")
	}
}

func TestZeroLimitIsImmediatelyExhausted(t *testing.T) {
	ctx := analysisbudget.WithLimit(context.Background(), 0)
	if !analysisbudget.Exhausted(ctx) || analysisbudget.Consume(ctx, 0) || analysisbudget.Consume(ctx, 1) || analysisbudget.Used(ctx) != 0 {
		t.Fatal("zero quota admitted an operation")
	}
	if ctx.Err() != nil {
		t.Fatal("quota exhaustion cancelled the context")
	}
}

func TestExactBoundaryIsSuccessfulUntilAnotherOperationIsRequested(t *testing.T) {
	ctx := analysisbudget.WithLimit(context.Background(), 5)
	if !analysisbudget.Consume(ctx, 3) || !analysisbudget.Consume(ctx, 2) || analysisbudget.Used(ctx) != 5 {
		t.Fatal("exact quota boundary was rejected")
	}
	if analysisbudget.Exhausted(ctx) || !analysisbudget.Consume(ctx, 0) {
		t.Fatal("a completed task at the boundary was marked incomplete")
	}
	if analysisbudget.Consume(ctx, 1) || !analysisbudget.Exhausted(ctx) || analysisbudget.Used(ctx) != 5 {
		t.Fatal("additional operation was not recorded as exhaustion")
	}
	if analysisbudget.Consume(ctx, 0) {
		t.Fatal("terminal exhaustion was reset by a no-op")
	}
}

func TestRejectedConsumptionIsTerminalAndDoesNotSpendUnits(t *testing.T) {
	ctx := analysisbudget.WithLimit(context.Background(), 5)
	if !analysisbudget.Consume(ctx, 4) || analysisbudget.Consume(ctx, 2) {
		t.Fatal("incorrect quota admission")
	}
	if analysisbudget.Used(ctx) != 4 || !analysisbudget.Exhausted(ctx) || analysisbudget.Consume(ctx, 1) {
		t.Fatal("rejected work consumed quota or allowed a later retry")
	}
	if ctx.Err() != nil {
		t.Fatal("quota failure replaced context state")
	}
}

func TestCounterDoesNotWrap(t *testing.T) {
	ctx := analysisbudget.WithLimit(context.Background(), math.MaxUint64)
	if !analysisbudget.Consume(ctx, math.MaxUint64-1) || analysisbudget.Consume(ctx, 2) {
		t.Fatal("overflowing quota request was accepted")
	}
	if analysisbudget.Used(ctx) != math.MaxUint64-1 || !analysisbudget.Exhausted(ctx) {
		t.Fatal("counter wrapped or spent rejected units")
	}
	exact := analysisbudget.WithLimit(context.Background(), math.MaxUint64)
	if !analysisbudget.Consume(exact, math.MaxUint64) || analysisbudget.Exhausted(exact) || analysisbudget.Consume(exact, 1) || analysisbudget.Used(exact) != math.MaxUint64 {
		t.Fatal("maximum exact boundary did not saturate safely")
	}
}

func TestCancellationRemainsTheParentError(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	ctx := analysisbudget.WithLimit(parent, 10)
	if !analysisbudget.Consume(ctx, 2) {
		t.Fatal("initial operation rejected")
	}
	cancel()
	if analysisbudget.Consume(ctx, 1) || analysisbudget.Consume(parent, 1) {
		t.Fatal("cancelled task admitted work")
	}
	if !errors.Is(ctx.Err(), context.Canceled) || !errors.Is(parent.Err(), context.Canceled) || analysisbudget.Exhausted(ctx) || analysisbudget.Used(ctx) != 2 {
		t.Fatal("cancellation was confused with quota exhaustion")
	}
}

func TestTaskQuotasAreIndependent(t *testing.T) {
	parent := analysisbudget.WithLimit(context.Background(), 3)
	child := analysisbudget.WithLimit(parent, 1)
	sibling := analysisbudget.WithLimit(parent, 4)
	if !analysisbudget.Consume(child, 1) || analysisbudget.Consume(child, 1) {
		t.Fatal("child quota did not exhaust independently")
	}
	if analysisbudget.Used(parent) != 0 || analysisbudget.Exhausted(parent) || analysisbudget.Used(sibling) != 0 || analysisbudget.Exhausted(sibling) {
		t.Fatal("child modified another task's counter")
	}
	if !analysisbudget.Consume(parent, 3) || !analysisbudget.Consume(sibling, 4) {
		t.Fatal("independent task lost quota")
	}
}

func TestConcurrentConsumptionNeverOvershoots(t *testing.T) {
	for _, units := range []uint64{1, 7} {
		ctx := analysisbudget.WithLimit(context.Background(), 1000)
		var accepted atomic.Uint64
		var group sync.WaitGroup
		for range 32 {
			group.Go(func() {
				for analysisbudget.Consume(ctx, units) {
					accepted.Add(units)
				}
			})
		}
		group.Wait()
		if got := analysisbudget.Used(ctx); got != accepted.Load() || got > 1000 || got != 1000/units*units {
			t.Fatalf("units=%d used=%d accepted=%d", units, got, accepted.Load())
		}
		if !analysisbudget.Exhausted(ctx) || ctx.Err() != nil {
			t.Fatal("concurrent quota exhaustion was not retained")
		}
	}
}
