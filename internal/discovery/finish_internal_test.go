package discovery

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
)

func TestFinalizationCancellationPreservesEvidenceAndCannotClaimComplete(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx := &finishCancelContext{Context: base, cancel: cancel, remaining: 3}
	root := t.TempDir()
	original := []string{filepath.Join(root, "a"), filepath.Join(root, "a", "child"), filepath.Join(root, "b")}
	b := builder{ctx: ctx, out: Snapshot{
		Schema: "scout.environment/v1", Complete: true,
		Targets: slices.Clone(original), Components: []Component{{Kind: "skill", Name: "retained"}},
		Sources: []Source{{Path: filepath.Join(root, "SKILL.md"), SHA256: "retained"}},
	}}
	snapshot, err := b.finish()
	if !errors.Is(err, context.Canceled) || snapshot.Complete || !slices.Contains(snapshot.Issues, Issue{Code: "cancelled"}) {
		t.Fatalf("cancellation during finalization was lost: err=%v snapshot=%+v", err, snapshot)
	}
	if !slices.Equal(snapshot.Targets, original) || len(snapshot.Components) != 1 || len(snapshot.Sources) != 1 {
		t.Fatal("partial finalization discarded captured evidence or protected inputs")
	}
}

// Cancel at a finalization checkpoint without sleeps or scheduling assumptions.
type finishCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *finishCancelContext) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}

	return c.Context.Err()
}
