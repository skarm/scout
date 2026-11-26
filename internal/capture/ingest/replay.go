package ingest

import (
	"context"
	"sync"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

type stableInputsKey struct{}

type stableInput struct {
	mu       sync.Mutex
	limits   report.CaptureLimits
	snapshot artifact.Snapshot
}

// WithStableInputs enables reuse for explicitly named, private, immutable
// materializations owned by the caller for the life of ctx. Ordinary selected
// filesystem paths must not be registered here.
func WithStableInputs(ctx context.Context, groups ...map[string]string) context.Context {
	inputs := map[string]*stableInput{}

	for _, group := range groups {
		for _, path := range group {
			inputs[path] = &stableInput{}
		}
	}

	return context.WithValue(ctx, stableInputsKey{}, inputs)
}

func readStableInput(ctx context.Context, target string, limits report.CaptureLimits, entry *stableInput) (artifact.Snapshot, error) {
	entry.mu.Lock()
	previous, previousLimits := entry.snapshot, entry.limits
	entry.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return artifact.Snapshot{}, err
	}

	if previous.Complete() && captureLimitsFit(previousLimits, limits) {
		return previous, nil
	}

	snapshot, err := readPath(ctx, target, limits)
	if err == nil && snapshot.Complete() {
		entry.mu.Lock()
		entry.limits, entry.snapshot = limits, snapshot
		entry.mu.Unlock()
	}

	return snapshot, err
}

// Reuse only captures completed under equal or stricter acquisition limits.
// MaxFindings affects analysis after capture, so it is independent of reuse.
func captureLimitsFit(captured, requested report.CaptureLimits) bool {
	return captured.MaxEntries <= requested.MaxEntries && captured.MaxFiles <= requested.MaxFiles &&
		captured.MaxFileBytes <= requested.MaxFileBytes && captured.MaxTotalBytes <= requested.MaxTotalBytes &&
		captured.MaxArchiveBytes <= requested.MaxArchiveBytes && captured.MaxPathBytes <= requested.MaxPathBytes &&
		captured.MaxDepth <= requested.MaxDepth
}
