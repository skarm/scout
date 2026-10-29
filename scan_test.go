//nolint:testpackage // Exercises private target quotas and finalization cancellation observations.
package scout

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/scout/internal/buildinfo"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

func TestVersionUsesScoutBuildMetadata(t *testing.T) {
	previous := buildVersionOverride
	t.Cleanup(func() { buildVersionOverride = previous })
	buildVersionOverride = ""
	if got, want := Version(), buildinfo.ModuleVersion("github.com/skarm/scout"); got != want {
		t.Fatalf("version = %q, want module version %q", got, want)
	}

	buildVersionOverride = "linker-version"
	if got := Version(); got != buildVersionOverride {
		t.Fatalf("version = %q, want linker override %q", got, buildVersionOverride)
	}
}

func TestTargetQuotasPreserveRemaindersAndIndependentServiceBudgets(t *testing.T) {
	o := basicOptions()
	o.Limits.Capture.MaxTotalBytes, o.Limits.Capture.MaxFileBytes, o.Limits.Capture.MaxArchiveBytes = 10, 10, 10
	o.Limits.Capture.MaxFiles, o.Limits.Capture.MaxEntries = 5, 8
	o.Limits.MaxCaptureBytes, o.Limits.MaxCaptureFiles, o.Limits.MaxCaptureEntries = 10, 5, 8
	o.Limits.Extraction.MaxTotalBytes, o.Limits.Extraction.MaxObjectBytes, o.Limits.MaxExtractedBytes = 8, 8, 8
	o.Limits.Analysis.MaxOperations, o.Limits.MaxServiceRequests = 11, 5
	settings := review.DefaultOptions()
	settings.Enabled, settings.AllowSourceUpload = true, true
	settings.MaxRequests, settings.MaxInputBytes = 7, 65536
	o.Review = &ReviewOptions{Provider: forbiddenReviewer{}, Settings: settings}
	v := osv.DefaultOptions()
	v.Enabled, v.AllowNetwork = true, true
	o.Vulnerabilities = &v
	s := testScanner(t, o)
	for i, want := range []struct {
		capture, extracted    int64
		files, entries        int
		operations            uint64
		requests, sourceBytes int
	}{{capture: 4, extracted: 3, files: 2, entries: 3, operations: 4, requests: 1, sourceBytes: 21846}, {
		capture:     3,
		extracted:   3,
		files:       2,
		entries:     3,
		operations:  4,
		requests:    1,
		sourceBytes: 21845,
	}, {
		capture:     3,
		extracted:   2,
		files:       1,
		entries:     2,
		operations:  3,
		requests:    0,
		sourceBytes: 21845,
	}} {
		got := s.targetOptions(i, 3, report.ScanOperation)
		if got.Limits.Capture.MaxTotalBytes != want.capture || got.Limits.Capture.MaxFileBytes != want.capture || got.Limits.Capture.MaxArchiveBytes != want.capture || got.Limits.Capture.MaxFiles != want.files || got.Limits.Capture.MaxEntries != want.entries || got.Limits.Extraction.MaxTotalBytes != want.extracted || got.Limits.Extraction.MaxObjectBytes != want.extracted || got.Limits.Analysis.MaxOperations != want.operations {
			t.Fatalf("target %d resource quota changed: %+v", i, got.Limits)
		}
		if got.semanticQuota.Requests != want.requests || got.semanticQuota.InputBytes != want.sourceBytes || *got.vulnerabilityQuota != want.requests || got.Review.Settings != settings {
			t.Fatalf("target %d service allocation changed", i)
		}
	}
	comparison := o
	comparison.Limits.Capture.MaxTotalBytes, comparison.Limits.Capture.MaxFileBytes, comparison.Limits.Capture.MaxArchiveBytes, comparison.Limits.MaxCaptureBytes = 9, 9, 9, 9
	comparing := testScanner(t, comparison)
	before := comparing.targetOptions(0, 2, report.CompareOperation)
	after := comparing.targetOptions(1, 2, report.CompareOperation)
	if before.Limits != after.Limits || *before.semanticQuota != *after.semanticQuota || *before.vulnerabilityQuota != *after.vulnerabilityQuota || before.Limits.Capture.MaxTotalBytes != 4 {
		t.Fatal("comparison sides have different configured contracts")
	}
	before.semanticQuota.Requests = 99
	*before.vulnerabilityQuota = 99
	before.Vulnerabilities.MaxRequests = 99
	if after.semanticQuota.Requests == 99 || *after.vulnerabilityQuota == 99 || after.Vulnerabilities.MaxRequests == 99 || s.Limits() != o.Limits {
		t.Fatal("one target changed another target's quotas or scanner configuration")
	}
}

func TestFinalizationUsesOneCancellationObservationForStateAndError(t *testing.T) {
	s := testScanner(t, basicOptions())
	original, err := s.Scan(context.Background(), Reader("README.txt", strings.NewReader("ordinary harmless text")))
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	ctx := &observedContext{Context: cancelled}
	final, err := sealExecution(ctx, original, nil)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrIncomplete) || final.State != report.RunCancelled || final.Digest == "" || final.Digest == original.Digest || ctx.observations.Load() != 1 {
		t.Fatalf("finalization diverged: state=%s observations=%d err=%v", final.State, ctx.observations.Load(), err)
	}
	sealed, sealErr := report.SealRun(final)
	if sealErr != nil || sealed.Digest != final.Digest || original.State != report.RunComplete || len(original.Problems) != 0 {
		t.Fatalf("cancellation binding or caller input changed: %v", sealErr)
	}
	gate, err := policy.New(policy.Options{FailAt: report.High})
	if err != nil || gate.Evaluate(final, time.Now()).Decision == report.Allow {
		t.Fatal("finalization cancellation allowed admission")
	}
}

type observedContext struct {
	context.Context
	observations atomic.Int32
}

func (c *observedContext) Err() error {
	c.observations.Add(1)
	return c.Context.Err()
}

type forbiddenReviewer struct{}

func (forbiddenReviewer) Identity() review.Identity {
	return review.Identity{Provider: "test", Model: "test"}
}

func (forbiddenReviewer) Complete(context.Context, []byte) (review.Completion, error) {
	panic("request should not fit this quota")
}

func testScanner(t *testing.T, options Options) *Scanner {
	t.Helper()
	s, err := New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func basicOptions() Options {
	o := DefaultOptions()
	o.Profile = Custom
	o.Checks = &Checks{}
	return o
}
