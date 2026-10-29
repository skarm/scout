package scout_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

func TestScanProducesBoundDocument(t *testing.T) {
	s := testScanner(t, basicOptions())
	r, err := s.Scan(context.Background(), scout.Reader("README.txt", strings.NewReader("plain harmless text")))
	if err != nil || r.State != report.RunComplete || len(r.Targets) != 1 {
		t.Fatalf("run=%+v err=%v", r, err)
	}
	g, err := policy.New(policy.Options{FailAt: report.High})
	if err != nil {
		t.Fatal(err)
	}
	d := report.NewDocument(r, g.Evaluate(r, time.Unix(1700000000, 0)))
	if err := d.Validate(); err != nil || policy.Code(d) != 0 {
		t.Fatalf("invalid evaluation: %+v %v", d.Evaluation, err)
	}
}

func TestConcurrentScansOwnIndependentResultsAndClose(t *testing.T) {
	s := testScanner(t, basicOptions())
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, err := s.Scan(context.Background(), scout.Reader("README.txt", strings.NewReader("plain text")))
			if err != nil || r.State != report.RunComplete {
				t.Errorf("scan failed: %+v %v", r, err)
			}
		})
	}
	wg.Wait()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Scan(context.Background(), scout.Reader("a.txt", strings.NewReader("a"))); !errors.Is(err, scout.ErrClosed) {
		t.Fatalf("scan after Close: %v", err)
	}
}

func TestCancellationNeverReturnsCompleteWithContextError(t *testing.T) {
	dir := t.TempDir()
	for i := range 128 {
		if err := os.WriteFile(filepath.Join(dir, time.Unix(int64(i), 0).Format("150405")+".txt"), []byte("plain text"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := testScanner(t, basicOptions())
	for _, duration := range []time.Duration{time.Nanosecond, 10 * time.Millisecond, 40 * time.Millisecond, 100 * time.Millisecond} {
		ctx, cancel := context.WithTimeout(context.Background(), duration)
		run, err := s.Scan(ctx, scout.Path(dir))
		cancel()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if run.State != report.RunCancelled {
				t.Fatalf("state=%s err=%v", run.State, err)
			}
		}
		if run.Digest == "" {
			t.Fatal("partial evidence was not sealed")
		}
	}
}

func testScanner(t *testing.T, options scout.Options) *scout.Scanner {
	t.Helper()
	s, err := scout.New(context.Background(), options)
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

func basicOptions() scout.Options {
	o := scout.DefaultOptions()
	o.Profile = scout.Custom
	o.Checks = &scout.Checks{}
	return o
}
