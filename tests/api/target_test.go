package scout_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/report"
)

func TestReaderContextOwnsCancellationAndRetainsCapturedPrefix(t *testing.T) {
	const prefix = "captured before cancellation\n"
	s := testScanner(t, basicOptions())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := contextInputFunc(func(ctx context.Context, p []byte) (int, error) {
		n := copy(p, prefix)
		cancel()
		return n, ctx.Err()
	})
	run, err := s.Scan(ctx, scout.ReaderContext("input.txt", input))
	if !errors.Is(err, context.Canceled) || run.State != report.RunCancelled {
		t.Fatalf("cancelled stream: state=%s err=%v", run.State, err)
	}
	files := run.Targets[0].Analysis.Artifact.Files
	if len(files) != 1 || files[0].Size != int64(len(prefix)) || run.Targets[0].Analysis.Artifact.InventoryComplete {
		t.Fatalf("captured prefix lost or declared complete: %+v", run.Targets[0].Analysis.Artifact)
	}
}

func TestReaderContextValidatesEveryTargetBeforeReading(t *testing.T) {
	s := testScanner(t, basicOptions())
	reads := 0
	input := contextInputFunc(func(context.Context, []byte) (int, error) {
		reads++
		return 0, io.EOF
	})
	for _, invalid := range []scout.Target{scout.ReaderContext("nil.txt", nil), scout.ReaderContext("../escape", input)} {
		if _, err := s.ScanMany(context.Background(), []scout.Target{scout.ReaderContext("valid.txt", input), invalid}); !errors.Is(err, scout.ErrInvalidInput) {
			t.Fatalf("invalid reader target admitted: %v", err)
		}
	}
	if reads != 0 {
		t.Fatal("read before all targets passed admission")
	}
}

func TestReaderContextAcceptsOrdinaryEOF(t *testing.T) {
	s := testScanner(t, basicOptions())
	input := strings.NewReader("ordinary text")
	run, err := s.Scan(context.Background(), scout.ReaderContext("input.txt", contextInputFunc(func(_ context.Context, p []byte) (int, error) {
		return input.Read(p)
	})))
	if err != nil || run.State != report.RunComplete || !run.Targets[0].Analysis.Artifact.InventoryComplete {
		t.Fatalf("complete stream: state=%s err=%v", run.State, err)
	}
}

func TestReaderUsesOfferedContextCancellation(t *testing.T) {
	input := &cancellableTestInput{release: make(chan struct{})}
	defer input.unblock()
	opts := basicOptions()
	opts.Limits.Timeout = 30 * time.Millisecond
	s := testScanner(t, opts)
	done := make(chan error, 1)
	go func() {
		run, err := s.Scan(context.Background(), scout.Reader("input.txt", input))
		if run.State != report.RunCancelled || !errors.Is(err, context.DeadlineExceeded) {
			done <- errors.New("reader cancellation lost its run state or deadline")
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(300 * time.Millisecond):
		input.unblock()
		<-done
		t.Fatal("context-aware reader remained blocked after the operation deadline")
	}
}

type cancellableTestInput struct {
	release chan struct{}
	once    sync.Once
}

type contextInputFunc func(context.Context, []byte) (int, error)

func (f contextInputFunc) ReadContext(ctx context.Context, p []byte) (int, error) {
	return f(ctx, p)
}

func (r *cancellableTestInput) Read([]byte) (int, error) { <-r.release; return 0, io.EOF }

func (r *cancellableTestInput) ReadContext(ctx context.Context, _ []byte) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func (r *cancellableTestInput) unblock() { r.once.Do(func() { close(r.release) }) }
