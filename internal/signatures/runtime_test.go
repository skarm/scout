//nolint:testpackage // Tests exercise private native engine ownership and close synchronization.
package signatures

import (
	"context"
	"errors"
	"fmt"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRuntimeRejectsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		edit    func(*Options)
		workers int
	}{
		{name: "disabled", edit: func(o *Options) { o.Enabled = false; o.ExtraRules = nil }, workers: 1},
		{name: "zero workers", edit: func(*Options) {}, workers: 0},
		{name: "excess workers", edit: func(*Options) {}, workers: 33},
		{name: "timeout", edit: func(o *Options) { o.Timeout = 0 }, workers: 1},
		{name: "total bytes", edit: func(o *Options) { o.MaxTotalBytes = 0 }, workers: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := runtimeOptions()
			tc.edit(&options)
			if runtime, err := Open(context.Background(), options, tc.workers); err == nil || runtime != nil {
				if runtime != nil {
					if err := runtime.Close(); err != nil {
						t.Error(err)
					}
				}
				t.Fatalf("runtime=%v err=%v", runtime, err)
			}
		})
	}
	if runtime, err := Open(nil, runtimeOptions(), 1); err == nil || runtime != nil {
		t.Fatal("nil constructor context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if runtime, err := Open(ctx, runtimeOptions(), 1); !errors.Is(err, context.Canceled) || runtime != nil {
		t.Fatalf("cancelled constructor: runtime=%v err=%v", runtime, err)
	}
}

func TestRuntimeOwnsRulesAndRetainsNativeEvidence(t *testing.T) {
	options := runtimeOptions()
	runtime := openNativeRuntime(t, options, 2)
	first, err := runtime.Check(context.Background(), []Input{runtimeInput(1)})
	if err != nil {
		t.Fatal(err)
	}
	for i := range options.ExtraRules {
		options.ExtraRules[i] = 'x'
	}
	second, err := runtime.Check(context.Background(), []Input{runtimeInput(2)})
	if err != nil {
		t.Fatal(err)
	}
	if first.RulesSHA256 == "" || first.RulesSHA256 != second.RulesSHA256 {
		t.Fatal("caller changed compiled rule identity")
	}
	for _, report := range []Report{first, second} {
		if report.Completeness != "complete" || len(report.Outcomes) != 1 || report.Outcomes[0].Status != "completed" {
			t.Fatalf("incomplete native result: %+v", report)
		}
		found := false
		for _, match := range report.Outcomes[0].Matches {
			if match.Rule == "runtime_marker" && match.Category == "malware" && len(match.Spans) == 1 {
				found = true
			}
		}
		if !found {
			t.Fatalf("custom native match lost: %+v", report.Outcomes)
		}
	}
}

func TestRuntimeConditionOnlyRulesKeepWholeFileEvidence(t *testing.T) {
	options := runtimeOptions()
	options.ExtraRules = []byte(`rule runtime_file { meta: category="unrecognized" condition: true }
rule runtime_integer { meta: category=42 condition: true }`)
	runtime := openNativeRuntime(t, options, 1)
	for _, text := range []string{"", "Пример\x00ordinary text"} {
		input := Input{Path: "input.txt", Data: text, SHA256: hash([]byte(text))}
		report, err := runtime.Check(context.Background(), []Input{input})
		if err != nil || report.Completeness != "complete" || len(report.Outcomes) != 1 {
			t.Fatalf("condition-only scan: completeness=%s error=%v", report.Completeness, err)
		}
		for _, rule := range []string{"runtime_file", "runtime_integer"} {
			match := requireRuntimeMatch(t, report.Outcomes[0], rule)
			if match.Category != "unknown" || len(match.Spans) != 1 || match.Spans[0] != (Span{Start: 0, End: len(text)}) {
				t.Fatalf("whole-file evidence: rule=%s category=%s spans=%v", match.Rule, match.Category, match.Spans)
			}
		}
	}
}

func TestRuntimeDeduplicatesBeforeSpanLimit(t *testing.T) {
	options := runtimeOptions()
	options.ExtraRules = []byte(`rule runtime_duplicates {
strings: $first="DUP_SENTINEL" $second="DUP_SENTINEL"
condition: any of them
}`)
	runtime := openNativeRuntime(t, options, 1)
	for _, count := range []int{8, 9} {
		text := strings.Repeat("Метка\x00DUP_SENTINEL ", count)
		report, err := runtime.Check(context.Background(), []Input{{
			Path:   "input.txt",
			Data:   text,
			SHA256: hash([]byte(text)),
		}})
		if err != nil || len(report.Outcomes) != 1 {
			t.Fatalf("duplicate scan: outcomes=%d error=%v", len(report.Outcomes), err)
		}
		out := report.Outcomes[0]
		want := "complete"
		if count > 8 {
			want = "partial"
		}
		if report.Completeness != want || out.Status != "completed" || out.Truncated != (count > 8) {
			t.Fatalf("count=%d completeness=%s status=%s truncated=%t", count, report.Completeness, out.Status, out.Truncated)
		}
		match := requireRuntimeMatch(t, out, "runtime_duplicates")
		if len(match.Spans) != 8 {
			t.Fatalf("duplicate span budget: %v", match.Spans)
		}
		seen := map[Span]bool{}
		for _, span := range match.Spans {
			if span.Start < len("Метка\x00") || span.End > len(text) || text[span.Start:span.End] != "DUP_SENTINEL" || seen[span] {
				t.Fatalf("invalid UTF-8 byte evidence: %v", span)
			}
			seen[span] = true
		}
	}
}

func TestRuntimeLimitsMatchingRulesAt32(t *testing.T) {
	for _, count := range []int{32, 33} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			var rules strings.Builder
			for i := range count {
				if _, err := fmt.Fprintf(&rules, "rule runtime_bound_%d { condition: true }\n", i); err != nil {
					t.Error(err)
				}
			}
			options := runtimeOptions()
			options.ExtraRules = []byte(rules.String())
			runtime := openNativeRuntime(t, options, 1)
			text := "ordinary text"
			report, err := runtime.Check(context.Background(), []Input{{
				Path:   "input.txt",
				Data:   text,
				SHA256: hash([]byte(text)),
			}})
			if err != nil || len(report.Outcomes) != 1 {
				t.Fatalf("rule budget: outcomes=%d error=%v", len(report.Outcomes), err)
			}
			out := report.Outcomes[0]
			want := "complete"
			if count > 32 {
				want = "partial"
			}
			if report.Completeness != want || out.Status != "completed" || out.Truncated != (count > 32) || len(out.Matches) != 32 {
				t.Fatalf("count=%d completeness=%s status=%s truncated=%t matches=%d", count, report.Completeness, out.Status, out.Truncated, len(out.Matches))
			}
		})
	}
}

func TestRuntimeRejectsInvalidRules(t *testing.T) {
	if !Backend().Available {
		t.Skip("native compiler is unavailable")
	}
	options := runtimeOptions()
	options.ExtraRules = []byte("rule broken { condition: }")
	if runtime, err := Open(context.Background(), options, 2); err == nil || runtime != nil {
		if runtime != nil {
			if err := runtime.Close(); err != nil {
				t.Error(err)
			}
		}
		t.Fatal("invalid rules opened a runtime")
	}
}

func TestRuntimeCancellationPreservesInputPlan(t *testing.T) {
	runtime := openNativeRuntime(t, runtimeOptions(), 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := runtime.Check(ctx, []Input{runtimeInput(1), runtimeInput(2)})
	if !errors.Is(err, context.Canceled) || report.Completeness != "partial" || len(report.Outcomes) != 2 {
		t.Fatalf("cancelled result: %+v %v", report, err)
	}
	for _, outcome := range report.Outcomes {
		if outcome.Status != "cancelled" || len(outcome.Matches) != 0 {
			t.Fatalf("cancelled evidence: %+v", outcome)
		}
	}
	if _, err := runtime.Check(nil, nil); err == nil {
		t.Fatal("nil check context accepted")
	}
}

func TestRuntimeParallelScansAndConcurrentClose(t *testing.T) {
	runtime := openNativeRuntime(t, runtimeOptions(), 2)
	var group sync.WaitGroup
	failures := make(chan error, 16)
	for i := range 16 {
		group.Go(func() {
			report, err := runtime.Check(context.Background(), []Input{runtimeInput(i)})
			if err != nil || report.Completeness != "complete" || len(report.Outcomes) != 1 || report.Outcomes[0].Path != runtimeInput(i).Path {
				failures <- fmt.Errorf("scan %d: completeness=%s err=%w", i, report.Completeness, err)
			}
		})
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	for range 8 {
		group.Go(func() {
			if err := runtime.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if _, err := runtime.Check(context.Background(), []Input{runtimeInput(1)}); !errors.Is(err, errClosed) {
		t.Fatalf("closed runtime error=%v", err)
	}
}

func TestRuntimeUnavailableBackendDoesNotFallback(t *testing.T) {
	if Backend().Available {
		t.Skip("absence path requires coreonly")
	}
	runtime, err := Open(context.Background(), runtimeOptions(), 1)
	if runtime != nil || err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("runtime=%v err=%v", runtime, err)
	}
}

func TestRuntimeCloseDrainsBorrowedAndQueuedChecks(t *testing.T) {
	if !Backend().Available {
		t.Skip("checkCompiled requires the native capability")
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	finishScan := func() { releaseOnce.Do(func() { close(release) }) }
	defer finishScan()
	closed := make(chan string, 4)
	child := &lifecycleEngine{name: "child", started: make(chan struct{}), release: release, closed: closed}
	parent := &lifecycleEngine{name: "parent", closed: closed}
	runtime := &Runtime{
		options:    runtimeOptions(),
		parent:     parent,
		sessions:   []compiledEngine{child},
		available:  make(chan compiledEngine, 1),
		closedDone: make(chan struct{}),
	}
	runtime.available <- child
	first := make(chan error, 1)
	go func() { _, err := runtime.Check(context.Background(), []Input{runtimeInput(1)}); first <- err }()
	<-child.started
	waiting := &observedRuntimeContext{Context: context.Background(), waiting: make(chan struct{})}
	second := make(chan error, 1)
	go func() { _, err := runtime.Check(waiting, []Input{runtimeInput(2)}); second <- err }()
	<-waiting.waiting
	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	watchdog := time.NewTimer(5 * time.Second)
	defer watchdog.Stop()
	for {
		_, err := runtime.Check(ctx, nil)
		if errors.Is(err, errClosed) {
			break
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("admission probe error=%v", err)
		}
		select {
		case <-watchdog.C:
			t.Fatal("Close did not stop new admission")
		default:
			goruntime.Gosched()
		}
	}
	select {
	case name := <-closed:
		t.Fatalf("destroyed %s while a scanner was borrowed", name)
	default:
	}
	finishScan()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatalf("admitted waiter was discarded: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if first, second := <-closed, <-closed; first != "child" || second != "parent" {
		t.Fatalf("destroy order=%q,%q", first, second)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case name := <-closed:
		t.Fatalf("destroyed %s twice", name)
	default:
	}
}

func runtimeOptions() Options {
	options := DefaultOptions()
	options.Enabled = true
	options.ExtraRules = []byte(`rule runtime_marker {
meta: category = "malware"
strings: $marker = "SCOUT_RUNTIME_CHECK_SENTINEL"
condition: $marker
}`)
	return options
}

func runtimeInput(index int) Input {
	text := fmt.Sprintf("SCOUT_RUNTIME_CHECK_SENTINEL %d", index)
	return Input{Path: fmt.Sprintf("input-%d.txt", index), SHA256: hash([]byte(text)), Data: text}
}

func openNativeRuntime(t *testing.T, options Options, workers int) *Runtime {
	t.Helper()
	if !Backend().Available {
		t.Skip("YARA-X runtime requires the native build")
	}
	runtime, err := Open(context.Background(), options, workers)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
	})
	return runtime
}

func requireRuntimeMatch(t *testing.T, outcome Outcome, rule string) Match {
	t.Helper()
	for _, match := range outcome.Matches {
		if match.Rule == rule {
			return match
		}
	}
	t.Fatalf("native rule missing: %s", rule)
	return Match{}
}

// The native tests above exercise actual signatures. This controlled engine
// makes the ownership lifecycle observable without depending on scan duration.
type lifecycleEngine struct {
	name    string
	started chan struct{}
	release <-chan struct{}
	closed  chan<- string
	once    sync.Once
}

func (e *lifecycleEngine) scan(ctx context.Context, _ []byte) (reply, error) {
	e.once.Do(func() { close(e.started) })
	select {
	case <-e.release:
		return reply{Status: "completed"}, nil
	case <-ctx.Done():
		return reply{}, ctx.Err()
	}
}

func (*lifecycleEngine) fork() (compiledEngine, error) {
	return nil, errors.New("lifecycle fixture does not compile or fork engines")
}

func (e *lifecycleEngine) close() { e.closed <- e.name }

type observedRuntimeContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *observedRuntimeContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}
