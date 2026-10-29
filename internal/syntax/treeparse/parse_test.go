//go:build !coreonly && cgo

package treeparse_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	sitter "github.com/tree-sitter/go-tree-sitter"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"

	"github.com/skarm/scout/internal/syntax/treeparse"
	"github.com/skarm/scout/internal/syntax/treeparse/internal/nativetest"
)

type (
	contextMarker    struct{ data [32768]byte }
	contextMarkerKey struct{}
)

func TestParseDoesNotRetainCallerContext(t *testing.T) {
	// Keep a cancellable parent alive during collection. Unlike Background,
	// it would retain an AfterFunc registration if Parse forgot to stop it.
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	collected := make(chan struct{})
	parseContextMarker(t, parent, collected)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		goruntime.GC()
		select {
		case <-collected:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("closed parse retains caller context through its cancellation callback")
}

func TestParsePreservesSyntaxTreesAndRefusesExpiredWork(t *testing.T) {
	parser := treeparse.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(sitter.NewLanguage(python.Language())); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		text    string
		invalid bool
	}{{text: "x = 1\n", invalid: false}, {text: "def (\n", invalid: true}} {
		tree := treeparse.Parse(t.Context(), parser, []byte(tc.text), time.Now().Add(time.Second))
		if tree == nil {
			t.Fatal("parse unexpectedly cancelled")
		}
		if tree.RootNode().HasError() != tc.invalid {
			tree.Close()
			t.Fatal("syntax validity changed")
		}
		tree.Close()
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		ctx      context.Context
		deadline time.Time
	}{
		{ctx: ctx, deadline: time.Now().Add(time.Second)},
		{ctx: t.Context(), deadline: time.Now().Add(-time.Second)},
	} {
		if tree := treeparse.Parse(tc.ctx, parser, []byte("x = 1\n"), tc.deadline); tree != nil {
			tree.Close()
			t.Fatal("expired work produced a tree")
		}
	}
}

func TestChunkedInputPreservesNativeTreeAndSourceSpans(t *testing.T) {
	for i, text := range []string{
		"text = '" + strings.Repeat("🙂", 3000) + "'\n",
		strings.Repeat("value = 1\n", 1200) + "print(value)\n",
		"value = [" + strings.Repeat("1,", 5000),
	} {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			parser := treeparse.NewParser()
			if err := parser.SetLanguage(sitter.NewLanguage(python.Language())); err != nil {
				parser.Close()
				t.Fatal(err)
			}
			oracle := sitter.NewParser()
			if err := oracle.SetLanguage(sitter.NewLanguage(python.Language())); err != nil {
				t.Fatal(err)
			}
			want := oracle.Parse([]byte(text), nil)
			defer oracle.Close()
			got := treeparse.Parse(t.Context(), parser, []byte(text), time.Now().Add(5*time.Second))
			if want == nil || got == nil {
				if want != nil {
					want.Close()
				}
				if got != nil {
					got.Close()
				}
				parser.Close()
				t.Fatal("native parse did not produce comparison trees")
			}
			assertNativeTreeEqual(t, got.RootNode(), want.RootNode())
			got.Close()
			want.Close()
			parser.Close()
		})
	}
}

func TestCloseWaitsForActiveParse(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	gate := &entryContext{Context: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	p := newLifecycleParser(t)
	result := make(chan *treeparse.Tree, 1)
	go func() { result <- treeparse.Parse(gate, p, []byte("let value = 1;"), time.Now().Add(time.Second)) }()
	<-gate.entered
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-closed:
		// Let the old implementation leave through the context check rather
		// than enter C with an already freed parser in this regression test.
		cancel()
		close(gate.release)
		<-result
		t.Fatal("Close returned while Parse still owned the native state")
	case <-time.After(20 * time.Millisecond):
	}
	close(gate.release)
	tree := <-result
	<-closed
	if tree == nil {
		t.Fatal("active parse was damaged by Close")
	}
	defer tree.Close()
	// Trees own their native storage independently of the parser and input.
	if tree.RootNode().HasError() || tree.RootNode().EndByte() != 14 {
		t.Fatal("tree did not survive parser closure")
	}
	cancel()
	p.Close()
	p.Reset()
	if err := p.SetLanguage(sitter.NewLanguage(typescript.LanguageTypescript())); err == nil {
		t.Fatal("closed parser was reopened")
	}
	if got := treeparse.Parse(t.Context(), p, []byte("let x = 1;"), time.Now().Add(time.Second)); got != nil {
		got.Close()
		t.Fatal("closed parser accepted work")
	}
}

func TestCancellationCloseAndReuseStress(t *testing.T) {
	t.Parallel()
	text := []byte("let x=" + strings.Repeat("A<", 1200) + "T" + strings.Repeat(">", 1200) + ";\n")
	for worker := range 4 {
		t.Run(fmt.Sprintf("%c", 'A'+worker), func(t *testing.T) {
			t.Parallel()
			for i := range 100 {
				p := newLifecycleParser(t)
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				timer := time.AfterFunc(time.Duration(i%5)*100*time.Microsecond, func() {
					cancel()
					if i%2 == 0 {
						p.Close()
					}
					close(done)
				})
				tree := treeparse.Parse(ctx, p, text, time.Now().Add(time.Second))
				if !timer.Stop() {
					<-done
				}
				cancel()
				if tree != nil {
					if tree.RootNode().EndByte() != uint(len(text)) {
						t.Error("partial tree escaped cancellation")
					}
					tree.Close()
				}
				if i%2 != 0 {
					assertReusableParser(t, p)
				}
				p.Close()
				p.Close()
				// A context cancelled after Close must never call into freed C state.
				cancel()
			}
		})
	}
}

func TestNativeProgressInterruptsWorkBetweenInputReads(t *testing.T) {
	// Fits in one input chunk, but ambiguous generics require substantial parser
	// work after delivery. The native logger interrupts at a fixed reduction;
	// accepting a tree before discarding it is a failure, regardless of speed.
	text := "let x=" + strings.Repeat("A<", 1200) + "T" + strings.Repeat(">", 1200) + ";\n"
	for _, mode := range []string{"deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			if err := nativetest.CheckProgress(typescript.LanguageTypescript(), text, "reduce ", mode == "deadline"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFlatTreeDeadlineAndReuse(t *testing.T) {
	// Interrupt after acceptance, when a flat tree still requires balancing.
	// The native check requires interruption before completion and a clean reuse.
	text := strings.Repeat("let value = 1;\n", 4000)
	for _, mode := range []string{"deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			if err := nativetest.CheckProgress(typescript.LanguageTypescript(), text, "accept", mode == "deadline"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func BenchmarkParseLifecycle(b *testing.B) {
	parser := treeparse.NewParser()
	b.Cleanup(parser.Close)
	if err := parser.SetLanguage(sitter.NewLanguage(python.Language())); err != nil {
		b.Fatal(err)
	}
	text := []byte("x = 1\n")
	deadline := time.Now().Add(time.Hour)
	b.ReportAllocs()
	for b.Loop() {
		tree := treeparse.Parse(context.Background(), parser, text, deadline)
		if tree == nil {
			b.Fatal("parse failed")
		}
		tree.Close()
	}
}

func TestParseHeapDiagnostics(t *testing.T) {
	dir := os.Getenv("SCOUT_PERFORMANCE_DIR")
	if dir == "" {
		t.Skip("set SCOUT_PERFORMANCE_DIR for retained-context heap diagnostics")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	parser := treeparse.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(sitter.NewLanguage(python.Language())); err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{0, 1000, 2000} {
		if count > 0 {
			for i := range 1000 {
				data := make([]byte, 8192)
				data[0] = byte(i)
				ctx := context.WithValue(context.Background(), contextMarkerKey{}, data)
				tree := treeparse.Parse(ctx, parser, []byte("x = 1\n"), time.Now().Add(time.Second))
				if tree == nil {
					t.Fatal("parse failed")
				}
				tree.Close()
			}
		}
		goruntime.GC()
		goruntime.GC()
		var memory goruntime.MemStats
		goruntime.ReadMemStats(&memory)
		t.Logf("completed_parses=%d retained_heap_bytes=%d", count, memory.HeapAlloc)
		f, err := os.Create(filepath.Join(dir, fmt.Sprintf("heap-%d.pprof", count)))
		if err != nil {
			t.Fatal(err)
		}
		err = pprof.WriteHeapProfile(f)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
	}
}

func parseContextMarker(t *testing.T, parent context.Context, collected chan struct{}) {
	t.Helper()
	marker := &contextMarker{}
	marker.data[0] = 1
	goruntime.AddCleanup(marker, func(done chan struct{}) { close(done) }, collected)
	ctx := context.WithValue(parent, contextMarkerKey{}, marker)
	parser := treeparse.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(sitter.NewLanguage(python.Language())); err != nil {
		t.Fatal(err)
	}
	tree := treeparse.Parse(ctx, parser, []byte("x = 1\n"), time.Now().Add(time.Second))
	if tree == nil {
		t.Fatal("parse failed")
	}
	tree.Close()
	goruntime.KeepAlive(ctx)
}

func assertNativeTreeEqual(t *testing.T, got *treeparse.Node, want *sitter.Node) {
	t.Helper()
	if got.Kind() != want.Kind() || got.StartByte() != want.StartByte() || got.EndByte() != want.EndByte() ||
		got.HasError() != want.HasError() || got.IsMissing() != want.IsMissing() || got.IsError() != want.IsError() ||
		got.IsNamed() != want.IsNamed() || got.ChildCount() != want.ChildCount() {
		t.Fatalf("chunking changed native node: %s [%d,%d) vs %s [%d,%d)", got.Kind(), got.StartByte(), got.EndByte(), want.Kind(), want.StartByte(), want.EndByte())
	}
	for i := uint(0); i < want.ChildCount(); i++ {
		if got.FieldNameForChild(uint32(i)) != want.FieldNameForChild(uint32(i)) {
			t.Fatal("field name changed")
		}
		assertNativeTreeEqual(t, got.Child(i), want.Child(i))
	}
}

type entryContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (c *entryContext) Err() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Context.Err()
}

func newLifecycleParser(t *testing.T) *treeparse.Parser {
	t.Helper()
	p := treeparse.NewParser()
	if err := p.SetLanguage(sitter.NewLanguage(typescript.LanguageTypescript())); err != nil {
		p.Close()
		t.Fatal(err)
	}
	return p
}

func assertReusableParser(t *testing.T, p *treeparse.Parser) {
	t.Helper()
	tree := treeparse.Parse(t.Context(), p, []byte("let value = 1;"), time.Now().Add(time.Second))
	if tree == nil {
		t.Fatal("cancelled callback damaged the next request")
	}
	defer tree.Close()
	if tree.RootNode().HasError() || tree.RootNode().EndByte() != 14 {
		t.Fatal("reused parser returned an invalid tree")
	}
}
