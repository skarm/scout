//go:build linux || darwin || freebsd

package devcli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/skarm/scout/internal/commands/devcli"
)

func TestEvaluationRejectsFIFOInputsWithoutWaitingForWriter(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "input.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	corpus := filepath.Join(root, "corpus.json")
	if err := os.WriteFile(corpus, []byte(`{"schema_version":1,"kind":"authored_regression_not_holdout","cases":[{"id":"doc","category":"docs","label":"benign","path":"README.txt","content":"ordinary text"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"evaluate", "--profile=custom", "--timeout=50ms", fifo},
		{"evaluate", "--llm-config=" + fifo, "--allow-source-upload", "--timeout=50ms", corpus},
	} {
		done := make(chan int, 1)
		go func() {
			var out, diag bytes.Buffer
			done <- devcli.Run(t.Context(), args, &out, &diag)
		}()
		select {
		case code := <-done:
			if code != 2 {
				t.Fatalf("nonregular input accepted: exit %d", code)
			}
		case <-time.After(2 * time.Second):
			// Release a regressed blocking open so the test never leaves a reader
			// behind. A regular-file-only implementation needs no writer.
			writer, err := os.OpenFile(fifo, os.O_RDWR|unix.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("evaluation reader did not stop")
			}
			t.Fatal("evaluation waited for a FIFO writer outside its deadline")
		}
	}
}
