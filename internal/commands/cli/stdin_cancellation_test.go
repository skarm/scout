//nolint:testpackage // Tests exercise the private borrowed-stdin adapter and cancellation contract.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/skarm/scout/report"
)

func TestStdinPipeRespectsOperationTimeout(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = read.Close() }()  // The pipe is also closed explicitly to unblock pending input.
	defer func() { _ = write.Close() }() // The pipe is also closed explicitly to unblock pending input.
	var out, diag bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- scanCommand(context.Background(), []string{"--profile", "custom", "--checks", "none", "--timeout", "30ms", "--format", "json", "--input", "-", "--name", "input.txt"}, read, &out, &diag)
	}()
	select {
	case code := <-done:
		var doc report.Document
		if code != 2 || json.Unmarshal(out.Bytes(), &doc) != nil || doc.Run.State != report.RunCancelled {
			t.Fatalf("stdin deadline outcome: code=%d out=%s diag=%s", code, &out, &diag)
		}
		if _, err := write.Write([]byte("still borrowed")); err != nil {
			t.Fatal("scan closed its caller's stdin", err)
		}
		data := make([]byte, len("still borrowed"))
		if _, err := io.ReadFull(read, data); err != nil || string(data) != "still borrowed" {
			t.Fatal("stdin no longer usable after timeout", err)
		}
	case <-time.After(300 * time.Millisecond):
		if err := write.Close(); err != nil {
			t.Error(err)
		}
		<-done
		t.Fatal("stdin capture remained blocked after the operation deadline")
	}
}

func TestStdinReadsPrefixAndEOF(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "eof", true: "cancel"}[cancelled], func(t *testing.T) {
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = read.Close() }()  // The pipe is also closed explicitly to unblock pending input.
			defer func() { _ = write.Close() }() // The pipe is also closed explicitly to unblock pending input.
			const prefix = "ordinary input\n"
			if _, err := write.Write([]byte(prefix)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input := stdinFile{file: read}
			p := make([]byte, 64)
			n, err := input.ReadContext(ctx, p)
			if err != nil || string(p[:n]) != prefix {
				t.Fatalf("prefix: %q %v", p[:n], err)
			}
			if cancelled {
				cancel()
			} else {
				if err := write.Close(); err != nil {
					t.Error(err)
				}
			}
			n, err = input.ReadContext(ctx, p)
			if n != 0 || (cancelled && !errors.Is(err, context.Canceled)) || (!cancelled && !errors.Is(err, io.EOF)) {
				t.Fatalf("end of stream: n=%d err=%v", n, err)
			}
		})
	}
}

func TestStdinFileAndClosedDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "input.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }() // The pipe is also closed explicitly to unblock pending input.
	if _, err := file.WriteString("ordinary input"); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 64)
	if n, err := (stdinFile{file: file}).ReadContext(context.Background(), p); err != nil || string(p[:n]) != "ordinary input" {
		t.Fatalf("regular stdin: %q %v", p[:n], err)
	}
	if err := file.Close(); err != nil {
		t.Error(err)
	}
	if _, err := (stdinFile{file: file}).ReadContext(context.Background(), p); err == nil {
		t.Fatal("closed descriptor admitted")
	}
}
