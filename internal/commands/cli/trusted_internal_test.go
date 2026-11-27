package cli

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadTrustedSizedHandlesChangedStatSize(t *testing.T) {
	data := strings.Repeat("x", 700)
	for _, size := range []int64{550, 700, 900, 0, maxTrustedPreallocation + 1} {
		got, err := readTrustedSized(strings.NewReader(data), size)
		if err != nil || string(got) != data {
			t.Fatalf("stat size %d produced %d bytes and %v", size, len(got), err)
		}
	}

	got, err := readTrustedSized(io.LimitReader(strings.NewReader(data), 600), 550)
	if err != nil || string(got) != data[:600] {
		t.Fatalf("growing file bypassed read limit: %d bytes, %v", len(got), err)
	}

	failure := errors.New("read failure")
	got, err = readTrustedSized(trustedFailingReader{failure}, 550)
	if !errors.Is(err, failure) || len(got) != 551 {
		t.Fatalf("lost an error on a full read: %d bytes, %v", len(got), err)
	}
}

type trustedFailingReader struct{ err error }

func (r trustedFailingReader) Read(p []byte) (int, error) { return len(p), r.err }
