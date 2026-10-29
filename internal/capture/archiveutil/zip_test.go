package archiveutil_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/capture/archiveutil"
)

func TestZIPHeaderConsistency(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{
		{name: "local-crc", edit: func(b []byte) { binary.LittleEndian.PutUint32(b[14:18], 17) }},
		{name: "local-size", edit: func(b []byte) { binary.LittleEndian.PutUint32(b[18:22], 99) }},
		{name: "descriptor", edit: func(b []byte) { at := bytes.Index(b, []byte{'P', 'K', 7, 8}); b[at+4] ^= 0xff }},
		{name: "local-flags", edit: func(b []byte) { b[6] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := makeZIP(t, []string{"x"}, []string{"content"})
			if e := open(data); e != nil {
				t.Fatal(e)
			}
			tc.edit(data)
			if open(data) == nil {
				t.Fatal("ambiguous header accepted")
			}
		})
	}
}

func TestZIPOverlappingMembersRejected(t *testing.T) {
	inner := makeZIP(t, []string{"b"}, []string{"hello"})
	central := bytes.Index(inner, []byte{'P', 'K', 1, 2})
	if central < 0 {
		t.Fatal("ZIP central record missing")
	}
	local := inner[:central]
	outer := makeZIP(t, []string{"a", "b"}, []string{string(local), "hello"})
	if e := open(outer); e != nil {
		t.Fatal(e)
	}
	aCentral := bytes.Index(outer, []byte{'P', 'K', 1, 2})
	bCentral := aCentral + 46 + int(binary.LittleEndian.Uint16(outer[aCentral+28:aCentral+30])) + int(binary.LittleEndian.Uint16(outer[aCentral+30:aCentral+32])) + int(binary.LittleEndian.Uint16(outer[aCentral+32:aCentral+34]))
	firstPayload := 30 + int(binary.LittleEndian.Uint16(outer[26:28])) + int(binary.LittleEndian.Uint16(outer[28:30]))
	binary.LittleEndian.PutUint32(outer[bCentral+42:bCentral+46], uint32(firstPayload))
	e := open(outer)
	if e == nil || !strings.Contains(e.Error(), "overlapping") {
		t.Fatalf("overlap did not reach interval check: %v", e)
	}
}

func TestZIPEntryCallbackAndArguments(t *testing.T) {
	data := makeZIP(t, []string{"a", "b"}, []string{"x", "y"})
	stop := errors.New("stop")
	calls := 0
	_, e := archiveutil.OpenZIPWithBudget(context.Background(), data, 3, 1024, 32, func() error {
		calls++
		if calls == 2 {
			return stop
		}
		return nil
	})
	if !errors.Is(e, stop) || calls != 2 {
		t.Fatal("entry budget ignored")
	}
	if _, e = archiveutil.OpenZIP(nil, data, 3, 1024, 32); e == nil {
		t.Fatal("nil context")
	}
	if _, e = archiveutil.OpenZIP(context.Background(), data, -1, 1024, 32); e == nil {
		t.Fatal("invalid entry limit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = archiveutil.OpenZIP(ctx, data, 3, 1024, 32); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}

func TestNamespace(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		dir  bool
	}{
		{a: "a", b: "A", dir: false}, {a: "K", b: "k", dir: false}, {a: "a", b: "a/b", dir: false}, {
			a:   "a/b",
			b:   "a",
			dir: false,
		}, {
			a:   "a",
			b:   "a",
			dir: true,
		},
	} {
		t.Run(tc.a+"/"+tc.b, func(t *testing.T) {
			n := archiveutil.Namespace{MaxNodes: 10}
			if e := n.Add(tc.a, tc.dir); e != nil {
				t.Fatal(e)
			}
			if n.Add(tc.b, tc.dir) == nil {
				t.Fatal("namespace conflict accepted")
			}
		})
	}
	n := archiveutil.Namespace{MaxNodes: 1}
	if n.Add("a/b", false) == nil {
		t.Fatal("implied directories unbounded")
	}
}

func makeZIP(t testing.TB, names, contents []string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for i, name := range names {
		r, e := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = io.WriteString(r, contents[i]); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

func open(data []byte) error {
	_, e := archiveutil.OpenZIP(context.Background(), data, 100, 1024, 32)
	return e
}
