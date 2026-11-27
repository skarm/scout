package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadBatchBlobPreservesFraming(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("first blob 5\na\nb\x00c\nempty blob 0\n\n"))
	for _, test := range []struct{ id, content string }{{"first", "a\nb\x00c"}, {"empty", ""}} {
		if data, err := readBatchBlob(reader, test.id); err != nil || string(data) != test.content {
			t.Fatalf("blob %q: %q, %v", test.id, data, err)
		}
	}

	for _, response := range []string{"test missing\n", "other blob 0\n\n", "test blob 2\na", "test blob 0\nx"} {
		if _, err := readBatchBlob(bufio.NewReader(strings.NewReader(response)), "test"); err == nil {
			t.Fatalf("accepted malformed batch response %q", response)
		}
	}
}
