// Package scenarios provides shared fixtures for Scanner integration tests.
package scenarios

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/scout/internal/scantest"
)

func WriteFile(t testing.TB, root, name, content string) {
	t.Helper()

	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func Scanner(t testing.TB, c scantest.Config) *scantest.Scanner {
	t.Helper()

	s, err := scantest.New(c, t)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func Scan(t testing.TB, root string) (result scantest.Result, err error) {
	t.Helper()

	s, err := scantest.New(scantest.DefaultConfig())
	if err != nil {
		return result, err
	}

	defer func() { err = errors.Join(err, s.Close()) }()

	return s.Scan(context.Background(), root)
}
