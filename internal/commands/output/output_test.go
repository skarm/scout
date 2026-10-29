package output_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/skarm/scout/internal/commands/output"
)

func TestCreateNewIsPrivateAndNeverReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.zip")
	if err := output.CreateNew(context.Background(), path, render("first")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("private file: info=%v err=%v", info, err)
	}
	if err := output.CreateNew(context.Background(), path, render("second")); !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "first" {
		t.Fatalf("original replaced: %s %v", data, err)
	}
}

func TestCreateNewFailureLeavesNoOutputOrTemporary(t *testing.T) {
	for _, name := range []string{"renderer", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bundle.zip")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			writer := func(w io.Writer) error {
				_, _ = io.WriteString(w, "partial")
				if name == "cancelled" {
					cancel()
					return nil
				}
				return errors.New("renderer failed")
			}
			if err := output.CreateNew(ctx, path, writer); err == nil {
				t.Fatal("failure ignored")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("partial output remains: %v %v", entries, err)
			}
		})
	}
}

func TestCreateNewConcurrentWritersHaveOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.zip")
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() { results <- output.CreateNew(context.Background(), path, render("complete")) })
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("winners=%d", wins)
	}
}

func TestCreateNewRejectsInvalidInputsAndExistingAliases(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", dir, alias} {
		if err := output.CreateNew(context.Background(), path, render("new")); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
	if err := output.CreateNew(nil, filepath.Join(dir, "nil"), render("new")); err == nil {
		t.Fatal("nil context")
	}
	if err := output.CreateNew(context.Background(), filepath.Join(dir, "nil"), nil); err == nil {
		t.Fatal("nil renderer")
	}
}

func render(text string) func(io.Writer) error {
	return func(w io.Writer) error { _, err := io.WriteString(w, text); return err }
}
