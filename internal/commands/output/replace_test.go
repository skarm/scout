package output_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/skarm/scout/internal/commands/output"
)

func TestRepeatedPublicationReplacesARegularReport(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "report.json")
	writeFile(t, destination, "old")
	for i := range 3 {
		want := fmt.Sprintf(`{"run":%d}`, i)
		if err := output.Write(context.Background(), destination, nil, render(want)); err != nil {
			t.Fatal(err)
		}
		assertContents(t, destination, want)
		assertNoTemps(t, dir)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("report is not private: %v", info.Mode())
	}
}

func TestRenderOrWriteFailurePreservesThePreviousReport(t *testing.T) {
	for _, failure := range []error{errors.New("renderer failed"), io.ErrShortWrite} {
		dir := t.TempDir()
		destination := filepath.Join(dir, "report")
		writeFile(t, destination, "previous complete report")
		err := output.Write(context.Background(), destination, nil, func(w io.Writer) error {
			if _, err := io.WriteString(w, "new partial report"); err != nil {
				return err
			}
			return failure
		})
		if !errors.Is(err, failure) {
			t.Fatalf("got %v, want %v", err, failure)
		}
		assertContents(t, destination, "previous complete report")
		assertNoTemps(t, dir)
	}
}

func TestCancellationNeverPublishesPartialContent(t *testing.T) {
	for _, before := range []bool{true, false} {
		dir := t.TempDir()
		destination := filepath.Join(dir, "report")
		writeFile(t, destination, "old")
		ctx, cancel := context.WithCancel(context.Background())
		if before {
			cancel()
		}
		called := false
		err := output.Write(ctx, destination, nil, func(w io.Writer) error {
			called = true
			if _, err := io.WriteString(w, "partial"); err != nil {
				return err
			}
			cancel()
			return nil
		})
		cancel()
		if !errors.Is(err, context.Canceled) || called == before {
			t.Fatalf("before=%v renderer=%v error=%v", before, called, err)
		}
		assertContents(t, destination, "old")
		assertNoTemps(t, dir)
	}
}

func TestDestinationSymlinksAndDirectoriesAreRejected(t *testing.T) {
	for _, dangling := range []bool{false, true} {
		dir := t.TempDir()
		target, destination := filepath.Join(dir, "target"), filepath.Join(dir, "report")
		if !dangling {
			writeFile(t, target, "keep target")
		}
		makeSymlink(t, target, destination)
		if _, err := output.Validate(destination, nil); err == nil {
			t.Fatal("symlink destination accepted")
		}
		if err := output.Write(context.Background(), destination, nil, render("new")); err == nil {
			t.Fatal("symlink destination replaced")
		}
		info, err := os.Lstat(destination)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatal("destination symlink changed")
		}
		if !dangling {
			assertContents(t, target, "keep target")
		}
		assertNoTemps(t, dir)
	}
	directory := t.TempDir()
	if _, err := output.Validate(directory, nil); err == nil {
		t.Fatal("directory destination accepted")
	}
}

func TestEveryDirectoryInputIsProtected(t *testing.T) {
	first, second, outside := t.TempDir(), t.TempDir(), t.TempDir()
	for _, input := range []string{first, second} {
		destination := filepath.Join(input, "report.json")
		if _, err := output.Validate(destination, []string{first, second}); err == nil {
			t.Fatal("report inside a scan input accepted")
		}
		if err := output.Write(context.Background(), destination, []string{first, second}, render("new")); err == nil {
			t.Fatal("report published inside a scan input")
		}
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refusal changed the input tree")
		}
		assertNoTemps(t, input)
	}
	if err := output.Write(context.Background(), filepath.Join(outside, "report"), []string{first, second}, render("complete")); err != nil {
		t.Fatal(err)
	}
}

func TestParentAndInputAliasesCannotBypassContainment(t *testing.T) {
	input, aliasDir := t.TempDir(), t.TempDir()
	alias := filepath.Join(aliasDir, "input-alias")
	makeSymlink(t, input, alias)
	for _, tc := range []struct {
		destination string
		input       string
	}{
		{destination: filepath.Join(alias, "report"), input: input},
		{destination: filepath.Join(input, "report"), input: alias},
	} {
		if _, err := output.Validate(tc.destination, []string{tc.input}); err == nil {
			t.Fatal("directory alias bypassed containment")
		}
	}
	missingInput := filepath.Join(alias, "missing-file")
	if _, err := output.Validate(filepath.Join(input, "missing-file"), []string{missingInput}); err == nil {
		t.Fatal("missing input path through a parent alias could be overwritten")
	}
	outside := t.TempDir()
	outputAlias := filepath.Join(aliasDir, "output-alias")
	makeSymlink(t, outside, outputAlias)
	name, err := output.Validate(filepath.Join(outputAlias, "report"), []string{input})
	wantParent, parentErr := filepath.EvalSymlinks(outside)
	if err != nil || parentErr != nil || name != filepath.Join(wantParent, "report") {
		t.Fatalf("resolved report=%q err=%v parentErr=%v", name, err, parentErr)
	}
}

func TestSameFileAndHardlinkInputsAreProtected(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	input := filepath.Join(dir, "input")
	writeFile(t, input, "source")
	if _, err := output.Validate(input, []string{input}); err == nil {
		t.Fatal("input replacement accepted")
	}
	alias := filepath.Join(outside, "report")
	if err := os.Link(input, alias); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if err := output.Write(context.Background(), alias, []string{input}, render("new")); err == nil {
		t.Fatal("report alias to input accepted")
	}
	assertContents(t, input, "source")
	assertContents(t, alias, "source")
	assertNoTemps(t, outside)
}

func TestPublicationRechecksDestinationAfterRendering(t *testing.T) {
	dir := t.TempDir()
	destination, target := filepath.Join(dir, "report"), filepath.Join(dir, "keep")
	writeFile(t, destination, "old")
	writeFile(t, target, "target")
	probe := filepath.Join(dir, "symlink-probe")
	makeSymlink(t, target, probe)
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	err := output.Write(context.Background(), destination, nil, func(w io.Writer) error {
		if err := os.Remove(destination); err != nil {
			return err
		}
		if err := os.Symlink(target, destination); err != nil {
			return err
		}
		_, err := io.WriteString(w, "new")
		return err
	})
	if err == nil {
		t.Fatal("new symlink destination accepted")
	}
	if info, err := os.Lstat(destination); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("renderer did not introduce the destination symlink")
	}
	assertContents(t, target, "target")
	assertNoTemps(t, dir)
}

func TestMissingInputStillAllowsAnOutsideDiagnosticReport(t *testing.T) {
	dir, inputs := t.TempDir(), t.TempDir()
	if err := output.Write(context.Background(), filepath.Join(dir, "report"), []string{filepath.Join(inputs, "missing")}, render("incomplete")); err != nil {
		t.Fatal(err)
	}
	assertContents(t, filepath.Join(dir, "report"), "incomplete")
	assertNoTemps(t, dir)
}

func TestBadArgumentsAndMissingParentDoNotCreateAnything(t *testing.T) {
	dir := t.TempDir()
	for _, destination := range []string{"", filepath.Join(dir, "missing", "report")} {
		called := false
		err := output.Write(context.Background(), destination, nil, func(io.Writer) error { called = true; return nil })
		if err == nil || called {
			t.Fatalf("destination=%q err=%v renderer=%v", destination, err, called)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("publisher created missing parent")
	}
	if err := output.Write(nil, filepath.Join(dir, "report"), nil, render("x")); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := output.Write(context.Background(), filepath.Join(dir, "report"), nil, nil); err == nil {
		t.Fatal("nil renderer accepted")
	}
	if _, err := output.Validate(filepath.Join(dir, "report"), []string{""}); err == nil {
		t.Fatal("empty local input accepted")
	}
	assertNoTemps(t, dir)
}

func writeFile(t *testing.T, name, contents string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertContents(t *testing.T, name, want string) {
	t.Helper()
	got, err := os.ReadFile(name)
	if err != nil || string(got) != want {
		t.Fatalf("contents=%q err=%v, want %q", got, err, want)
	}
}

func makeSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	for _, pattern := range []string{".scout-report-*", ".scout-publish-*"} {
		files, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil || len(files) != 0 {
			t.Fatalf("temporary reports leaked: %v %v", files, err)
		}
	}
}
