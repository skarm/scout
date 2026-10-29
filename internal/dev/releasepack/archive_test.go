package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseArchives(t *testing.T) {
	candidates, output := fixture(t)
	for _, platform := range targets() {
		for _, name := range []string{"LICENSE", "NOTICE", "licenses/parser/LICENSE", "notices/module/LICENSE", "README.md"} {
			writeFixture(t, filepath.Join(candidates, "native-candidate-"+platform.name, filepath.FromSlash(name)), "extra metadata")
		}
	}

	if err := run([]string{"--version", "v1.2.3", "--candidates", candidates, "--output", output}, io.Discard); err != nil {
		t.Fatal(err)
	}

	files, err := os.ReadDir(output)
	if err != nil || len(files) != 4 {
		t.Fatal("expected three archives and SHA256SUMS", files, err)
	}

	checksums, err := os.ReadFile(filepath.Join(output, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(checksums)), "\n")
	if len(lines) != 3 {
		t.Fatal("missing archive checksum", string(checksums))
	}

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatal("invalid checksum row", line)
		}

		data, err := os.ReadFile(filepath.Join(output, fields[1]))
		if err != nil {
			t.Fatal(err)
		}

		hash := sha256.Sum256(data)
		if fields[0] != hex.EncodeToString(hash[:]) {
			t.Fatal("archive checksum differs", fields[1])
		}
	}

	for _, label := range []string{"macos-arm64", "linux-amd64"} {
		checkTar(t, filepath.Join(output, "scout-v1.2.3-"+label+".tar.gz"))
	}

	checkZIP(t, filepath.Join(output, "scout-v1.2.3-windows-amd64.zip"))
}

func TestCandidatesNeedOnlyBinaryAndChecksum(t *testing.T) {
	candidates, output := fixture(t)
	if err := packageRelease("v1.2.3", candidates, output); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidCandidatesLeaveNoOutput(t *testing.T) {
	for _, scenario := range []string{"tampered binary", "missing platform", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			candidates, output := fixture(t)
			path := filepath.Join(candidates, "native-candidate-windows-amd64", "scout.exe")

			switch scenario {
			case "tampered binary":
				writeFixture(t, path, "changed binary")
			case "missing platform":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "original-binary")
				writeFixture(t, target, "checked-binary")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skip("symlinks unavailable", err)
				}
			}

			if err := packageRelease("v1.2.3", candidates, output); err == nil {
				t.Fatal("invalid candidate was packaged")
			}

			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid input left partial release assets", err)
			}
		})
	}
}

func TestVersionAndOutputAdmission(t *testing.T) {
	candidates, output := fixture(t)
	for _, version := range []string{"", "../outside", "-flag", "v1/2", strings.Repeat("a", 129)} {
		if err := packageRelease(version, candidates, output); err == nil {
			t.Fatal("invalid version accepted", version)
		}
	}

	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid version created output", err)
	}

	marker := filepath.Join(output, "existing-file")
	writeFixture(t, marker, "preserve")

	if err := packageRelease("abc123", candidates, output); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing output was not refused", err)
	}

	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "preserve" {
		t.Fatal("existing output changed", err)
	}
}

func fixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	candidates := filepath.Join(root, "candidates")
	hash := sha256.Sum256([]byte("checked-binary"))

	for _, platform := range targets() {
		directory := filepath.Join(candidates, "native-candidate-"+platform.name)
		writeFixture(t, filepath.Join(directory, platform.binary), "checked-binary")
		writeFixture(t, filepath.Join(directory, "scout.sha256"), hex.EncodeToString(hash[:])+"  "+platform.binary+"\n")
	}

	return candidates, filepath.Join(root, "release")
}

func writeFixture(t *testing.T, path, contents string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func checkTar(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()

	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := compressed.Close(); err != nil {
			t.Error(err)
		}
	}()

	archive := tar.NewReader(compressed)
	header, err := archive.Next()
	if err != nil || header.Name != "scout" || header.Typeflag != tar.TypeReg || header.Mode&0o777 != 0o755 {
		t.Fatal("expected only the executable at the archive root", header, err)
	}

	data, err := io.ReadAll(archive)
	if err != nil || string(data) != "checked-binary" {
		t.Fatal("binary contents changed", err)
	}

	if header, err := archive.Next(); !errors.Is(err, io.EOF) {
		t.Fatal("archive contains an extra entry", header, err)
	}
}

func checkZIP(t *testing.T, path string) {
	t.Helper()
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := archive.Close(); err != nil {
			t.Error(err)
		}
	}()

	if len(archive.File) != 1 || archive.File[0].Name != "scout.exe" || archive.File[0].Mode().Perm() != 0o755 {
		t.Fatal("expected only scout.exe at the archive root", archive.File)
	}

	file, err := archive.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil || string(data) != "checked-binary" {
		t.Fatal("ZIP contents changed", err, closeErr)
	}
}
