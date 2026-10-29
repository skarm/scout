package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBottleAuthenticityAndContents(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong digest", "missing library", "symlink", "duplicate library", "invalid pkg-config"} {
		t.Run(scenario, func(t *testing.T) {
			archive, digest := testBottle(t, scenario)
			if scenario == "wrong digest" {
				digest = strings.Repeat("0", 64)
			}
			output := filepath.Join(t.TempDir(), "install")
			err := unpackBottle(archive, output, digest)
			if scenario != "valid" {
				if err == nil {
					t.Fatal("accepted invalid native dependency", scenario)
				}
				if scenario == "wrong digest" {
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("unverified archive was extracted")
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			pc, err := os.ReadFile(filepath.Join(output, "lib/pkgconfig/yara_x_capi.pc"))
			if err != nil || strings.Contains(string(pc), "HOMEBREW_CELLAR") || !strings.Contains(string(pc), "Libs.private: -liconv") {
				t.Fatal("pkg-config relocation lost native linker flags", string(pc), err)
			}
			if _, err := os.Stat(filepath.Join(output, "yr")); !os.IsNotExist(err) {
				t.Fatal("unneeded CLI extracted")
			}
		})
	}
}

func TestCompleteBottleCacheNeedsNoDownload(t *testing.T) {
	archive, digest := testBottle(t, "valid")
	prefix := filepath.Join(t.TempDir(), "cache")
	if err := unpackBottle(archive, prefix, digest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "bottle.sha256"), []byte(digest), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ensureBottle(ctx, prefix, bottle{sha256: digest}); err != nil {
		t.Fatal("complete cache attempted a network operation", err)
	}
}

func TestIncompleteCacheIsRepairedFromVerifiedStaging(t *testing.T) {
	archive, digest := testBottle(t, "valid")
	prefix := filepath.Join(t.TempDir(), "cache")
	stage := filepath.Join(t.TempDir(), "install")
	for _, dir := range []string{prefix, stage} {
		if err := unpackBottle(archive, dir, digest); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, markerFile), []byte(digest), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(prefix, licenseFile)); err != nil {
		t.Fatal(err)
	}
	if err := libraryFiles(prefix); err == nil {
		t.Fatal("incomplete cache was accepted")
	}
	if err := repairCache(stage, prefix); err != nil {
		t.Fatal(err)
	}
	if err := libraryFiles(prefix); err != nil {
		t.Fatal("repair left cache incomplete", err)
	}
	license, err := os.ReadFile(filepath.Join(prefix, licenseFile))
	if err != nil || string(license) != "BSD-3-Clause" {
		t.Fatal("repair lost the package license", err)
	}
}

func testBottle(t *testing.T, scenario string) (string, string) {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	writer := tar.NewWriter(gz)
	entries := []struct{ name, data string }{
		{name: "include/yara_x.h", data: "/* C API */"},
		{name: "LICENSE", data: "BSD-3-Clause"},
		{name: "lib/libyara_x_capi.a", data: "static library"},
		{
			name: "lib/pkgconfig/yara_x_capi.pc",
			data: "prefix=@@HOMEBREW_CELLAR@@/yara-x/1.22.0\nVersion: 1.22.0\nLibs.private: -liconv\n",
		},
		{name: "bin/yr", data: "do not extract executable"},
	}
	for _, entry := range entries {
		if scenario == "missing library" && strings.HasSuffix(entry.name, ".a") {
			continue
		}
		if scenario == "invalid pkg-config" && strings.HasSuffix(entry.name, ".pc") {
			entry.data = "no prefix\n"
		}
		header := &tar.Header{
			Name:     "yara-x/" + version + "/" + entry.name,
			Size:     int64(len(entry.data)),
			Mode:     0o644,
			Typeflag: tar.TypeReg,
		}
		if scenario == "symlink" && strings.HasSuffix(entry.name, ".a") {
			header.Typeflag, header.Linkname, header.Size = tar.TypeSymlink, "/outside/cache", 0
			entry.data = ""
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
		if scenario == "duplicate library" && strings.HasSuffix(entry.name, ".a") {
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte(entry.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "bottle.tar.gz")
	if err := os.WriteFile(archive, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data.Bytes())
	return archive, hex.EncodeToString(digest[:])
}
