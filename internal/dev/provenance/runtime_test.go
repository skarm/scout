package provenance //nolint:testpackage // Exercises private Go inventory decoding and its offline tool environment.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeInventoryJSON(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"product.go", "platform_windows.go", "embed.txt", "native.c", "native.h", "platform_arm64.s"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	pkg := listedPackage{
		Dir: root, Module: &struct{ Dir string }{Dir: root},
		GoFiles:        []string{"product.go", "ignored_test.go"},
		IgnoredGoFiles: []string{"platform_windows.go"}, EmbedFiles: []string{"embed.txt"},
		CFiles: []string{"native.c"}, HFiles: []string{"native.h"}, IgnoredOtherFiles: []string{"platform_arm64.s"},
	}
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}

	files, err := decodeRuntimeFiles(root, data)
	want := []string{
		filepath.Join(root, "product.go"), filepath.Join(root, "platform_windows.go"), filepath.Join(root, "embed.txt"),
		filepath.Join(root, "native.c"), filepath.Join(root, "native.h"), filepath.Join(root, "platform_arm64.s"),
	}
	if err != nil || !reflect.DeepEqual(files, want) {
		t.Fatalf("runtime inventory=%v error=%v, want %v", files, err, want)
	}

	if _, err := decodeRuntimeFiles(root, []byte("{")); err == nil {
		t.Fatal("malformed dependency inventory accepted")
	}
}

func TestRuntimeInventoryRejectsMissingOrOutsideSources(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"missing.go", "../outside.go"} {
		if _, err := checkedRuntimePath(root, root, name); err == nil {
			t.Fatalf("unavailable project source accepted: %s", name)
		}
	}

	for _, pkg := range []listedPackage{{}, {Module: &struct{ Dir string }{Dir: t.TempDir()}}} {
		files, err := runtimePackageFiles(root, pkg)
		if err != nil || len(files) != 0 {
			t.Fatal("external package entered the local source closure", files, err)
		}
	}

	if files := sortedRuntimePaths(map[string]bool{}); files == nil {
		t.Fatal("empty source inventory must retain its non-nil slice contract")
	}
}

func TestRuntimeInventoryEnvironmentStaysOffline(t *testing.T) {
	t.Setenv("GOPROXY", "https://proxy.invalid")
	t.Setenv("GOTOOLCHAIN", "auto")
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("SCOUT_INVENTORY_FIXTURE", "retained")
	env := map[string]string{}
	for _, entry := range offlineEnvironment() {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}

	if env["GOPROXY"] != "off" || env["GOTOOLCHAIN"] != "local" {
		t.Fatal("inventory may download modules or toolchains")
	}

	if _, exists := env["GOFLAGS"]; exists || env["SCOUT_INVENTORY_FIXTURE"] != "retained" {
		t.Fatal("inventory did not isolate build flags while retaining unrelated environment")
	}
}
