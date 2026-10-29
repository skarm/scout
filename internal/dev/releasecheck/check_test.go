package releasecheck_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/dev/releasecheck"
)

func TestLibraryAllowlistIsExact(t *testing.T) {
	for _, tc := range []struct {
		os, lib string
		allowed bool
	}{
		{os: "linux", lib: "libc.so.6", allowed: true},
		{os: "linux", lib: "libssl.so.3", allowed: false},
		{os: "linux", lib: "libyara_x_capi.so", allowed: false},
		{os: "linux", lib: "libpython3.13.so", allowed: false},
		{os: "linux", lib: "./libc.so.6", allowed: false},
		{os: "linux", lib: "libc.so.6.evil", allowed: false},
		{os: "darwin", lib: "/usr/lib/libSystem.B.dylib", allowed: true},
		{os: "darwin", lib: "@rpath/libyara_x_capi.dylib", allowed: false},
		{os: "darwin", lib: "/opt/homebrew/lib/libssl.3.dylib", allowed: false},
		{os: "darwin", lib: "/usr/lib/../local/lib/libpython.dylib", allowed: false},
		{os: "darwin", lib: "/System/Library/Frameworks/Security.framework/Versions/A/Security", allowed: true},
		{os: "windows", lib: "libc.so.6", allowed: false},
		{os: "windows", lib: "KERNEL32.dll", allowed: true},
		{os: "windows", lib: "bcrypt.dll", allowed: true},
		{os: "windows", lib: "libyara_x_capi.dll", allowed: false},
		{os: "windows", lib: "libwinpthread-1.dll", allowed: false},
		{os: "windows", lib: `C:\temp\kernel32.dll`, allowed: false},
		{os: "windows", lib: "kernel32.dll.evil", allowed: false},
	} {
		t.Run(tc.os+tc.lib, func(t *testing.T) {
			if releasecheck.AllowedSystemLibrary(tc.os, tc.lib) != tc.allowed {
				t.Fatal(tc)
			}
		})
	}
}

func TestReleaseRequiresNativeModulesAndBuildMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*debug.BuildInfo)
		bad    bool
	}{
		{name: "full", change: func(*debug.BuildInfo) {}, bad: false},
		{name: "core", change: func(b *debug.BuildInfo) {
			b.Settings = append(b.Settings, debug.BuildSetting{Key: "-tags", Value: "foo,coreonly"})
		}, bad: true},
		{name: "nocgo", change: func(b *debug.BuildInfo) { b.Settings[0].Value = "0" }, bad: true},
		{name: "missing", change: func(b *debug.BuildInfo) { b.Deps = b.Deps[1:] }, bad: true},
		{name: "malformed-sum", change: func(b *debug.BuildInfo) { b.Deps[0].Sum = "h1:not-a-checksum" }, bad: true},
		{name: "sum", change: func(b *debug.BuildInfo) { b.Deps[0].Sum = "" }, bad: true},
		{
			name:   "replace",
			change: func(b *debug.BuildInfo) { b.Deps[0].Replace = &debug.Module{Path: "/tmp/forged"} },
			bad:    true,
		},
		{name: "architecture", change: func(b *debug.BuildInfo) { b.Settings[2].Value = "arm64" }, bad: true},
		{name: "race", change: func(b *debug.BuildInfo) {
			b.Settings = append(b.Settings, debug.BuildSetting{Key: "-race", Value: "true"})
		}, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := goodBuild()
			tc.change(b)
			if (len(releasecheck.ValidateBuildInfo(b, "linux", "amd64")) > 0) != tc.bad {
				t.Fatal(tc.name)
			}
		})
	}
	if len(releasecheck.ValidateBuildInfo(nil, "linux", "amd64")) == 0 {
		t.Fatal("nil metadata")
	}
}

func TestInspectActualGoTestBinaryDoesNotClaimRelease(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("platform unsupported")
	}
	p, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	r, e := releasecheck.Inspect(p)
	if e != nil {
		t.Fatal(e)
	}
	if r.SHA256 == "" || r.Passed || r.Selftest != nil || r.OS != runtime.GOOS || r.Arch != runtime.GOARCH {
		t.Fatal(r)
	}
	// The verifier's own executable does not link any of the scanner engines.
	if len(r.Issues) == 0 {
		t.Fatal("accepted non-scanner binary")
	}
	v, e := releasecheck.Verify(context.Background(), p)
	if e != nil || v.Passed || v.Selftest != nil {
		t.Fatal(v, e)
	}
}

func TestBadReleaseInputs(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("not an executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, bad, filepath.Join(dir, "missing")} {
		if _, e := releasecheck.Inspect(p); e == nil {
			t.Fatal(p)
		}
	}
	if _, e := releasecheck.Verify(nil, bad); e == nil {
		t.Fatal("nil ctx")
	}
	p := filepath.Join(dir, "fake-elf")
	if err := os.WriteFile(p, append([]byte{0x7f, 'E', 'L', 'F'}, []byte(strings.Repeat("x", 100))...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, e := releasecheck.Inspect(p); e == nil {
		t.Fatal("bad ELF")
	}
}

func TestReleaseRejectsTreeSitterReplacements(t *testing.T) {
	for _, replacement := range []debug.Module{
		{Path: "/tmp/tree-sitter"},
		{
			Path:    "example.invalid/tree-sitter",
			Version: "v0.25.0",
			Sum:     "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
		{
			Path:    "github.com/tree-sitter/go-tree-sitter",
			Version: "v0.25.0",
			Sum:     "h1:sx6kcg8raRFCvc9BnXglke6axya12krCJF5xJ2sftRU=",
		},
	} {
		t.Run(replacement.Path, func(t *testing.T) {
			build := goodBuild()
			for _, module := range build.Deps {
				if module.Path == "github.com/tree-sitter/go-tree-sitter" {
					module.Replace = &replacement
				}
			}

			if len(releasecheck.ValidateBuildInfo(build, "linux", "amd64")) == 0 {
				t.Fatal("module replacement accepted")
			}
		})
	}
}

func goodBuild() *debug.BuildInfo {
	b := &debug.BuildInfo{
		GoVersion: "go1.26.8",
		Settings: []debug.BuildSetting{{Key: "CGO_ENABLED", Value: "1"}, {
			Key:   "GOOS",
			Value: "linux",
		}, {
			Key:   "GOARCH",
			Value: "amd64",
		}},
	}
	for _, p := range releasecheck.RequiredModules() {
		b.Deps = append(b.Deps, &debug.Module{
			Path:    p,
			Version: "v1.0.0",
			Sum:     "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		})
	}
	return b
}
