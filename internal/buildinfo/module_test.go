//nolint:testpackage // Exercises module selection with synthetic build metadata, independent of the test binary.
package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestModuleVersion(t *testing.T) {
	const modulePath = "github.com/skarm/scout"
	for _, tc := range []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{
			name: "release",
			info: &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v1.2.3"}},
			want: "v1.2.3",
		},
		{
			name: "local",
			info: &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}},
			want: "(devel)",
		},
		{name: "unversioned-main", info: &debug.BuildInfo{Main: debug.Module{Path: modulePath}}, want: "(devel)"},
		{
			name: "revision",
			info: &debug.BuildInfo{Main: debug.Module{
				Path:    modulePath,
				Version: "v0.0.0-20261028131417-5b17ee9ede97",
			}},
			want: "v0.0.0-20261028131417-5b17ee9ede97",
		},
		{
			name: "dirty",
			info: &debug.BuildInfo{Main: debug.Module{
				Path:    modulePath,
				Version: "v0.0.0-20261028131417-5b17ee9ede97+dirty",
			}},
			want: "v0.0.0-20261028131417-5b17ee9ede97+dirty",
		},
		{
			name: "dependency",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/app", Version: "v9.0.0"},
				Deps: []*debug.Module{{
					Path:    "example.com/other",
					Version: "v8.0.0",
				}, {
					Path:    modulePath,
					Version: "v1.2.3",
				}},
				Settings: []debug.BuildSetting{{
					Key:   "vcs.revision",
					Value: "host-revision",
				}},
			},
			want: "v1.2.3",
		},
		{
			name: "replacement",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path:    modulePath,
				Version: "v1.2.3",
				Replace: &debug.Module{
					Path:    "example.com/fork",
					Version: "v1.2.4",
				},
			}}},
			want: "v1.2.4",
		},
		{
			name: "main-replacement",
			info: &debug.BuildInfo{Main: debug.Module{
				Path:    modulePath,
				Version: "v1.2.3",
				Replace: &debug.Module{
					Path:    "example.com/fork",
					Version: "v1.2.4",
				},
			}},
			want: "v1.2.4",
		},
		{
			name: "local-replacement",
			info: &debug.BuildInfo{
				Deps: []*debug.Module{{
					Path:    modulePath,
					Version: "v1.2.3",
					Replace: &debug.Module{Path: "../scout"},
				}},
				Settings: []debug.BuildSetting{{
					Key:   "vcs.revision",
					Value: "host-revision",
				}},
			},
			want: "(devel)",
		},
		{
			name: "missing",
			info: &debug.BuildInfo{Main: debug.Module{Path: "example.com/app", Version: "v9.0.0"}},
			want: "unknown",
		},
		{
			name: "exact-path",
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: modulePath + "/v2", Version: "v2.0.0"}}},
			want: "unknown",
		},
		{
			name: "nil-dependency",
			info: &debug.BuildInfo{Deps: []*debug.Module{nil, {Path: modulePath, Version: "v1.2.3"}}},
			want: "v1.2.3",
		},
		{name: "no-metadata", info: nil, want: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := moduleVersion(tc.info, modulePath); got != tc.want {
				t.Fatalf("module version = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMissingModuleVersion(t *testing.T) {
	for _, path := range []string{"", "example.invalid/not-linked"} {
		if got := ModuleVersion(path); got != "unknown" {
			t.Errorf("ModuleVersion(%q) = %q, want unknown", path, got)
		}
	}
}
