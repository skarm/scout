package hookpolicy_test

import (
	"context"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/hookpolicy"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

const command = `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"printf hello"}]}]}}`

func TestCapturedSettingsPrecedenceAndIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, project, local string
		off, uncertain       bool
	}{
		{name: "inherited", project: `{"disableAllHooks":true}`, local: command, off: true, uncertain: false},
		{
			name:      "local-on",
			project:   `{"disableAllHooks":true}`,
			local:     `{"disableAllHooks":false}`,
			off:       false,
			uncertain: false,
		},
		{
			name:      "local-off",
			project:   `{"disableAllHooks":false}`,
			local:     `{"disableAllHooks":true}`,
			off:       true,
			uncertain: false,
		},
		{
			name:      "unknown-shape",
			project:   `{"disableAllHooks":true,"future":true}`,
			local:     command,
			off:       false,
			uncertain: true,
		},
		{name: "malformed-local", project: `{"disableAllHooks":true}`, local: `{`, off: false, uncertain: true},
		{name: "wrong-type", project: `{"disableAllHooks":"true"}`, local: command, off: false, uncertain: true},
		{
			name:      "invalid-permission",
			project:   `{"disableAllHooks":true,"permissions":{"allow":["Read("]}}`,
			local:     command,
			off:       false,
			uncertain: true,
		},
		{
			name:      "invalid-hook-timeout",
			project:   `{"disableAllHooks":true,"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"printf ok","timeout":false}]}]}}`,
			local:     command,
			off:       false,
			uncertain: true,
		},
		{
			name:      "duplicate-key",
			project:   `{"disableAllHooks":true,"disableAllHooks":false}`,
			local:     command,
			off:       false,
			uncertain: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := bind(t, map[string]string{
				".claude/settings.json":       tc.project,
				".claude/settings.local.json": tc.local,
				"hooks/hooks.json":            command,
				"nested/SKILL.md":             "Read text.",
				"nested/hooks/hooks.json":     command,
			}, report.ExtractionReport{})
			for _, name := range []string{".claude/settings.json", ".claude/settings.local.json", "hooks/hooks.json"} {
				s := p[name]
				if s.Disabled != tc.off || s.Uncertain != tc.uncertain {
					t.Fatalf("%s: %+v", name, s)
				}
			}
			if s := p["nested/hooks/hooks.json"]; s.Disabled || s.Uncertain {
				t.Fatalf("cross-project suppression: %+v", s)
			}
		})
	}
}

func TestOnlyRealSettingsCanDisableHooks(t *testing.T) {
	p := bind(t, map[string]string{
		"examples.md":           "```json\n{\"disableAllHooks\":true}\n```",
		"hooks/hooks.json":      command,
		"scout-object://scalar": "{\"disableAllHooks\":true}",
	}, report.ExtractionReport{})
	if p["hooks/hooks.json"].Disabled {
		t.Fatal("derived/example settings granted an exemption")
	}
}

func TestArchiveNamespacesDoNotShareDisableState(t *testing.T) {
	a, b, c := "scout-object://a", "scout-object://b", "scout-object://c"
	p := bind(t, map[string]string{a: `{"disableAllHooks":true}`, b: command, c: command}, report.ExtractionReport{Objects: []report.DerivedObject{
		{Role: "archive_member", ParentPath: "one.zip", MemberName: ".claude/settings.json", File: report.File{Path: a}},
		{Role: "archive_member", ParentPath: "one.zip", MemberName: "hooks/hooks.json", File: report.File{Path: b}},
		{Role: "archive_member", ParentPath: "two.zip", MemberName: "hooks/hooks.json", File: report.File{Path: c}},
	}})
	if !p[b].Disabled || p[c].Disabled {
		t.Fatalf("archive boundary: %+v", p)
	}
}

func bind(t *testing.T, files map[string]string, extraction report.ExtractionReport) hookpolicy.Policy {
	t.Helper()
	fs := make([]artifact.File, 0, len(files))
	for name, s := range files {
		fs = append(fs, artifact.NewFile(name, []byte(s), false))
	}
	return hookpolicy.Bind(context.Background(), document.PrepareAll(context.Background(), fs), extraction)
}
