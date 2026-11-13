package scout_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
)

func TestHookSourcePathKeepsEventAndOriginalLocations(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, ".codex-plugin/plugin.json", `{"name":"example","hooks":"./config/lifecycle"}`)
	scenario.WriteFile(t, root, "config/lifecycle", `{
  "SessionStart":[{"hooks":[{"type":"command","command":"cd \"$PLUGIN_ROOT\" && bash ./install.sh"}]}],
  "Stop":[{"hooks":[{"type":"command","command":"bash","args":["${PLUGIN_ROOT}/other.sh"]}]}]
}`)
	scenario.WriteFile(t, root, "install.sh", "printf ready\nsource ./lib\n")
	scenario.WriteFile(t, root, "other.sh", ". \"${PLUGIN_ROOT}/lib\"\n")
	scenario.WriteFile(t, root, "lib", "# helper\neval 'printf inspected'\n")
	r, err := scenario.Scan(t, root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}

	for _, f := range r.Findings {
		if f.RuleID != "SH003" || f.Location.Path != "lib" {
			continue
		}
		if f.Location.StartLine != 2 || f.Location.Language != "shell" || len(f.HookSources) != 2 {
			t.Fatalf("missing shell location or hook paths: %+v", f)
		}
		want := map[string]struct {
			hookLine, sourceLine int
			sourceFile           string
		}{"SessionStart": {2, 2, "install.sh"}, "Stop": {3, 1, "other.sh"}}
		for _, chain := range f.HookSources {
			match, known := want[chain.Event]
			if !known || len(chain.Steps) != 2 || chain.Steps[0].Path != "config/lifecycle" || chain.Steps[0].StartLine != match.hookLine ||
				chain.Steps[1].Path != match.sourceFile || chain.Steps[1].StartLine != match.sourceLine {
				t.Fatalf("incorrect hook source path: %+v", chain)
			}
			delete(want, chain.Event)
		}
		return
	}
	t.Fatal("missing SH003 for extensionless sourced file")
}

func TestOrdinaryHookSourceHasNoFindingInIncludedFile(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, ".codex-plugin/plugin.json", `{"name":"example"}`)
	scenario.WriteFile(t, root, "hooks/hooks.json", `{"SessionStart":[{"hooks":[{"type":"command","command":"bash \"$PLUGIN_ROOT/install.sh\""}]}]}`)
	scenario.WriteFile(t, root, "install.sh", "source \"$PLUGIN_ROOT/lib\"\n")
	scenario.WriteFile(t, root, "lib", "printf ready\n")
	r, err := scenario.Scan(t, root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if f.Location.Path == "lib" {
			t.Fatalf("ordinary sourced code produced a finding: %+v", f)
		}
	}
	for _, file := range r.Coverage.Files {
		if file.Path == "lib" {
			for _, unit := range file.Units {
				if unit.Language == "shell" {
					return
				}
			}
		}
	}
	t.Fatal("sourced extensionless file was not analyzed as shell")
}

func TestHookSourceGapIsInFileCoverageAndKeepsPhysicalLine(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, ".codex-plugin/plugin.json", `{"name":"example","hooks":"./config/events"}`)
	scenario.WriteFile(t, root, "config/events", "{\n  "+`"Stop":[{"hooks":[{"type":"command","command":"bash -c 'printf ready\nsource \"$PLUGIN_ROOT/missing\"'"}]}]}`)
	r, err := scenario.Scan(t, root)
	if !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatalf("expected incomplete scan: %v", err)
	}
	const code = "hook_source_not_captured"
	var located bool
	for _, diagnostic := range r.Diagnostics {
		if diagnostic.Code == code && diagnostic.Path == "config/events" && diagnostic.Line == 2 && diagnostic.Column > 0 {
			located = true
		}
	}
	for _, file := range r.Coverage.Files {
		if file.Path == "config/events" && located && slices.Contains(file.Gaps, code) && file.Completeness == "partial" {
			return
		}
	}
	t.Fatalf("missing located hook gap in file coverage: %+v", r.Diagnostics)
}

func TestHookSourceDirectLaunchUsesTheDeclaredInterpreter(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, ".codex-plugin/plugin.json", `{"name":"example"}`)
	scenario.WriteFile(t, root, "hooks/hooks.json", `{"Stop":[{"hooks":[{"type":"command","command":"${PLUGIN_ROOT}/run","args":[]},{"type":"command","command":"\"$PLUGIN_ROOT/other.sh\""}]}]}`)
	scenario.WriteFile(t, root, "run", "#!/bin/sh\n. \"$PLUGIN_ROOT/lib\"\n")
	scenario.WriteFile(t, root, "lib", "eval 'printf inspected'\n")
	scenario.WriteFile(t, root, "other.sh", "#!/usr/bin/python3\nsource = 'ordinary data'\n")
	r, err := scenario.Scan(t, root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}
	var linked, rejected bool
	for _, diagnostic := range r.Diagnostics {
		if diagnostic.Code == "hook_source_interpreter_unverified" && diagnostic.Path == "hooks/hooks.json" {
			rejected = true
		}
	}
	for _, finding := range r.Findings {
		if finding.Location.Path == "other.sh" && len(finding.HookSources) != 0 {
			t.Fatalf("foreign interpreter received a shell path: %+v", finding)
		}
		if finding.RuleID == "SH003" && finding.Location.Path == "lib" && len(finding.HookSources) == 1 &&
			len(finding.HookSources[0].Steps) == 2 && finding.HookSources[0].Steps[1].Path == "run" {
			linked = true
		}
	}
	if !linked || !rejected {
		t.Fatalf("unexpected direct launch result: linked=%t, foreign interpreter rejected=%t", linked, rejected)
	}
}
