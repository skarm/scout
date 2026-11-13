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

func TestHookSourceFunctionContextKeepsDefinitionAndCallLocations(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, ".codex-plugin/plugin.json", `{"name":"example"}`)
	scenario.WriteFile(t, root, "hooks/hooks.json", "{\n  "+`"SessionStart":[{"hooks":[{"type":"command","command":"bash -c 'cd \"$PLUGIN_ROOT\" && bash ./install.sh'"}]}],`+"\n  "+`"Stop":[{"hooks":[{"type":"command","command":"cd \"$PLUGIN_ROOT\" && bash ./other.sh"}]}]}`)
	scenario.WriteFile(t, root, "install.sh", "source ./lib\ninspect_local\n")
	scenario.WriteFile(t, root, "other.sh", "source ./lib\nprintf ready\n")
	scenario.WriteFile(t, root, "lib", "inspect_local() {\n  source ./extra\n  eval 'printf called'\n}\ninspect_unused() {\n  eval 'printf unused'\n}\n")
	scenario.WriteFile(t, root, "extra", "eval 'printf extra'\n")
	r, err := scenario.Scan(t, root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, f := range r.Findings {
		if f.RuleID != "SH003" {
			continue
		}
		switch {
		case f.Location.Path == "lib" && f.Location.StartLine == 3:
			seen["called"] = true
			if len(f.HookSources) != 1 {
				t.Fatalf("unexpected hook contexts for called function: %+v", f)
			}
			chain := f.HookSources[0]
			if chain.Event != "SessionStart" || len(chain.Steps) != 3 ||
				chain.Steps[0].Path != "hooks/hooks.json" || chain.Steps[0].StartLine != 2 ||
				chain.Steps[1].Path != "install.sh" || chain.Steps[1].StartLine != 1 ||
				chain.Steps[2].Path != "install.sh" || chain.Steps[2].StartLine != 2 {
				t.Fatalf("incorrect function context: %+v", chain)
			}
		case f.Location.Path == "lib" && f.Location.StartLine == 6:
			seen["unused"] = true
			if len(f.HookSources) != 0 {
				t.Fatalf("an uncalled function acquired a hook context: %+v", f)
			}
		case f.Location.Path == "extra" && f.Location.StartLine == 1:
			seen["nested"] = true
			if len(f.HookSources) != 1 || f.HookSources[0].Event != "SessionStart" || len(f.HookSources[0].Steps) != 4 ||
				f.HookSources[0].Steps[3].Path != "lib" || f.HookSources[0].Steps[3].StartLine != 2 {
				t.Fatalf("nested include lost its call context: %+v", f)
			}
		}
	}
	if len(seen) != 3 {
		t.Fatalf("expected called, uncalled and nested findings, saw %v", seen)
	}
}

func TestHookSourceFunctionReportRetainsBothBranchImports(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, ".codex-plugin/plugin.json", `{"name":"example"}`)
	scenario.WriteFile(t, root, "hooks/hooks.json", "{\n  "+`"Stop":[{"hooks":[{"type":"command","command":"bash \"$PLUGIN_ROOT/run.sh\""}]}]}`)
	scenario.WriteFile(t, root, "run.sh", "if test -n \"$mode\"; then\n  source \"$PLUGIN_ROOT/lib\"\nelse\n  . \"$PLUGIN_ROOT/lib\"\nfi\ninspect_local\n")
	scenario.WriteFile(t, root, "lib", "inspect_local() {\n  eval 'printf inspected'\n}\n")
	r, err := scenario.Scan(t, root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}

	for _, f := range r.Findings {
		if f.RuleID != "SH003" || f.Location.Path != "lib" || f.Location.StartLine != 2 {
			continue
		}
		if len(f.HookSources) != 2 {
			t.Fatalf("expected two hook contexts: %+v", f)
		}
		importLines := make([]int, 0, len(f.HookSources))
		for _, chain := range f.HookSources {
			if chain.Event != "Stop" || len(chain.Steps) != 3 || chain.Steps[0].Path != "hooks/hooks.json" || chain.Steps[0].StartLine != 2 ||
				chain.Steps[1].Path != "run.sh" || chain.Steps[2].Path != "run.sh" || chain.Steps[2].StartLine != 6 {
				t.Fatalf("wrong import or call location: %+v", chain)
			}
			importLines = append(importLines, chain.Steps[1].StartLine)
		}
		slices.Sort(importLines)
		if !slices.Equal(importLines, []int{2, 4}) {
			t.Fatalf("incorrect import lines: %v", importLines)
		}
		return
	}
	t.Fatal("missing SH003 in the imported function")
}
