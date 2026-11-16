package scout_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
	"github.com/skarm/scout/report"
)

func TestHookShellFindingsKeepEventAndPhysicalLine(t *testing.T) {
	const name = "hooks/hooks.json"
	const input = `{
  "hooks": {
    "SessionStart": [{"hooks":[{"type":"command","command":"eval 'printf first'"}]}],
    "PreToolUse": [{"hooks":[{"type":"command","command":"bash -c 'printf ready\neval \"printf second\"'"}]}],
    "Stop": [{"hooks":[{"type":"command","command":"/bin/sh","args":["-c","eval 'printf third'"]}]}],
    "SessionEnd": [{"hooks":[{"type":"command","command":"bash","args":["-c","cat >setup.sh <<'EOF'\neval 'printf fourth'\nEOF\n"]}]}]
  }
}`
	root := t.TempDir()
	scenario.WriteFile(t, root, name, input)
	r, err := scenario.Scan(t, root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}

	want := map[string]struct {
		line int
		text string
	}{
		"SessionStart": {3, `eval 'printf first'`},
		"PreToolUse":   {4, `eval \"printf second\"`},
		"Stop":         {5, `eval 'printf third'`},
		"SessionEnd":   {6, `eval 'printf fourth'`},
	}
	for _, finding := range r.Findings {
		if finding.RuleID != "SH003" || finding.Location.Path != name {
			continue
		}
		loc := finding.Location
		commandText := slices.Contains(finding.ContextSignals, check.ShellCommandText)
		if commandText && !slices.Contains(finding.ContextSignals, check.ShellEval) {
			continue // Separate SH003 observation for the outer interpreter.
		}
		entry, found := want[loc.HookEvent]
		structure := "hook-command"
		if loc.HookEvent == "SessionEnd" {
			structure = "heredoc"
		}
		if !found || loc.StartLine != entry.line || loc.Language != "shell" || loc.Structure != structure ||
			loc.ByteStart != strings.Index(input, entry.text) || input[loc.ByteStart:loc.ByteEnd] != entry.text {
			t.Fatalf("incorrect hook finding: %+v", loc)
		}
		if loc.HookEvent == "Stop" && !commandText {
			t.Fatal("argv and eval evidence at the same span should both be retained")
		}
		delete(want, loc.HookEvent)
	}
	if len(want) > 0 {
		t.Fatalf("missing findings: %+v", want)
	}
}

func TestGeminiExtensionHookResolvesCapturedHandler(t *testing.T) {
	const config = `{"hooks":{"AfterAgent":[{"hooks":[{
		"type":"command","command":"bash '${extensionPath}/hooks/start.sh'"
	}]}]}}`
	root := t.TempDir()
	scenario.WriteFile(t, root, "extension/gemini-extension.json", `{"name":"example","version":"1.0.0"}`)
	scenario.WriteFile(t, root, "extension/hooks/hooks.json", config)
	scenario.WriteFile(t, root, "extension/hooks/start.sh", "bash -c 'printf ready'\n")

	for _, tc := range []struct {
		name, path string
		coverage   report.Completeness
	}{
		{name: "unknown root", coverage: report.Partial},
		{name: "shell-safe root", path: "/installed/shell-extension", coverage: report.Complete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := scantest.DefaultConfig()
			if tc.path != "" {
				options.Scanner.Harness.ShellHookRoot = report.ShellHookRoot{Host: report.HostGeminiCLI, Path: tc.path}
			}

			r, err := scenario.Scanner(t, options).Scan(context.Background(), root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			found := slices.ContainsFunc(r.Findings, func(f report.Finding) bool {
				return f.RuleID == "SH003" && f.Location.Path == "extension/hooks/start.sh" &&
					slices.ContainsFunc(f.HookSources, func(h report.HookSourceContext) bool {
						return h.Event == "AfterAgent" && len(h.Steps) == 1 && h.Steps[0].Path == "extension/hooks/hooks.json"
					})
			})
			if !found {
				t.Fatalf("expected a Shell finding linked to the Gemini hook: %+v", r.Findings)
			}

			coverage := r.Coverage.ShellHooks
			if coverage == nil || coverage.Completeness != tc.coverage ||
				slices.Contains(coverage.Gaps, "hook_source_gemini_root_unverified") != (tc.path == "") {
				t.Fatalf("unexpected Gemini hook coverage: %+v", coverage)
			}
		})
	}
}

func TestManifestHookShellFindingsUseReferencedFile(t *testing.T) {
	const path = "plugin/config/lifecycle.custom"
	const config = `{
  "hooks": {
    "PreToolUse": [{"hooks":[{"type":"command","command":"bash -o pipefail -c 'printf ready\neval \"printf inspected\"'"}]}],
    "Stop": [{"hooks":[{"type":"command","command":"sh","args":["-c","cat >setup.sh <<'EOF'\neval 'printf generated'\nEOF\n"]}]}]
  }
}`
	root := t.TempDir()
	scenario.WriteFile(t, root, "plugin/.codex-plugin/plugin.json", `{"name":"example-plugin","hooks":"./config/lifecycle.custom"}`)
	scenario.WriteFile(t, root, path, config)
	scenario.WriteFile(t, root, "plugin/config/other.json", config)
	r, err := scenario.Scan(t, root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}

	want := map[string]struct {
		text, structure string
		line            int
	}{
		"PreToolUse": {`eval \"printf inspected\"`, "hook-command", 3},
		"Stop":       {`eval 'printf generated'`, "heredoc", 4},
	}
	for _, finding := range r.Findings {
		loc := finding.Location
		if finding.RuleID != "SH003" || loc.Derived {
			continue
		}
		if loc.Path != path {
			t.Fatalf("shell finding from unrelated input: %+v", loc)
		}
		if slices.Contains(finding.ContextSignals, check.ShellCommandText) {
			continue
		}
		entry, found := want[loc.HookEvent]
		if !found || loc.StartLine != entry.line || loc.Structure != entry.structure ||
			loc.ByteStart != strings.Index(config, entry.text) || config[loc.ByteStart:loc.ByteEnd] != entry.text {
			t.Fatalf("incorrect finding location: %+v", loc)
		}
		delete(want, loc.HookEvent)
	}
	if len(want) != 0 {
		t.Fatalf("missing hook findings: %+v", want)
	}
}

func TestHookEvalInSubstitutionsKeepsSourceEvidence(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, "p/.claude-plugin/plugin.json", `{"name":"example"}`)
	scenario.WriteFile(t, root, "p/hooks/hooks.json", `{"SessionStart":[{"hooks":[{"type":"command","command":"/bin/bash \"${CLAUDE_PLUGIN_ROOT}/start.sh\""}]}]}`)

	const input = `#!/bin/bash
if [[ -n "$(eval 'printf %s test')" ]]; then :; fi
value="${data:-$(eval 'printf %s fallback')}"
cat < <(eval 'printf %s process')
`

	scenario.WriteFile(t, root, "p/start.sh", input)

	result, err := scenario.Scan(t, root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}

	seen := make(map[int]bool)
	for _, finding := range result.Findings {
		if finding.RuleID == "SH003" && finding.Location.Path == "p/start.sh" && len(finding.HookSources) != 0 {
			seen[finding.Location.StartLine] = true
		}
	}

	for _, line := range []int{2, 3, 4} {
		if !seen[line] {
			t.Errorf("line %d missing a hook-linked eval finding", line)
		}
	}
}

func TestLiteralInlineHookHasShellCoverage(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, "p/.claude-plugin/plugin.json", `{"name":"example"}`)
	scenario.WriteFile(t, root, "p/hooks/hooks.json", `{"SessionStart":[{"hooks":[{"type":"command","command":"echo 'eval example'"}]}]}`)

	result, err := scenario.Scan(t, root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}

	coverage := result.Coverage.ShellHooks
	if coverage == nil || coverage.Completeness != report.Complete || len(coverage.Gaps) != 0 {
		t.Fatalf("incomplete inline shell handler coverage: %+v", coverage)
	}

	for _, finding := range result.Findings {
		if finding.RuleID == "SH003" {
			t.Fatalf("literal output was treated as a shell execution signal: %+v", finding.Location)
		}
	}
}
