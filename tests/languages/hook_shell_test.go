package scout_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
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
		if loc.HookEvent == "PreToolUse" && strings.HasPrefix(input[loc.ByteStart:loc.ByteEnd], "bash -c") {
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
		delete(want, loc.HookEvent)
	}
	if len(want) > 0 {
		t.Fatalf("missing findings: %+v", want)
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
		if strings.HasPrefix(config[loc.ByteStart:loc.ByteEnd], "bash -o") {
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
