//go:build !coreonly && cgo

package scout_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/python"
	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
	"github.com/skarm/scout/report"
)

func TestIsolatedPythonFileFilterCoverage(t *testing.T) {
	const program = `import json, sys
with open(sys.argv[1], encoding="utf-8", errors="ignore") as stream:
    text = stream.read(100)
    if stream.read(1):
        text += "…"
print(json.dumps({"context": "Prefix: " + text}))
`

	for _, tc := range []struct {
		name, command, body string
		file                bool
		complete            bool
	}{
		{name: "bounded read-only filter", command: "python3 -I -S - ./notes.txt", body: program, complete: true},
		{name: "captured isolated program", command: `python3 -I -B -S "$CLAUDE_PLUGIN_ROOT/filter.py" ./notes.txt`, body: program, file: true, complete: true},
		{name: "captured program with site enabled", command: `python3 -I -B "$CLAUDE_PLUGIN_ROOT/filter.py" ./notes.txt`, body: program, file: true},
		{name: "captured program with a dynamic argument list", command: `python3 -I -S "$CLAUDE_PLUGIN_ROOT/filter.py" "$@"`, body: program, file: true},
		{name: "captured program with an additional import", command: `python3 -I -S "$CLAUDE_PLUGIN_ROOT/filter.py" ./notes.txt`, body: "import pathlib\n" + program, file: true},
		{name: "site enabled", command: "python3 -I - ./notes.txt", body: program},
		{name: "write mode", command: "python3 -I -S - ./notes.txt", body: strings.Replace(program, `encoding="utf-8"`, `mode="w", encoding="utf-8"`, 1)},
		{name: "unbounded read", command: "python3 -I -S - ./notes.txt", body: strings.Replace(program, "read(100)", "read()", 1)},
		{name: "additional statement", command: "python3 -I -S - ./notes.txt", body: program + "print(input())\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
			scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/wrapper.sh\""}]}]}}`)
			wrapper := tc.command + " <<'PY'\n" + tc.body + "PY\n"
			if tc.file {
				wrapper = tc.command + "\n"
				scenario.WriteFile(t, root, "filter.py", tc.body)
			}

			scenario.WriteFile(t, root, "wrapper.sh", wrapper)

			config := scantest.DefaultConfig()
			config.Scanner = scout.DefaultOptions()
			result, err := scenario.Scanner(t, config).Scan(t.Context(), root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			coverage := result.Coverage.ShellHooks
			if coverage == nil || (coverage.Completeness == report.Complete) != tc.complete ||
				slices.Contains(coverage.Gaps, "hook_source_python_scope_unverified") == tc.complete {
				t.Fatalf("complete = %v, reported %+v", tc.complete, coverage)
			}
		})
	}
}

func TestIsolatedPythonJSONLinesCoverage(t *testing.T) {
	const program = `import json, sys
count = 0
with open(sys.argv[1], "r") as stream:
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if item.get("type") != "message":
                continue
            content = item.get("data", {}).get("content", "")
            if isinstance(content, str):
                count += 1
        except (json.JSONDecodeError, AttributeError):
            pass
print(count)
`

	for _, tc := range []struct {
		name, body string
		complete   bool
	}{
		{name: "count decoded rows", body: program, complete: true},
		{name: "dynamic decoder", body: strings.Replace(program, "json.loads(line)", "json.loads(line, object_hook=str)", 1)},
		{name: "change counter type", body: strings.Replace(program, "count += 1", "count += content", 1)},
		{name: "dynamic path", body: strings.Replace(program, "sys.argv[1]", "input()", 1)},
		{name: "dynamic comparison", body: strings.Replace(program, `!= "message"`, "!= input()", 1)},
		{name: "chained comparison", body: strings.Replace(program, `!= "message"`, `!= "message" != "other"`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
			scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/wrapper.sh\""}]}]}}`)
			scenario.WriteFile(t, root, "wrapper.sh", "python3 -I -S - ./events.jsonl <<'PY'\n"+tc.body+"PY\n")

			config := scantest.DefaultConfig()
			config.Scanner = scout.DefaultOptions()
			result, err := scenario.Scanner(t, config).Scan(t.Context(), root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			coverage := result.Coverage.ShellHooks
			if coverage == nil || (coverage.Completeness == report.Complete) != tc.complete ||
				slices.Contains(coverage.Gaps, "hook_source_python_scope_unverified") == tc.complete {
				t.Fatalf("complete = %v, reported %+v", tc.complete, coverage)
			}
		})
	}
}

func TestIsolatedInlinePythonHookCoverage(t *testing.T) {
	const jsonProgram = `'import json, sys; d = json.load(sys.stdin); print(d.get("tool_input", {}).get("file_path", ""))'`

	for _, tc := range []struct {
		name, command, setup string
		complete             bool
	}{
		{name: "isolated JSON fields", command: "python3 -I -S -c " + jsonProgram, complete: true},
		{name: "JSON here string", command: "python3 -I -S -c " + jsonProgram + ` <<< "$input" 2>/dev/null`, complete: true},
		{name: "reversed flags", command: `python3 -S -I -c 'import sys; import json; print(json.load(sys.stdin).get("name"))'`, complete: true},
		{name: "site enabled", command: "python3 -I -c " + jsonProgram},
		{name: "nonisolated imports", command: "python3 -S -c " + jsonProgram},
		{name: "other import", command: `python3 -I -S -c 'import json, sys, pathlib; print(json.load(sys.stdin))'`},
		{name: "argument to program", command: "python3 -I -S -c " + jsonProgram + " arg"},
		{name: "custom decoder", command: `python3 -I -S -c 'import json, sys; print(json.load(sys.stdin, object_hook=str))'`},
		{name: "wrapped launch", command: "env python3 -I -S -c " + jsonProgram},
		{name: "JSON fallback catches decode errors", command: `python3 -I -S -c 'import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get("value", ""))
except (json.JSONDecodeError, KeyError):
    pass'`, complete: true},
		{name: "JSON exception runs another callback", command: `python3 -I -S -c 'import json, sys
try:
    print(json.load(sys.stdin).get("value", ""))
except Exception:
    input()'`},
		{name: "nested JSON object type guard", command: `python3 -I -S -c 'import json, sys
d = json.load(sys.stdin)
m = d.get("message", {})
print(m.get("type", "") if isinstance(m, dict) else "")'`, complete: true},
		{name: "overwritten JSON type guard", command: `python3 -I -S -c 'import json, sys
dict = json.load(sys.stdin)
print(dict.get("value", "") if isinstance(dict, dict) else "")'`},
		{name: "UTC timestamp", command: `python3 -I -S -c 'from datetime import datetime; print(datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))'`, complete: true},
		{name: "UTC day offset", command: `python3 -I -S -c 'from datetime import datetime, timedelta; print((datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d"))'`, complete: true},
		{name: "UTC nonliteral format", command: `python3 -I -S -c 'from datetime import datetime; print(datetime.utcnow().strftime(input()))'`},
		{name: "UTC import alias", command: `python3 -I -S -c 'from datetime import date as datetime; print(datetime.utcnow().strftime("%Y-%m-%d"))'`},
		{name: "JSON serializer", command: `python3 -I -S -c 'import json, sys; print(json.dumps({"outer": {"inner": sys.argv[1]}}))' "$input"`, complete: true},
		{name: "JSON serializer missing argument", command: `python3 -I -S -c 'import json, sys; print(json.dumps({"value": sys.argv[2]}))' "$input"`},
		{name: "JSON serializer expanded argument list", command: `python3 -I -S -c 'import json, sys; print(json.dumps({"value": sys.argv[1]}))' "$@"`},
		{name: "JSON serializer expanded array", command: `python3 -I -S -c 'import json, sys; print(json.dumps({"value": sys.argv[1]}))' "${items[@]}"`},
		{name: "JSON serializer dynamic argument index", command: `python3 -I -S -c 'import json, sys; print(json.dumps({"value": sys.argv[int(input())]}))' "$input"`},
		{name: "JSON serializer callback", command: `python3 -I -S -c 'import json, sys; print(json.dumps({"value": sys.argv[1]}, default=str))' "$input"`},
		{
			name: "embedded leaf at the shell depth limit",
			setup: `one() { two; }
two() { three; }
three() { four; }
four() { five; }
five() { python3 -I -S -c ` + jsonProgram + `; }
`,
			command: "one", complete: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
			scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/wrapper.sh\""}]}]}}`)
			scenario.WriteFile(t, root, "wrapper.sh", tc.setup+"input=$(cat)\nprintf '%s' \"$input\" | "+tc.command+"\n")

			config := scantest.DefaultConfig()
			config.Scanner = scout.DefaultOptions()
			result, err := scenario.Scanner(t, config).Scan(t.Context(), root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			coverage := result.Coverage.ShellHooks
			if coverage == nil || (coverage.Completeness == report.Complete) != tc.complete ||
				slices.Contains(coverage.Gaps, "hook_source_python_scope_unverified") == tc.complete {
				t.Fatalf("complete = %v, reported %+v", tc.complete, coverage)
			}
		})
	}
}

func TestPythonHookStdinProgramCoverage(t *testing.T) {
	const body = "import subprocess\nsubprocess.run('printf ready', shell=True)"

	for _, tc := range []struct {
		name, launch, delimiter string
		projected               bool
	}{
		{name: "implicit stdin", launch: "python3", delimiter: "'PY'", projected: true},
		{name: "explicit stdin", launch: "python3 -I -S -", delimiter: "'PY'", projected: true},
		{name: "shell expands input", launch: "python3 -", delimiter: "PY"},
		{name: "stdin remains data", launch: "python3 -I -S -c 'print(1)'", delimiter: "'PY'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
			scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/wrapper.sh\""}]}]}}`)
			scenario.WriteFile(t, root, "wrapper.sh", tc.launch+" <<"+tc.delimiter+"\n"+body+"\nPY\n")

			config := scantest.DefaultConfig()
			config.Scanner = scout.DefaultOptions()
			result, err := scenario.Scanner(t, config).Scan(t.Context(), root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			coverage := result.Coverage.ShellHooks
			if coverage == nil || !slices.Contains(coverage.Gaps, "hook_source_python_scope_unverified") {
				t.Fatalf("missing gap for unverified Python launch: %+v", coverage)
			}

			projected := slices.ContainsFunc(result.Findings, func(f report.Finding) bool {
				return f.RuleID == python.HookShellCommandRule && f.Location.Path == "wrapper.sh" &&
					f.Location.StartLine == 3 && len(f.HookSources) == 1
			})
			if projected != tc.projected {
				t.Fatalf("mapped Python input = %v, want %v", projected, tc.projected)
			}
		})
	}
}

func TestHookDirectPythonShebang(t *testing.T) {
	for _, executable := range []bool{false, true} {
		root := t.TempDir()
		scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
		scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"\"${CLAUDE_PLUGIN_ROOT}/handler.py\""}]}]}}`)
		scenario.WriteFile(t, root, "handler.py", "#!/usr/bin/env python3\nimport subprocess\nsubprocess.run('printf ready', shell=True)\n")
		if executable {
			if err := os.Chmod(filepath.Join(root, "handler.py"), 0o755); err != nil {
				t.Fatal(err)
			}
		}

		result, err := scenario.Scanner(t, scantest.FullConfig()).Scan(t.Context(), root)
		if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
			t.Fatal(err)
		}

		linked := false
		for _, finding := range result.Findings {
			if finding.Location.Path == "handler.py" && finding.RuleID == python.HookShellCommandRule &&
				slices.Contains(finding.ContextSignals, check.ShellCommandText) && len(finding.HookSources) == 1 {
				linked = finding.HookSources[0].Event == "Stop"
			}
		}

		if linked != executable {
			t.Fatalf("linked direct Python command = %v with executable bit %v", linked, executable)
		}
	}
}

func TestHookPythonLauncherLinksShellCommandText(t *testing.T) {
	for _, tc := range []struct {
		name, wrapper string
		want          bool
	}{
		{name: "interpreter selection", wrapper: `case "$1" in *.py) ;; *) exit 0 ;; esac
for interpreter in python3.12 python3; do
  if "$interpreter" -c 'import sys; sys.exit(0)' 2>/dev/null; then
    exec "$interpreter" "$1"
  fi
done`, want: true},
		{name: "uv script", wrapper: `for runner in "$(command -v uv)" /usr/local/bin/uv; do
  if [ -x "$runner" ]; then
    exec "$runner" run --no-project --python 3.12 "$1"
  fi
done`, want: true},
		{name: "shadowed interpreter", wrapper: "python3() { :; }\npython3 \"$1\""},
		{name: "inline interpreter", wrapper: `python3 -c "$1"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
			scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"sh \"${CLAUDE_PLUGIN_ROOT}/wrap.sh\" \"${CLAUDE_PLUGIN_ROOT}/handler.py\""}]}]}}`)
			scenario.WriteFile(t, root, "wrap.sh", tc.wrapper+"\n")
			scenario.WriteFile(t, root, "handler.py", `import subprocess as sp
sp.Popen("printf ready", shell=True)
sp.run(["adb", "-s", input(), "shell", "echo", "ready"])
sp.run(["adb", "devices"])
sp.run(["echo", "shell", "ready"])
sp.run(["adb", "shell", "echo"], executable="echo")
sp.run(["echo", "ready"], shell=False)
sp.Popen("printf ready", shell=True, executable="printf")
sp.run(args=["adb", "shell", "echo"])
`)

			result, err := scenario.Scanner(t, scantest.FullConfig()).Scan(t.Context(), root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			lines := []int{}
			for _, f := range result.Findings {
				if f.RuleID != python.HookShellCommandRule || f.Location.Path != "handler.py" ||
					!slices.Contains(f.ContextSignals, check.ShellCommandText) {
					continue
				}

				lines = append(lines, f.Location.StartLine)
				linked := false
				for _, h := range f.HookSources {
					linked = linked || h.Event == "Stop" && len(h.Steps) == 2 &&
						h.Steps[0].Path == "hooks/hooks.json" && h.Steps[1].Path == "wrap.sh"
				}
				if linked != tc.want {
					t.Fatalf("linked Python command = %v, want %v: %+v", linked, tc.want, f)
				}
			}
			slices.Sort(lines)
			if !slices.Equal(lines, []int{2, 3, 9}) {
				t.Fatalf("shell command evidence at lines %v, want [2 3 9]", lines)
			}
		})
	}
}

func TestHookInlineRuntimeMapsLiteralPrograms(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
	scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/wrapper.sh\""}]}]}}`)
	scenario.WriteFile(t, root, "wrapper.sh", `python3 -c 'import subprocess
try:
    subprocess.run("printf ready", shell=True)
except ValueError:
    pass'
	node -e 'require("child_process").execSync("printf ready")' -- "$1"
program='import subprocess; subprocess.run("printf unknown", shell=True)'
python3 -c "$program"
python3() { :; }
python3 -c 'import subprocess; subprocess.run("printf shadowed", shell=True)'
`)

	result, err := scenario.Scanner(t, scantest.FullConfig()).Scan(t.Context(), root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}

	lines := map[string][]int{}
	for _, finding := range result.Findings {
		if finding.Location.Path != "wrapper.sh" ||
			!slices.Contains(finding.ContextSignals, check.ShellCommandText) {
			continue
		}

		if finding.Location.Structure != document.OriginHookInlineRuntime || len(finding.HookSources) != 1 ||
			finding.HookSources[0].Event != "Stop" || len(finding.HookSources[0].Steps) != 2 {
			t.Fatalf("incorrect inline program evidence: %+v", finding)
		}

		lines[finding.RuleID] = append(lines[finding.RuleID], finding.HookSources[0].Steps[1].StartLine, finding.Location.StartLine)
	}

	if len(lines) != 2 || !slices.Equal(lines[python.HookShellCommandRule], []int{1, 3}) ||
		!slices.Equal(lines["JS001"], []int{6, 6}) {
		t.Fatalf("inline program findings: %v", lines)
	}
}

func TestHookInlineRuntimeThroughExec(t *testing.T) {
	const body = `'import subprocess; subprocess.run("printf ready", shell=True)'`

	for _, tc := range []struct {
		name, prefix string
		want         bool
	}{
		{name: "exec replaces the shell", prefix: "exec python3 -c ", want: true},
		{name: "exec with env", prefix: "exec -- env -i python3 -c ", want: true},
		{name: "interpreter option boundary", prefix: "exec python3 -- -c "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
			scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/wrapper.sh\""}]}]}}`)
			scenario.WriteFile(t, root, "wrapper.sh", tc.prefix+body+"\n"+`python3 -c 'import subprocess; subprocess.run("printf later", shell=True)'`+"\n")

			result, err := scenario.Scanner(t, scantest.FullConfig()).Scan(t.Context(), root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			var lines []int
			for _, f := range result.Findings {
				if f.Location.Path == "wrapper.sh" && f.RuleID == python.HookShellCommandRule && len(f.HookSources) != 0 {
					lines = append(lines, f.Location.StartLine)
				}
			}

			if tc.want && !slices.Equal(lines, []int{1}) || !tc.want && slices.Contains(lines, 1) {
				t.Fatalf("linked inline Python at %v, want first line only: %v", lines, tc.want)
			}
		})
	}
}
