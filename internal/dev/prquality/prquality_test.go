package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPRQualityReviewFindsWeakenedChecks(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	gitTest(t, "init", "--quiet")
	gitTest(t, "config", "user.email", "pr-quality@example.invalid")
	gitTest(t, "config", "user.name", "PR Quality Test")
	gitTest(t, "config", "commit.gpgsign", "false")
	gitTest(t, "config", "core.symlinks", "false")
	gitTest(t, "config", "core.hooksPath", filepath.Join(dir, "no-hooks"))
	writeFile(t, "scanner_test.go", `package scanner
import "testing"
func TestRemoved(t *testing.T) {}
func TestScanner(t *testing.T) {
	t.Run("benign description", func(t *testing.T) {})
	t.Run("still here", func(t *testing.T) {
		if testing.Short() { t.SkipNow() }
		got, want := "actual", "expected"
		if got != want { t.Fatal("different result") }
	})
}
`)
	writeFile(t, "scanner.go", "package scanner\nvar count = 1\n")
	writeFile(t, "stable_test.go", "package scanner\nimport \"testing\"\nfunc TestStable(t *testing.T) {}\n")
	writeFile(t, "replaced_test.go", "package scanner\nimport \"testing\"\nfunc TestReplacedBySymlink(t *testing.T) {}\n")
	writeFile(t, "testdata/security-corpus/packages.json", `{"cases":[{"id":"benign-fixture","label":"benign"},{"id":"still-benign","label":"benign"}]}`)
	writeFile(t, "testdata/production-replay/cases.json", `{"cases":[{"id":"runner","forbidden_rules":["RULE1","RULE2"]}]}`)
	writeFile(t, ".github/workflows/ci.yml", `on:
  pull_request:
jobs:
  test:
    steps:
      - name: Go suite
        run: |
          go test ./...
          make host-test race
      - name: Evaluate
        run: |
          "$RUNNER_TEMP/scout-dev" evaluate --min-recall 0.9 --max-fpr=0.05 --max-incomplete 1
          jq -e '.metrics | .complete_negative_benign >= 2 and .false_positive_benign == 0'
`)
	save(t)
	base := gitTest(t, "rev-parse", "HEAD")

	writeFile(t, "scanner_test.go", `//go:build special

package scanner
import "testing"
func TestScanner(t *testing.T) {
	// t.Skip("this comment is not a skip")
	t.Run("still here", func(t *testing.T) {
		t.SkipNow()
		got := "actual"
		if got == "" { t.Fatal("missing result") }
	})
}
`)
	writeFile(t, "scanner.go", "package scanner\nvar count = 1 //nolint:unused\n")
	writeFile(t, "testdata/security-corpus/packages.json", `{"cases":[{"id":"benign-fixture","label":"ambiguous"},{"id":"still-benign","label":"benign"}]}`)
	writeFile(t, "testdata/production-replay/cases.json", `{"cases":[{"id":"runner","forbidden_rules":["RULE2"]}]}`)
	writeFile(t, ".github/workflows/ci.yml", `on:
  push:
jobs:
  test:
    steps:
      - name: Go suite
        if: ${{ false }}
        run: |
          go test -skip 'TestScanner' ./...
          make race
      - name: Evaluate
        run: |
          "$RUNNER_TEMP/scout-dev" evaluate --min-recall=0.8 --max-fpr 0.06 --max-incomplete 0
          jq -e '.metrics | .complete_negative_benign >= 1 and .false_positive_benign <= 0'
`)
	writeFile(t, "replaced_test.go", "stable_test.go")
	gitTest(t, "add", "--all")
	link := gitTest(t, "rev-parse", ":replaced_test.go")
	gitTest(t, "update-index", "--cacheinfo", "120000,"+link+",replaced_test.go")
	gitTest(t, "commit", "--quiet", "-m", "test revision")
	head := gitTest(t, "rev-parse", "HEAD")

	// The base branch advances independently. These base-only changes are not PR removals.
	gitTest(t, "checkout", "--quiet", "--detach", base)
	writeFile(t, "stable_test.go", "package scanner\nimport \"testing\"\nfunc TestStable(t *testing.T) {}\nfunc TestBaseOnly(t *testing.T) {}\n")
	save(t)
	advancedBase := gitTest(t, "rev-parse", "HEAD")

	var out bytes.Buffer
	const summary = "summary.md"
	if err := run(t.Context(), []string{"-github", "-summary", summary, advancedBase, head}, &out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("**Negative control removed**")) || !bytes.Contains(data, []byte("(base)")) {
		t.Fatalf("missing removed controls in check summary:\n%s", data)
	}
	for _, want := range []string{
		"Negative control removed", "benign-fixture", "benign description", "runner forbids RULE1",
		"Test removed from run", "TestRemoved", "TestReplacedBySymlink",
		"Test can now be skipped", "TestScanner/still here",
		"Test assertion weakened", "file=scanner.go,title=Go lint suppression added,line=2",
		"Go test build selection changed", "PR test trigger removed",
		"Test run removed or narrowed", "host-test", "selection for \"./...\"",
		"Quality threshold weakened", "--min-recall", "--max-fpr", ".complete_negative_benign",
		"Quality threshold removed", ".false_positive_benign",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, &out)
		}
	}
	for _, unwanted := range []string{"TestBaseOnly", "still-benign", "RULE2", "--max-incomplete", "comment is not a skip"} {
		if strings.Contains(out.String(), unwanted) {
			t.Errorf("unexpected %q in:\n%s", unwanted, &out)
		}
	}
}

func TestBroaderTestCommandsAndFormattingDoNotWarn(t *testing.T) {
	before, after := newInventory(), newInventory()
	if err := before.readMakefile("Makefile", "test:\n\t$(GO) test -run '^Test' ./scanner/...\n\tjq -e '.failures == 0 and .recall >= 0.9'\n"); err != nil {
		t.Fatal(err)
	}
	if err := after.readMakefile("Makefile", "test:\n\t$(GO) test ./...\n\tjq -e '.failures==0 and .recall>0.9'\n"); err != nil {
		t.Fatal(err)
	}
	if got := compareInventories(before, after); len(got) != 0 {
		t.Fatalf("stronger equivalent run raised warnings: %+v", got)
	}
}

func TestShellCommandsReadQuotedArgumentsWithoutMatchingExamples(t *testing.T) {
	i := newInventory()
	key := commandKey{"ci.yml", "tests"}
	found, err := i.readShell(key, 10, `echo 'go test -skip TestExample ./...'
# jq -e '.recall > 0.99'
go test -run='^Test one|Test two$' ./... && node --test --test-skip-pattern "slow case" adapter.mjs
jq -e '"inside string .recall > 1" and .metrics.recall>9e-1 and .slack <= -0.1 # .unused < 0
'
`, "")
	if err != nil || !found {
		t.Fatalf("test commands were not parsed: %v", err)
	}
	commands := i.commands[key]
	if len(commands) != 2 || strings.Join(commands[0].filters, ",") != "-run=^Test one|Test two$" ||
		strings.Join(commands[1].filters, ",") != "--test-skip-pattern=slow case" {
		t.Fatalf("incorrect quote or command handling: %+v", commands)
	}
	recall := i.gates[gateKey{key.path, key.scope, ".metrics.recall", true}]
	slack := i.gates[gateKey{key.path, key.scope, ".slack", false}]
	if len(i.gates) != 2 || len(recall) != 1 || len(slack) != 1 || recall[0].value != 0.9 ||
		slack[0].value != -0.1 {
		t.Fatalf("incorrect jq thresholds: %+v", i.gates)
	}
}

func TestIndependentJQGatesAndOptions(t *testing.T) {
	before, after := newInventory(), newInventory()
	key := commandKey{"ci.yml", "tests"}
	base := `jq --argjson ignored 2 --exit-status '.recall >= 0.95' first.json
jq -L scripts -e -- '.recall >= 0.9' second.json
jq -e '.computed > 0.5 + $offset'
jq -ef program.jq input.json
`
	if _, err := before.readShell(key, 20, base, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := after.readShell(key, 20, strings.Replace(base, ">= 0.9'", ">= 0.8'", 1), ""); err != nil {
		t.Fatal(err)
	}
	warnings := compareInventories(before, after)
	if len(before.gates) != 1 || len(warnings) != 1 || warnings[0].category != "Quality threshold weakened" ||
		warnings[0].line != 21 || !strings.Contains(warnings[0].detail, "from >= 0.9 to >= 0.8") {
		t.Fatalf("lost an independent gate or treated a computed comparison as literal: %+v, %+v", before.gates, warnings)
	}
}

func TestNarrowedTestInvocations(t *testing.T) {
	key := commandKey{"ci.yml", "tests"}
	for _, tc := range []struct {
		before, after string
		narrowed      bool
	}{
		{"go test ./...", "go test -short ./...", true},
		{"go test ./...", "go test -short -short=false ./...", false},
		{"go test -run '^Test Foo$' ./...", `go test -run=^Test\ Foo$ ./...`, false},
		{"go test ./...", "go test -list '.' ./...", true},
		{"go test ./...", "go test -c ./...", true},
		{"go test ./...", "go test -n ./...", true},
		{"go test ./...", "go test -count=0 ./...", true},
		{"go test ./...", "go test ./... -args -test.count -1", true},
		{"go test ./...", "go test -count=0 -count=2 ./...", false},
		{"go test example.org/scout/a example.org/scout/b", "go test -timeout 30s example.org/scout/b", true},
		{"go -C ./tools test ./...", "go -C=./tools test -count 2 ./...", false},
		{"node --test host_test.mjs", "node --test-name-pattern 'fast tests' --test host_test.mjs", true},
		{"node --test host_test.mjs", "node --test --test-only host_test.mjs", true},
	} {
		t.Run(tc.after, func(t *testing.T) {
			before, after := newInventory(), newInventory()
			if _, err := before.readShell(key, 1, tc.before, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := after.readShell(key, 1, tc.after, ""); err != nil {
				t.Fatal(err)
			}
			warnings := compareInventories(before, after)
			if (len(warnings) > 0) != tc.narrowed {
				t.Fatalf("unexpected warnings: %+v", warnings)
			}
		})
	}
}

func TestGitHubExpressionsPreserveCommandAndFilterIdentity(t *testing.T) {
	key := commandKey{"ci.yml", "tests"}
	before, after := newInventory(), newInventory()
	script := "go test -run=${{ format('}}{0}',\n matrix.filter) }} ./...\ngo test ./separate"
	for _, item := range []struct {
		inv  inventory
		text string
	}{{before, script}, {after, strings.Replace(script, "matrix.filter", "matrix.narrower", 1)}} {
		if _, err := item.inv.readShell(key, 30, maskExpressions(item.text), ""); err != nil {
			t.Fatal(err)
		}
		cmds := item.inv.commands[key]
		if len(cmds) != 2 || cmds[0].line != 30 || len(cmds[0].filters) != 1 || cmds[1].line != 32 {
			t.Fatalf("expression split a shell command or lost its coordinates: %+v", cmds)
		}
	}
	if warnings := compareInventories(before, after); len(warnings) != 1 {
		t.Fatalf("changed expression filter went unreported: %+v", warnings)
	}
}

func TestMovedGoTestPlatformSelection(t *testing.T) {
	const test = "package scout\nimport \"testing\"\nfunc TestProbe(t *testing.T) {}\n"
	for _, tc := range []struct{ filename, category string }{
		{"probe_linux_arm64_test.go", "Go test build selection changed"},
		{"_probe_test.go", "Test removed from run"},
		{"moved_test.go", ""},
	} {
		t.Run(tc.filename, func(t *testing.T) {
			before, after := newInventory(), newInventory()
			if err := before.readGoTests("probe_test.go", []byte(test)); err != nil {
				t.Fatal(err)
			}
			if err := after.readGoTests(tc.filename, []byte(test)); err != nil {
				t.Fatal(err)
			}
			warnings := compareInventories(before, after)
			if tc.category == "" {
				if len(warnings) != 0 {
					t.Fatalf("mere rename changed test selection: %+v", warnings)
				}
			} else if len(warnings) != 1 || warnings[0].category != tc.category {
				t.Fatalf("test selection change went unreported: %+v", warnings)
			}
		})
	}
}

func TestWorkflowUsesRunnerShellAndReportsDisabledEvaluation(t *testing.T) {
	i := newInventory()
	err := i.readWorkflow(".github/workflows/eval.yml", []byte(`on: pull_request
jobs:
  windows:
    runs-on: windows-latest
    steps:
      - run: if ($false) { Write-Output "PowerShell" }
  gate:
    if: false
    steps:
      - run: jq -e '.recall >= 0.9'
`))
	if err != nil {
		t.Fatal(err)
	}
	if coverage := i.workflows[".github/workflows/eval.yml"]; coverage.triggerLine == 0 || !coverage.runsChecks || len(i.gates) != 1 || len(i.skips) != 1 {
		t.Fatalf("workflow metadata lost: %+v", i)
	}
}

func TestWorkflowDistinguishesDisabledTestsFromRemovedPRTrigger(t *testing.T) {
	const name = ".github/workflows/ci.yml"
	const source = "on: pull_request\njobs:\n  scan:\n    steps:\n      - run: go test ./...\n"
	before := newInventory()
	if err := before.readWorkflow(name, []byte(source)); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ from, to, category string }{
		{"go test ./...", "go test -count=0 ./...", "Test run removed or narrowed"},
		{"on: pull_request", "on: push", "PR test trigger removed"},
	} {
		after := newInventory()
		if err := after.readWorkflow(name, []byte(strings.Replace(source, tc.from, tc.to, 1))); err != nil {
			t.Fatal(err)
		}
		if warnings := compareInventories(before, after); len(warnings) != 1 || warnings[0].category != tc.category {
			t.Fatalf("unexpected workflow warnings: %+v", warnings)
		}
	}
}

func TestWorkflowWorkingDirectoryAffectsTestSelection(t *testing.T) {
	const workflow = `on: pull_request
defaults:
  run:
    working-directory: modules
jobs:
  scan:
    defaults:
      run:
        working-directory: modules/scanner
    steps:
      - name: Go
        run: go -C child test ./...
      - name: Node
        working-directory: ui
        run: node --test smoke.mjs
  fallback:
    steps:
      - run: go test ./...
`
	for _, tc := range []struct {
		name, from, to string
		want           int
	}{
		{"job directory changed", "modules/scanner", "modules/other", 1},
		{"step directory changed", "working-directory: ui", "working-directory: extension", 1},
		{"workflow directory changed", "working-directory: modules\n", "working-directory: packages\n", 1},
		{"equivalent Go directory", "modules/scanner", "./modules/tmp/../scanner", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := newInventory(), newInventory()
			const name = ".github/workflows/ci.yml"
			if err := before.readWorkflow(name, []byte(workflow)); err != nil {
				t.Fatal(err)
			}
			if err := after.readWorkflow(name, []byte(strings.Replace(workflow, tc.from, tc.to, 1))); err != nil {
				t.Fatal(err)
			}
			if warnings := compareInventories(before, after); len(warnings) != tc.want ||
				tc.want != 0 && warnings[0].category != "Test run removed or narrowed" {
				t.Fatalf("unexpected workflow warnings: %+v", warnings)
			}
		})
	}
}

func TestNewGoTestsWithGuardsDoNotCountAsLostCoverage(t *testing.T) {
	const base = `package scanner
import "testing"
func TestExisting(t *testing.T) {}
`
	const head = `package scanner
import "testing"
func TestExisting(t *testing.T) { if testing.Short() { t.Skip("short") } }
func TestNew(t *testing.T) { if testing.Short() { t.Skip("short") } }
`
	before, after := newInventory(), newInventory()
	if err := before.readGoTests("scan_test.go", []byte(base)); err != nil {
		t.Fatal(err)
	}
	if err := after.readGoTests("scan_test.go", []byte(head)); err != nil {
		t.Fatal(err)
	}
	if warnings := compareInventories(before, after); len(warnings) != 1 || warnings[0].category != "Test can now be skipped" ||
		!strings.Contains(warnings[0].detail, "TestExisting") {
		t.Fatalf("expected a warning for only the previously running test: %+v", warnings)
	}
}

func TestRepositoryCommandSourcesParse(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	i := newInventory()
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if err := i.readMakefile("Makefile", string(makefile)); err != nil {
		t.Fatal(err)
	}

	workflows, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil || len(workflows) == 0 {
		t.Fatalf("cannot find repository workflows: %v", err)
	}
	for _, name := range workflows {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := i.readWorkflow(name, data); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGitHubWarningsEscapeUntrustedValues(t *testing.T) {
	var out bytes.Buffer
	err := writeWarning(&out, warning{location{"comma,path:here", 5}, false, "title", "text\n::error::hidden%\r"}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := "::warning file=comma%2Cpath%3Ahere,title=title,line=5::text%0A::error::hidden%25%0D\n"
	if out.String() != want {
		t.Fatalf("annotation did not escape workflow command syntax: %q", out.String())
	}
}

func writeFile(t testing.TB, name, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func save(t testing.TB) {
	t.Helper()
	gitTest(t, "add", "--all")
	gitTest(t, "commit", "--quiet", "-m", "test revision")
}

func gitTest(t testing.TB, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %s (%v)", args, out, err)
	}
	return strings.TrimSpace(string(out))
}
