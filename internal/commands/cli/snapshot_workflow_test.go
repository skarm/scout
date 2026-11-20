package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
	"github.com/skarm/scout/report"
)

type usableComparison struct {
	Before   string          `json:"before_sha256"`
	After    string          `json:"after_sha256"`
	Decision report.Decision `json:"decision"`
	Roots    []struct {
		ID, Change string
		BeforePath string `json:"before_path"`
		AfterPath  string `json:"after_path"`
		Content    []struct {
			Path, Explanation, Excerpt string
			AddedLines                 int  `json:"added_lines"`
			RemovedLines               int  `json:"removed_lines"`
			DiffOmitted                bool `json:"diff_omitted"`
		} `json:"content_changes"`
	} `json:"roots"`
	Relationships struct {
		Completeness                       report.Completeness
		Introduced, Persistent, Unverified int
		NotObserved                        int `json:"not_observed"`
		Changes                            []struct{ Change, Kind string }
	} `json:"relationships"`
	Previous *report.Document `json:"previous_environment"`
	Current  *report.Document `json:"environment"`
}

func comparisonResult(t *testing.T, data []byte) usableComparison {
	t.Helper()
	var result usableComparison
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid comparison: %v", err)
	}
	return result
}

func TestSnapshotDiscoverRepeatDetectsNewAndRemovedComponents(t *testing.T) {
	home := t.TempDir()
	checkpoint := filepath.Join(t.TempDir(), "saved.json")
	first := discoverySkill(t, home, "first", "# First helper\nSummarize local text.\n")
	args := []string{"discover", "--home", home, "--agent", "codex", "--system=false", "--no-project", "--kind", "skill", "--snapshot", checkpoint, "--", "--profile", "custom", "--checks", "none", "--format", "json"}
	if code, _ := runCheckpoint(t, args); code != 0 {
		t.Fatal("discovery snapshot failed", code)
	}
	// A later command must not inherit new process home overrides or cwd.
	other := t.TempDir()
	discoverySkill(t, other, "unrelated", "Private unrelated source")
	t.Setenv("CODEX_HOME", other)
	code, out := runCheckpoint(t, checkpointArgs("compare", checkpoint))
	if code != 0 {
		t.Fatal("saved discovery did not repeat", code)
	}
	result := comparisonResult(t, out)
	if len(result.Roots) != 1 || result.Roots[0].Change != "unchanged" {
		t.Fatal("unstable root identity")
	}
	second := discoverySkill(t, home, "second", "# Second helper\nFormat local text.\n")
	if err := os.RemoveAll(filepath.Dir(first)); err != nil {
		t.Fatal(err)
	}
	code, out = runCheckpoint(t, checkpointArgs("compare", checkpoint))
	if code != 1 {
		t.Fatal("component change did not require review", code)
	}
	result = comparisonResult(t, out)
	added, removed := false, false
	for _, root := range result.Roots {
		for _, c := range root.Content {
			added = added || (strings.Contains(c.Path, "second") || strings.Contains(root.AfterPath, "second")) && root.Change != "removed"
			removed = removed || (strings.Contains(c.Path, "first") || strings.Contains(root.BeforePath, "first")) && c.Explanation != ""
		}
	}
	if !added || !removed || bytes.Contains(out, []byte("Private unrelated source")) {
		t.Fatal("new/removed skill not discovered or context expanded")
	}
	if err := os.RemoveAll(filepath.Dir(second)); err != nil {
		t.Fatal(err)
	}
	code, out = runCheckpoint(t, checkpointArgs("compare", checkpoint))
	if code != 1 {
		t.Fatal("empty discovered environment was not compared", code)
	}
	result = comparisonResult(t, out)
	if len(result.Roots) != 1 || result.Roots[0].Change != "removed" {
		t.Fatal("missing root not removed", result.Roots)
	}
	// Inspection must never emit source bytes.
	code, out = runCheckpoint(t, []string{"snapshot", "inspect", "--snapshot", checkpoint, "--format", "json"})
	if code != 0 || !json.Valid(out) || bytes.Contains(out, []byte("Summarize local text")) {
		t.Fatal("checkpoint preview failed")
	}
}

func TestSnapshotSavedManualPathsAndProtectedOutputs(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "SKILL.md")
	checkpoint := filepath.Join(t.TempDir(), "saved.json")
	if err := os.WriteFile(file, []byte("# Helper\nFormat local text.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := runCheckpoint(t, checkpointArgs("create", checkpoint, "--root", "helper="+root)); code != 0 {
		t.Fatal(code)
	}
	if code, _ := runCheckpoint(t, checkpointArgs("compare", checkpoint)); code != 0 {
		t.Fatal("manual paths not reused", code)
	}
	if code, _ := runCheckpoint(t, checkpointArgs("compare", checkpoint, "--output", file)); code != 2 {
		t.Fatal("overwrote saved source")
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	code, out := runCheckpoint(t, checkpointArgs("compare", checkpoint))
	if code != 1 || comparisonResult(t, out).Roots[0].Change != "removed" {
		t.Fatal("deleted saved root not removed", code)
	}
}

func TestSnapshotDiscoveryIncompleteAndProtectedLocations(t *testing.T) {
	home := t.TempDir()
	discoverySkill(t, home, "first", "# Helper\nFormat text.\n")
	checkpoint := filepath.Join(t.TempDir(), "saved.json")
	base := []string{"discover", "--home", home, "--agent", "codex", "--system=false", "--no-project", "--snapshot", checkpoint, "--", "--profile", "custom", "--checks", "none", "--format", "json"}
	if code, _ := runCheckpoint(t, base); code != 0 {
		t.Fatal(code)
	}
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(home, ".codex", "config.toml")
	if err := os.WriteFile(config, []byte("[invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := runCheckpoint(t, checkpointArgs("compare", checkpoint)); code != 2 || len(out) != 0 {
		t.Fatal("incomplete discovery was interpreted as removal")
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	// Protect known configuration locations, including paths outside selected scan roots.
	if code, _ := runCheckpoint(t, checkpointArgs("compare", checkpoint, "--output", filepath.Join(home, ".codex", "auth.json"))); code != 2 {
		t.Fatal("discovery protection was lost")
	}
}

func TestSnapshotRelationshipChangesUseStableRootsAndCoverage(t *testing.T) {
	base := t.TempDir()
	old := filepath.Join(base, "old")
	action := filepath.Join(base, "action")
	for _, root := range []string{old, action} {
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(old, "run.sh"), []byte("printf hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	actionFile := filepath.Join(action, "run.sh")
	if err := os.WriteFile(actionFile, []byte("kubectl --context local delete pod fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(base, "saved.json")
	roots := []string{"--scope", "selected", "--root", "reader=" + old, "--root", "writer=" + action}
	if code, _ := runCheckpoint(t, checkpointArgs("create", checkpoint, roots...)); code != 0 {
		t.Fatal(code)
	}
	if err := os.WriteFile(filepath.Join(old, "run.sh"), []byte("curl https://example.invalid/status\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := runCheckpoint(t, checkpointArgs("compare", checkpoint, roots...))
	result := comparisonResult(t, out)
	if code != 1 || result.Relationships.Introduced != 1 || result.Previous == nil || result.Current == nil {
		t.Fatalf("relationship introduction missing: code=%d delta=%+v", code, result.Relationships)
	}
	// Add an earlier root: target indexes change, evidence correspondence must not.
	persistent := filepath.Join(base, "persistent.json")
	if code, _ := runCheckpoint(t, checkpointArgs("create", persistent, roots...)); code != 1 {
		t.Fatal(code)
	}
	extra := filepath.Join(base, "extra.txt")
	if err := os.WriteFile(extra, []byte("Local notes."), 0o600); err != nil {
		t.Fatal(err)
	}
	withExtra := append(append([]string{}, roots...), "--root", "aaa="+extra)
	_, out = runCheckpoint(t, checkpointArgs("compare", persistent, withExtra...))
	result = comparisonResult(t, out)
	if result.Relationships.Persistent != 1 || result.Relationships.Introduced != 0 {
		t.Fatal("run-local target IDs changed relationship identity", result.Relationships)
	}
	if err := os.WriteFile(actionFile, []byte("printf hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out = runCheckpoint(t, checkpointArgs("compare", persistent, roots...))
	result = comparisonResult(t, out)
	if result.Relationships.NotObserved != 1 {
		t.Fatal("relationship disappearance missing", result.Relationships)
	}
	_, out = runCheckpoint(t, checkpointArgs("compare", persistent, append(append([]string{}, roots...), "--max-file-bytes", "1")...))
	result = comparisonResult(t, out)
	if result.Relationships.Completeness != report.Partial {
		t.Fatal("partial relationship coverage promoted to complete")
	}
}

func TestSnapshotSourceDiffIsExplicitBoundedAndEscaped(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "SKILL.md")
	checkpoint := filepath.Join(t.TempDir(), "saved.json")
	if err := os.WriteFile(file, []byte("# Helper\nOld private sentence.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := runCheckpoint(t, checkpointArgs("create", checkpoint, "--root", "helper="+root)); code != 0 {
		t.Fatal(code)
	}
	replacement := "# Helper\nNew private sentence with ``` and " + string(rune(27)) + ".\n"
	if err := os.WriteFile(file, []byte(replacement), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out := runCheckpoint(t, checkpointArgs("compare", checkpoint))
	if bytes.Contains(out, []byte("private sentence")) {
		t.Fatal("source diff enabled implicitly")
	}
	result := comparisonResult(t, out)
	content := result.Roots[0].Content[0]
	if content.AddedLines != 1 || content.RemovedLines != 1 || !strings.Contains(content.Explanation, "Agent instructions") {
		t.Fatal("unhelpful change summary", content)
	}
	_, out = runCheckpoint(t, checkpointArgs("compare", checkpoint, "--include-source-diff", "--format", "markdown"))
	if !bytes.Contains(out, []byte("Old private sentence")) || !bytes.Contains(out, []byte("````text")) || bytes.ContainsRune(out, rune(27)) {
		t.Fatal("source excerpt missing or unsafe")
	}
	if err := os.WriteFile(file, []byte(strings.Repeat("large replacement\n", 1000)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out = runCheckpoint(t, checkpointArgs("compare", checkpoint, "--include-source-diff"))
	result = comparisonResult(t, out)
	content = result.Roots[0].Content[0]
	if !content.DiffOmitted || len(content.Excerpt) > 64<<10 {
		t.Fatal("source diff budget ignored")
	}

	code, out := runCheckpoint(t, checkpointArgs("compare", checkpoint, "--include-source-diff", "--format", "markdown", "--max-file-bytes", "1"))
	if code != 2 || !bytes.Contains(out, []byte("Coverage is incomplete")) ||
		!bytes.Contains(out, []byte("Source excerpt omitted or truncated")) || bytes.Contains(out, []byte("analysis still covers captured content")) {
		t.Fatal("truncated excerpt misrepresents incomplete analysis coverage", code)
	}
}

func TestSnapshotLargeSupportedEnvironmentCanBeReopened(t *testing.T) {
	root := t.TempDir()
	checkpoint := filepath.Join(t.TempDir(), "saved.json")
	// This is within the documented entry/byte limits but produces more than the
	// original reader's 500,000 JSON value nodes once coverage evidence is included.
	for i := range 2500 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("note-%04d.txt", i)), []byte("Summarize local notes.\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code, _ := runCheckpoint(t, checkpointArgs("create", checkpoint, "--root", "notes="+root, "--output", filepath.Join(t.TempDir(), "report.json"))); code != 0 {
		t.Fatal("large supported snapshot creation failed", code)
	}
	code, out := runCheckpoint(t, []string{"snapshot", "inspect", "--snapshot", checkpoint, "--format", "json"})
	if code != 0 || !json.Valid(out) {
		t.Fatal("created snapshot cannot be reopened", code)
	}
	var summary struct{ Roots []struct{ Files int } }
	if err := json.Unmarshal(out, &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.Roots) != 1 || summary.Roots[0].Files != 2500 {
		t.Fatal("snapshot contents lost")
	}
	// Compare shares capture counts between both versions; explicitly budget
	// enough files for the pair instead of weakening the scanner's run limit.
	config := filepath.Join(t.TempDir(), "compare-config.json")
	if err := os.WriteFile(config, []byte(`{"schema":"scout.config/v1","limits":{"max_capture_files":8192,"max_capture_entries":16384}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := runCheckpoint(t, checkpointArgs("compare", checkpoint, "--config", config, "--output", filepath.Join(t.TempDir(), "comparison.json"))); code != 0 {
		t.Fatal("large snapshot cannot be compared", code)
	}
}

func TestSnapshotDiscoveryRejectsSelectionOverridesInScanFlags(t *testing.T) {
	home := t.TempDir()
	discoverySkill(t, home, "helper", "# Helper\nSummarize notes.\n")
	dir := t.TempDir()
	snapshot := filepath.Join(dir, "saved.json")
	other := filepath.Join(dir, "unexpected.json")
	for _, extra := range [][]string{{"--snapshot", other}, {"-snapshot=" + other}, {"--root", "unexpected=" + home}, {"--empty"}} {
		args := []string{"discover", "--home", home, "--agent", "codex", "--system=false", "--no-project", "--snapshot", snapshot, "--", "--profile", "custom", "--checks", "none"}
		code, _ := runCheckpoint(t, append(args, extra...))
		if code != 2 {
			t.Fatal("scanner arguments overrode discovery selection or checkpoint path", extra)
		}
		for _, path := range []string{snapshot, other} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("unexpected checkpoint published", path, err)
			}
		}
	}
}

func TestSnapshotReferenceUpdateLifecycle(t *testing.T) {
	home := t.TempDir()
	skill := discoverySkill(t, home, "helper", "# Helper\nSummarize notes.\n")
	dir := t.TempDir()
	old, candidate := filepath.Join(dir, "old.json"), filepath.Join(dir, "candidate.json")
	args := []string{"discover", "--home", home, "--agent", "codex", "--system=false", "--no-project", "--kind", "skill", "--snapshot", old, "--", "--profile", "custom", "--checks", "none", "--format", "json"}
	if code, _ := runCheckpoint(t, args); code != 0 {
		t.Fatal(code)
	}
	oldBytes, err := os.ReadFile(old)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(skill, []byte("# Helper\nSummarize notes and preserve their order.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := runCheckpoint(t, checkpointArgs("compare", old, "--save-candidate", candidate))
	if code != 1 {
		t.Fatal("changed environment did not require review", code)
	}
	live := comparisonResult(t, out)
	data, err := os.ReadFile(candidate)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Snapshot   struct{ Digest string }
		Inspection report.Document
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Snapshot.Digest != live.After || live.Current == nil || saved.Inspection.Run.Digest != live.Current.Run.Digest {
		t.Fatal("saved candidate differs from the compared bytes or inspection")
	}
	code, out = runCheckpoint(t, []string{"snapshot", "inspect", "--snapshot", candidate})
	if code != 0 || !bytes.Contains(out, []byte(`"--agent" "codex"`)) || !bytes.Contains(out, []byte(`"--kind" "skill"`)) || bytes.Contains(out, []byte("Summarize notes")) {
		t.Fatal("inspect does not show the saved context safely", code, string(out))
	}
	if code, _ := runCheckpoint(t, checkpointArgs("compare", candidate)); code != 0 {
		t.Fatal("saved candidate did not retain reusable discovery", code)
	}
	if err := os.RemoveAll(filepath.Dir(skill)); err != nil {
		t.Fatal(err)
	}
	code, out = runCheckpoint(t, checkpointArgs("compare", old, "--candidate", candidate))
	if code != 1 {
		t.Fatal("archived comparison depends on original sources", code)
	}
	archived := comparisonResult(t, out)
	if live.Before != archived.Before || live.After != archived.After || archived.Roots[0].Change != "modified" {
		t.Fatal("archived comparison does not reproduce the content delta")
	}
	unchanged, err := os.ReadFile(old)
	if err != nil || !bytes.Equal(unchanged, oldBytes) {
		t.Fatal("updating reference overwrote historical evidence", err)
	}
}

func TestSnapshotCandidateDestinationBoundaries(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("Local notes."), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	old, candidate := filepath.Join(dir, "old.json"), filepath.Join(dir, "candidate.json")
	if code, _ := runCheckpoint(t, checkpointArgs("create", old, "--root", "notes="+root)); code != 0 {
		t.Fatal(code)
	}
	for _, extra := range [][]string{
		{"--save-candidate", old},
		{"--save-candidate", filepath.Join(root, "new.json")},
		{"--save-candidate", candidate, "--report", "json=" + candidate},
		{"--candidate", old, "--root", "notes=" + root},
		{"--candidate", old, "--empty"},
		{"--candidate", old, "--save-candidate", candidate},
		{"--candidate", old, "--output", old},
	} {
		if code, _ := runCheckpoint(t, checkpointArgs("compare", old, extra...)); code != 2 {
			t.Fatal("accepted conflicting flags or destination", extra, code)
		}
	}
	if _, err := os.Stat(candidate); !os.IsNotExist(err) {
		t.Fatal("published a candidate for a rejected invocation", err)
	}
	// Retain partial evidence without turning it into a successful decision.
	if code, _ := runCheckpoint(t, checkpointArgs("compare", old, "--save-candidate", candidate, "--max-file-bytes", "1")); code != 2 {
		t.Fatal("partial inspection must keep exit code 2", code)
	}
	code, out := runCheckpoint(t, []string{"snapshot", "inspect", "--snapshot", candidate, "--format", "json"})
	if code != 0 || !bytes.Contains(out, []byte(`"inspection_state":"incomplete"`)) {
		t.Fatal("candidate did not preserve incomplete inspection", code, string(out))
	}
}

func TestSnapshotCaptureFailureReportsLocationAndLimit(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "too-large.txt")
	if err := os.WriteFile(input, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const limit = 4 << 20
	if err := os.Truncate(input, limit+1); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	checkpoint, failureReport := filepath.Join(dir, "saved.json"), filepath.Join(dir, "failure.json")
	var stdout, stderr bytes.Buffer
	args := checkpointArgs("create", checkpoint, "--root", "notes="+root, "--report", "json="+failureReport)
	if code := cli.Run(t.Context(), args, &stdout, &stderr); code != 2 {
		t.Fatal(code)
	}
	var failure struct {
		Schema, Operation string
		Code              int `json:"exit_code"`
		Problem           struct {
			Code, Root, Path, Unit string
			Limit, Actual          int
		}
	}
	if err := json.Unmarshal(stdout.Bytes(), &failure); err != nil {
		t.Fatal(err)
	}
	problem := failure.Problem
	if failure.Schema != "scout.environment-snapshot-error/v1" || failure.Operation != "create" || failure.Code != 2 ||
		problem.Code != "file_size_limit" || problem.Root != "notes" || filepath.Base(problem.Path) != "too-large.txt" ||
		problem.Unit != "bytes" || problem.Actual != limit+1 || problem.Limit != limit {
		t.Fatal("missing capture error information", failure)
	}
	if !strings.Contains(stderr.String(), "too-large.txt") || !strings.Contains(stderr.String(), "4194304") {
		t.Fatal("text diagnostic lacks file or limit", stderr.String())
	}
	data, err := os.ReadFile(failureReport)
	if err != nil || !bytes.Equal(data, stdout.Bytes()) {
		t.Fatal("JSON report destination did not receive the failure", err)
	}
	if _, err := os.Stat(checkpoint); !os.IsNotExist(err) {
		t.Fatal("created a checkpoint for a failed capture", err)
	}
}

func TestSnapshotSavedSourceReplacementDoesNotFollowNewSymlink(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent-replaced=%t", nested), func(t *testing.T) {
			dir := t.TempDir()
			replaced := filepath.Join(dir, "selected")
			root := replaced
			if nested {
				root = filepath.Join(replaced, "child")
			}
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("Local notes."), 0o600); err != nil {
				t.Fatal(err)
			}
			checkpoint := filepath.Join(dir, "saved.json")
			if code, _ := runCheckpoint(t, checkpointArgs("create", checkpoint, "--root", "notes="+root)); code != 0 {
				t.Fatal(code)
			}
			replacement := t.TempDir()
			newRoot := replacement
			if nested {
				newRoot = filepath.Join(replacement, "child")
				if err := os.Mkdir(newRoot, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(newRoot, "private.txt"), []byte("Unselected material."), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(replaced); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(replacement, replaced); err != nil {
				t.Skip("symlinks unavailable: ", err)
			}
			if code, out := runCheckpoint(t, checkpointArgs("compare", checkpoint)); code != 2 || len(out) != 0 {
				t.Fatal("saved path followed a replacement symlink", code)
			}
		})
	}
}

func TestSnapshotStandardDependencyManifestLifecycle(t *testing.T) {
	if !standardProfileAvailable() {
		t.Skip("standard profile requires native parser and signature capabilities")
	}
	root := t.TempDir()
	requirements := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(requirements, []byte("requests==2.32.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(t.TempDir(), "saved.json")
	args := func(mode string) []string {
		return []string{"snapshot", mode, "--snapshot", checkpoint, "--profile", "standard", "--scope", "selected", "--format", "json"}
	}
	if code, data := runCheckpoint(t, append(args("create"), "--root", "dependencies="+root)); code != 0 {
		var inspection report.Document
		if err := json.Unmarshal(data, &inspection); err != nil {
			t.Fatal(err)
		}
		for _, target := range inspection.Run.Targets {
			for _, diagnostic := range target.Analysis.Diagnostics {
				if diagnostic.AffectsScope {
					t.Log(diagnostic.Path, diagnostic.Code)
				}
			}
		}
		t.Fatal("supported dependency manifests made standard snapshot incomplete", code)
	}
	if code, _ := runCheckpoint(t, args("compare")); code != 0 {
		t.Fatal("unchanged dependency manifests could not be compared", code)
	}
	if err := os.WriteFile(requirements, []byte("requests==2.32.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := runCheckpoint(t, args("compare")); code != 1 || comparisonResult(t, out).Roots[0].Change != "modified" {
		t.Fatal("dependency version change not reported", code)
	}
	// A filename must not turn unresolved declarations into complete coverage.
	for _, content := range []string{"-r uncaptured.txt\n", "requests>=2.32.4\n"} {
		if err := os.WriteFile(requirements, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _ := runCheckpoint(t, args("compare")); code != 2 {
			t.Fatal("unresolved dependency inventory lost incomplete status", code)
		}
	}
}

func TestSnapshotRepeatDiscoveryReportsDeletedIncludedRoot(t *testing.T) {
	home := t.TempDir()
	const content = "# Selected\nSummarize local text.\n"
	gone := filepath.Dir(discoverySkill(t, home, "selected", content))
	discoverySkill(t, home, "remaining", "# Remaining\nFormat local text.\n")
	checkpoint := filepath.Join(t.TempDir(), "saved.json")
	args := []string{"discover", "--home", home, "--agent", "codex", "--system=false", "--no-project", "--include-path", gone, "--snapshot", checkpoint, "--", "--profile", "custom", "--checks", "none", "--format", "json"}
	if code, _ := runCheckpoint(t, args); code != 0 {
		t.Fatal("failed to create snapshot", code)
	}
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}

	code, out := runCheckpoint(t, checkpointArgs("compare", checkpoint))
	if code != 1 {
		t.Fatalf("expected deletion delta, got code %d: %s", code, out)
	}
	result := comparisonResult(t, out)
	if len(result.Roots) != 1 || result.Roots[0].Change != "removed" {
		t.Fatal("removed component missing from comparison", result.Roots)
	}

	discoverySkill(t, home, "selected", content)
	if code, out := runCheckpoint(t, checkpointArgs("compare", checkpoint)); code != 0 {
		t.Fatalf("restored component must match, got code %d: %s", code, out)
	}
}
