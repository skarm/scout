package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/report"
)

func TestComparePRSummaryAndExactPackageApproval(t *testing.T) {
	before, after := updateInputs(t)
	for _, folder := range []string{before, after} {
		if err := os.Mkdir(filepath.Join(folder, "helpers"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const helper = "helpers/run [draft].sh"
	const oldCall = "curl -s 'https://old.example.test/data'\n"
	const newCall = "curl -s 'https://new.example.test/data?token=private-marker'\n"
	write := func(root, file, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, file), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(before, helper, "#!/bin/sh\n"+oldCall)
	write(after, helper, "#!/bin/sh\n# shifted\n"+oldCall+newCall+newCall)

	commit := strings.Repeat("a", 40)
	jsonFile := filepath.Join(t.TempDir(), "candidate.json")
	compare := func(expected int, extra ...string) string {
		t.Helper()
		args := compareCLIArgs("--scope", "selected", "--pr-head", "Example-Org/skills.v1_test@"+commit,
			"--pr-path", "skills/daily reports", "--report", "json="+jsonFile)
		args = append(args, extra...)
		args = append(args, before, after)
		var out, stderr bytes.Buffer
		if code := cli.Run(t.Context(), args, &out, &stderr); code != expected {
			t.Fatalf("exit %d, want %d: %s\n%s", code, expected, stderr.String(), out.String())
		}
		return out.String()
	}
	readReport := func() report.Document {
		t.Helper()
		data, err := os.ReadFile(jsonFile)
		if err != nil {
			t.Fatal(err)
		}
		return readCompareDocument(t, data)
	}

	md := compare(1)
	for _, piece := range []string{
		"### New static capabilities", "new.example.test", helper + ":4",
		"https://github.com/Example-Org/skills.v1_test/blob/" + commit + "/skills/daily%20reports/helpers/run%20%5Bdraft%5D.sh#L4",
	} {
		if !strings.Contains(md, piece) {
			t.Fatalf("summary missing %q:\n%s", piece, md)
		}
	}
	if strings.Contains(md, "old.example.test") || strings.Contains(md, "private-marker") || strings.Count(md, "new.example.test") != 1 {
		t.Fatalf("summary leaked an unchanged destination, URL query, or duplicate:\n%s", md)
	}
	doc := readReport()
	changes := doc.Run.Comparison.Capabilities.Changes
	if len(changes) != 1 || changes[0].Kind != "network" || changes[0].Status != "introduced" || changes[0].Line != 4 || changes[0].Source.Path != helper {
		t.Fatalf("unexpected capability changes: %+v", changes)
	}
	digest := doc.Run.Targets[1].Analysis.Artifact.SnapshotSHA256
	if !strings.Contains(md, digest) {
		t.Fatal("summary is missing the approval digest")
	}

	compare(0, "--approved-sha256", digest)
	if got := readReport().Evaluation; got.Decision != report.Allow || !slices.Contains(got.Reasons, "package_approval_hash_matched") {
		t.Fatalf("matching package approval: %+v", got)
	}
	compare(1, "--approved-sha256", digest, "--fail-on", "medium")
	if got := readReport().Evaluation; got.Decision != report.Block || !slices.Contains(got.Reasons, "finding_threshold") {
		t.Fatalf("approved package did not retain a blocking finding: %+v", got)
	}
	compare(2, "--approved-sha256", digest, "--max-changes", "1")
	if got := readReport().Evaluation; !slices.Contains(got.Reasons, "package_approval_unverified") {
		t.Fatalf("incomplete comparison used a package approval: %+v", got)
	}
	write(after, "SKILL.md", "Edited wording only.\n")
	compare(1, "--approved-sha256", digest)
	if got := readReport().Evaluation; got.Decision != report.Review || !slices.Contains(got.Reasons, "package_approval_hash_mismatch") {
		t.Fatalf("old approval survived a text change: %+v", got)
	}
}

func TestComparePRRejectsInvalidCoordinatesAndApproval(t *testing.T) {
	before, after := updateInputs(t)
	commit := strings.Repeat("a", 40)
	for _, flags := range [][]string{
		{"--pr-path", "skills"},
		{"--pr-provider", "gitlab"},
		{"--pr-provider", "other", "--pr-head", "owner/repo@" + commit},
		{"--pr-provider", "gitlab", "--pr-head", "javascript://host/group/project@" + commit},
		{"--pr-provider", "gitlab", "--pr-head", "https://host/group/../project@" + commit},
		{"--pr-provider", "gitlab", "--pr-head", "https://host/group/project?token=secret@" + commit},
		{"--pr-provider", "gitlab", "--pr-head", "https://user:password@host/group/project@" + commit},
		{"--pr-head", "https://example.test/owner/repo@" + commit},
		{"--pr-head", "-owner/repo@" + commit},
		{"--pr-head", "owner/..@" + commit},
		{"--pr-head", "owner/repo@" + strings.ToUpper(commit)},
		{"--pr-head", "owner/repo@" + commit[:39]},
		{"--pr-head", "owner/repo@@" + commit[:39]},
		{"--pr-head", "owner/repo@" + commit, "--pr-path", "../skills"},
		{"--approved-sha256", ""},
		{"--approved-sha256", strings.Repeat("A", 64)},
	} {
		var out, stderr bytes.Buffer
		if code := cli.Run(t.Context(), compareCLIArgs(append(flags, before, after)...), &out, &stderr); code != 2 || out.Len() != 0 {
			t.Fatalf("invalid args %q: code %d output %q diagnostics %q", flags, code, out.String(), stderr.String())
		}
	}
}

func TestCompareGitLabSummaryLinksToSourceCommit(t *testing.T) {
	before, after := updateInputs(t)
	if err := os.WriteFile(filepath.Join(after, "network report.sh"), []byte("#!/bin/sh\ncurl -s https://example.test/data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	for _, project := range []string{"https://gitlab.com/group/project", "http://gitlab.example.test:8443/gitlab/group/subgroup/project"} {
		var out, stderr bytes.Buffer
		args := compareCLIArgs("--scope", "selected", "--pr-provider", "gitlab", "--pr-head", project+"@"+commit,
			"--pr-path", "skills/reports", before, after)
		if code := cli.Run(t.Context(), args, &out, &stderr); code != 1 ||
			!strings.Contains(out.String(), project+"/-/blob/"+commit+"/skills/reports/network%20report.sh#L2") {
			t.Fatalf("expected GitLab URL for %s: code %d\n%s\n%s", project, code, &out, &stderr)
		}
	}
}

func TestComparePRReportsChangedDNSDestination(t *testing.T) {
	before, after := updateInputs(t)
	for root, host := range map[string]string{before: "old.example.test", after: "new.example.test"} {
		data := []byte("#!/bin/sh\ndig " + host + "\n")
		if err := os.WriteFile(filepath.Join(root, "lookup.sh"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var out, stderr bytes.Buffer
	args := compareCLIArgs("--scope", "selected", "--pr-head", "example/skills@"+strings.Repeat("a", 40), before, after)
	if code := cli.Run(t.Context(), args, &out, &stderr); code != 1 ||
		!strings.Contains(out.String(), "DNS query to `new.example.test`") || !strings.Contains(out.String(), "/lookup.sh#L2") ||
		strings.Contains(out.String(), "old.example.test") {
		t.Fatalf("DNS destination change missing: code %d\n%s\n%s", code, &out, &stderr)
	}
}

func TestComparePRLinksToNewSkillDeclaration(t *testing.T) {
	if !frontend.BackendFor("yaml").Available {
		t.Skip("requires the YAML parser")
	}
	before, after := updateInputs(t)
	const skill = "---\nname: example\ndescription: Write a short report.\nallowed-tools:\n  - Read\n"
	if err := os.WriteFile(filepath.Join(before, "SKILL.md"), []byte(skill+"---\nWrite a report.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(after, "SKILL.md"), []byte(skill+"  - Write\n---\nWrite a report.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	args := []string{
		"compare", "--profile", "custom", "--checks", "yaml", "--harness", "claude-code",
		"--pr-head", "example/skills@" + strings.Repeat("a", 40), before, after,
	}
	if code := cli.Run(t.Context(), args, &out, &stderr); code != 2 ||
		!strings.Contains(out.String(), "Decision **block**") ||
		strings.Count(out.String(), "Allowed tools declaration") != 1 || !strings.Contains(out.String(), "/SKILL.md#L6") {
		t.Fatalf("declaration not linked to its source: code %d\n%s\n%s", code, &out, &stderr)
	}
}
