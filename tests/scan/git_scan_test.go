package scout_test

import (
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/report"
)

func TestRemoteGitScanUsesTreeBudgetAndConfiguredDepth(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git is required for the Smart HTTP fixture")
	}

	root := t.TempDir()
	gitCommand := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), git, args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	backend, err := exec.LookPath(filepath.Join(gitCommand("--exec-path"), "git-http-backend"))
	if err != nil {
		t.Skip("git-http-backend is required for the Smart HTTP fixture")
	}

	gitCommand("init", "--quiet", "--template=", "--object-format=sha1", "project.git")
	path := strings.Repeat("d/", 35) + "notes.txt"
	name := filepath.Join(root, "project.git", filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("project notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	gitCommand("-C", "project.git", "add", ".")
	gitCommand("-C", "project.git", "-c", "user.name=Scout", "-c", "user.email=scout@example.invalid", "commit", "--quiet", "-m", "fixture")
	sha := gitCommand("-C", "project.git", "rev-parse", "HEAD")
	server := httptest.NewServer(&cgi.Handler{
		Path: backend, Dir: root, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"},
	})
	defer server.Close()

	opts := scout.DefaultOptions()
	opts.Profile, opts.Checks = scout.Custom, &scout.Checks{}
	download := fetch.DefaultOptions()
	download.Enabled, download.AllowLoopback = true, true
	opts.Download = &download
	opts.Limits.Capture.MaxFileBytes, opts.Limits.Capture.MaxArchiveBytes = 128, 128
	opts.Limits.Capture.MaxDepth = 40
	scanner, err := scout.New(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scanner.Close() })

	target, err := scout.Remote(server.URL+"/project.git", scout.RemotePin{Revision: sha})
	if err != nil {
		t.Fatal(err)
	}
	run, err := scanner.Scan(t.Context(), target)
	if err != nil || run.State != report.RunComplete || len(run.Targets) != 1 {
		t.Fatalf("pinned Git tree did not scan completely: %s, %v", run.State, err)
	}
	analysis := run.Targets[0].Analysis
	if analysis.Source == nil || analysis.Source.Revision != sha || analysis.Source.Bytes <= opts.Limits.Capture.MaxArchiveBytes ||
		len(analysis.Artifact.Files) != 1 || analysis.Artifact.Files[0].Path != path {
		t.Fatalf("incorrect source or repository inventory: %+v, %+v", analysis.Source, analysis.Artifact.Files)
	}
}
