package fetch_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/fetch"
)

func TestPinnedGitSmartHTTP(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git is required for the Smart HTTP fixture")
	}

	root := t.TempDir()
	work := filepath.Join(root, "repository.git")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}

	gitCommand := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), git, args...)
		cmd.Dir = work
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gitCommand("init", "--quiet", "--template=", "--object-format=sha1")
	gitCommand("config", "user.name", "Scout fixture")
	gitCommand("config", "user.email", "scout@example.invalid")
	gitCommand("config", "uploadpack.allowReachableSHA1InWant", "true")
	write(".gitattributes", "private.txt export-ignore\nSKILL.md export-subst\n")
	write("private.txt", "captured despite export-ignore\n")
	write("SKILL.md", "original $Format:%H$\n")
	gitCommand("add", ".")
	gitCommand("commit", "--quiet", "-m", "pinned version")
	sha := gitCommand("rev-parse", "HEAD")
	write("SKILL.md", "new version\n")
	write("large.txt", strings.Repeat("z", 50000))
	gitCommand("add", ".")
	gitCommand("commit", "--quiet", "-m", "later version")
	later := gitCommand("rev-parse", "HEAD")
	gitCommand("update-index", "--add", "--cacheinfo", "120000,"+gitCommand("rev-parse", "HEAD:SKILL.md")+",link")
	gitCommand("commit", "--quiet", "-m", "unsupported symlink")
	linked := gitCommand("rev-parse", "HEAD")

	backend := filepath.Join(gitCommand("--exec-path"), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend is required for the Smart HTTP fixture")
	}

	server := httptest.NewTLSServer(&cgi.Handler{
		Path: backend, Dir: root,
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"},
	})
	defer server.Close()

	options := enabled()
	options.AllowLoopback, options.Revision = true, sha
	options.RootCAs = x509.NewCertPool()
	options.RootCAs.AddCert(server.Certificate())
	address := server.URL + "/repository.git"
	result, err := fetch.Get(t.Context(), address, options)
	if err != nil {
		t.Fatal(err)
	}
	digest, target := sha256.Sum256(result.Data), sha256.Sum256([]byte(address))
	if result.Source.Revision != sha || result.Source.Kind != "git-tree" || result.Source.Bytes != int64(len(result.Data)) ||
		result.Source.BytesSHA256 != hex.EncodeToString(digest[:]) || result.Source.TargetSHA256 != hex.EncodeToString(target[:]) {
		t.Fatalf("incorrect Git provenance: %+v", result.Source)
	}

	archive, err := zip.NewReader(bytes.NewReader(result.Data), int64(len(result.Data)))
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{}
	for _, file := range archive.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		contents[file.Name] = string(data)
	}
	if len(contents) != 3 || contents["SKILL.md"] != "original $Format:%H$\n" || contents["private.txt"] != "captured despite export-ignore\n" {
		t.Fatalf("captured the wrong tree: %+v", contents)
	}

	again, err := fetch.Get(t.Context(), address, options)
	if err != nil || again.Source.BytesSHA256 != result.Source.BytesSHA256 {
		t.Fatalf("Git tree bytes are not reproducible: %+v, %v", again.Source, err)
	}
	options.Revision = linked
	if _, err := fetch.Get(t.Context(), address, options); code(err) != "git_unsupported_tree_entry" {
		t.Fatalf("Git symlink was not rejected: %v", err)
	}

	options.MaxBytes, options.Revision = 32, sha
	if _, err := fetch.Get(t.Context(), address, options); code(err) != "byte_limit" {
		t.Fatalf("Git traffic escaped the byte limit: %v", err)
	}

	options.MaxBytes, options.Revision = 4096, later
	if _, err := fetch.Get(t.Context(), address, options); code(err) != "byte_limit" {
		t.Fatalf("expanded Git tree escaped the byte limit: %v", err)
	}
}

func TestGitSmartHTTPRejectsRedirectAndDumbHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		serve      http.HandlerFunc
	}{
		{"redirect", "redirect_refused", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.invalid/another.git", http.StatusFound)
		}},
		{"dumb HTTP", "git_smart_http_required", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "refs\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := exec.LookPath("git"); err != nil {
				t.Skip("Git is required for Smart HTTP")
			}
			server := httptest.NewServer(tc.serve)
			defer server.Close()
			o := enabled()
			o.AllowLoopback, o.Revision = true, strings.Repeat("a", 40)
			if _, err := fetch.Get(t.Context(), server.URL+"/repository.git", o); code(err) != tc.want {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
}
