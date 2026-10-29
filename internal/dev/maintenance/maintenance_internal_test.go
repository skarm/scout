// Exercises private implementation details and package fixtures.
package maintenance

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaintenanceDispatchRequiresEveryExplicitInput(t *testing.T) {
	for _, command := range []string{"verify-knowledge-sources", "check-knowledge-runtime", "unknown"} {
		if err := execute(t.Context(), command, options{}, io.Discard); err == nil {
			t.Fatalf("%s accepted implicit inputs", command)
		}
	}
}

func TestRuntimeJSONAndLocalPathContracts(t *testing.T) {
	root := t.TempDir()
	if _, err := safeJoin(root, "../escape"); err == nil {
		t.Fatal("artifact path escaped its root")
	}
	if name, err := safeJoin(root, "a/file"); err != nil || name != filepath.Join(root, "a/file") {
		t.Fatal("local path normalization changed")
	}
	if root, err := projectRoot(); err != nil || root == "" {
		t.Fatal("repository root discovery failed")
	}
	parsed, _ := url.Parse("https://github.com/example/repo")
	_, item, _ := sourceFixture()
	if err := verifyArtifactURL(parsed, strings.Repeat("a", 40), item); err != nil {
		t.Fatal(err)
	}
	if got := obj(map[string]any{"x": true}); !boolean(got["x"]) {
		t.Fatal("JSON object boundary lost a field")
	}
	if obj(object{"x": true}) == nil || obj("not-object") != nil {
		t.Fatal("JSON object shape changed")
	}
}

func maintenanceFile(t *testing.T, root, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func maintenanceJSON(t *testing.T, root, name string, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return maintenanceFile(t, root, name, data)
}

func sourceFixture() (pinnedSource, sourceArtifact, []byte) {
	data := []byte("inert pinned source\n")
	blob := sha1.Sum(append(fmt.Appendf(nil, "blob %d\x00", len(data)), data...))
	item := sourceArtifact{
		Path:        "src/sample.py",
		SHA256:      digest(data),
		Bytes:       len(data),
		GitBlobSHA1: hex.EncodeToString(blob[:]),
	}
	source := pinnedSource{
		ID:         "fixture",
		Repository: "https://github.com/example/repo",
		Revision:   strings.Repeat("a", 40),
	}
	item.URL = source.Repository[:8] + "raw.githubusercontent.com/example/repo/" + source.Revision + "/" + item.Path
	source.Artifacts = []sourceArtifact{item}
	return source, item, data
}
