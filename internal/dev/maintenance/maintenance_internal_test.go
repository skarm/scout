// Exercises private implementation details and package fixtures.
package maintenance

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaintenanceDispatchRequiresEveryExplicitInput(t *testing.T) {
	for _, command := range []string{"verify-knowledge-sources", "check-knowledge-runtime", "compare-upstream-suite", "adjudicate-upstream-suite", "compare-upstream", "run-upstream-suite", "unknown"} {
		if err := execute(t.Context(), command, options{}, io.Discard); err == nil {
			t.Fatalf("%s accepted implicit inputs", command)
		}
	}
}

func TestReplayExclusionsDistinguishPathsBytesRepresentationsAndCaps(t *testing.T) {
	valid := capturedBlob{SHA256: strings.Repeat("a", 64), Bytes: 1}
	for _, tc := range []struct {
		name string
		blob capturedBlob
		want string
	}{
		{name: "input.py", blob: valid, want: ""},
		{name: "../input.py", blob: valid, want: "path_not_a_scout_artifact_path"},
		{name: "input.py", blob: capturedBlob{Omitted: "capture_limit"}, want: "capture_limit"},
		{name: "input.py", blob: capturedBlob{}, want: "no_bytes"},
		{name: "input.py", blob: capturedBlob{SHA256: "bad"}, want: "invalid_blob_digest"},
		{
			name: "input.py",
			blob: capturedBlob{SHA256: valid.SHA256, Representation: "python_surrogate_string"},
			want: "not_a_utf8_file_python_surrogate_string",
		},
		{name: "input.py", blob: capturedBlob{SHA256: valid.SHA256, Bytes: -1}, want: "replay_input_limit"},
		{name: "input.py", blob: capturedBlob{SHA256: valid.SHA256, Bytes: 4<<20 + 1}, want: "replay_input_limit"},
	} {
		if got := replayFileExclusion(tc.name, tc.blob); got != tc.want {
			t.Fatalf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
	files := map[string]capturedBlob{}
	for i := range 5 {
		files[fmt.Sprintf("part-%d", i)] = capturedBlob{SHA256: valid.SHA256, Bytes: 4 << 20}
	}
	if replayExclusion(files) != "replay_input_limit" {
		t.Fatal("aggregate replay byte cap ignored")
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
