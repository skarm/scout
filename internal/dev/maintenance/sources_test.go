//nolint:testpackage // Tests exercise private maintenance evidence, process and filesystem contracts.
package maintenance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestPinnedSourceCacheBindsURLRevisionBytesAndGitIdentity(t *testing.T) {
	source, item, data := sourceFixture()
	cache := t.TempDir()
	maintenanceFile(t, cache, item.SHA256, data)
	if count, err := verifySource(t.Context(), source, cache, false); err != nil || count != 1 {
		t.Fatalf("valid pinned source rejected: %d %v", count, err)
	}
	for _, mutate := range []func(*pinnedSource){
		func(s *pinnedSource) { s.Revision = "main" }, func(s *pinnedSource) { s.Repository = "http://github.com/example/repo" },
		func(s *pinnedSource) { s.Artifacts[0].URL += "?token=secret" }, func(s *pinnedSource) { s.Artifacts[0].Bytes++ },
		func(s *pinnedSource) { s.Artifacts[0].GitBlobSHA1 = strings.Repeat("0", 40) }, func(s *pinnedSource) { s.Artifacts[0].SHA256 = "bad" },
	} {
		changed := source
		changed.Artifacts = append([]sourceArtifact{}, source.Artifacts...)
		mutate(&changed)
		if _, err := verifySource(t.Context(), changed, cache, false); err == nil {
			t.Fatal("unbound pinned source accepted")
		}
	}
	root := t.TempDir()
	maintenanceJSON(t, root, "knowledge/data/review_sources.json", []pinnedSource{source})
	enabled := true
	o := options{root: root, download: &enabled, values: map[string]*string{"cache": &cache}}
	var output bytes.Buffer
	if err := verifyKnowledgeSources(t.Context(), o, &output); err != nil || !strings.Contains(output.String(), "verified 1 source files") {
		t.Fatalf("cache workflow failed: %v %s", err, &output)
	}
	if err := verifySourceBytes(data, item); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySource(t.Context(), source, t.TempDir(), false); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing cache did not remain offline")
	}
}

func TestSourceDownloadRejectsRedirectsStatusAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/bytes", http.StatusFound)
		case "/bad":
			w.WriteHeader(http.StatusBadGateway)
		default:
			_, _ = io.WriteString(w, "source bytes")
		}
	}))
	defer server.Close()
	if data, err := downloadSource(t.Context(), server.URL+"/bytes"); err != nil || string(data) != "source bytes" {
		t.Fatal("source download changed bytes")
	}
	for _, path := range []string{"/redirect", "/bad"} {
		if _, err := downloadSource(t.Context(), server.URL+path); err == nil {
			t.Fatal("source transport accepted an unbound redirect or failed status")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := downloadSource(ctx, server.URL); err == nil {
		t.Fatal("cancelled source download ran")
	}
}

func TestVerifyUpstreamBindsCommitInventoryPathsAndEverySourceByte(t *testing.T) {
	root, upstream := t.TempDir(), t.TempDir()
	data := []byte("pinned source")
	maintenanceFile(t, upstream, "source.py", data)
	inventory := func(path, sha string, count int, commit string) object {
		return object{
			"Commit":     commit,
			"file_count": count,
			"Files": []any{object{
				"Path":   path,
				"SHA256": sha,
				"Bytes":  len(data),
			}},
		}
	}
	name := "testdata/provenance/upstream-inventory.json"
	maintenanceJSON(t, root, name, inventory("source.py", digest(data), 1, upstreamCommit))
	if got, err := verifyUpstream(root, upstream); err != nil || got.FileCount != 1 {
		t.Fatal("valid pinned inventory rejected")
	}
	for _, value := range []object{inventory("source.py", digest(data), 1, "main"), inventory("source.py", digest(data), 2, upstreamCommit), inventory("../outside", digest(data), 1, upstreamCommit), inventory("missing.py", digest(data), 1, upstreamCommit), inventory("source.py", strings.Repeat("0", 64), 1, upstreamCommit)} {
		maintenanceJSON(t, root, name, value)
		if _, err := verifyUpstream(root, upstream); err == nil {
			t.Fatal("modified or incomplete source inventory accepted")
		}
	}
}
