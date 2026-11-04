package evaluation_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/dev/evaluation"
)

func TestCollectedCorpusPreservesPinnedBytesAndRequiresReview(t *testing.T) {
	root := t.TempDir()
	content := "# External fixture\r\nKeep the input unchanged.\r\n"
	if err := os.WriteFile(filepath.Join(root, "source.md"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := collectionFixture(content)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := evaluation.ParseCollectionManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, inputs, err := evaluation.Collect(t.Context(), parsed, root, fetch.DefaultOptions())
	if err != nil || len(inputs) != 1 {
		t.Fatalf("collection failed: inputs=%v error=%v", inputs, err)
	}
	corpus, err := evaluation.Parse(data)
	if err != nil || corpus.Kind != "external_unreviewed_corpus" || corpus.Cases[0].Label != "ambiguous" || corpus.Cases[0].Files[0].Content != content {
		t.Fatalf("collection changed source or asserted a label: %+v %v", corpus, err)
	}
	parsed.Cases[0].Files[0].SHA256 = strings.Repeat("0", 64)
	if _, _, err := evaluation.Collect(t.Context(), parsed, root, fetch.DefaultOptions()); err == nil {
		t.Fatal("pin mismatch accepted")
	}
	manifest.Cases[0].Label = "benign"
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evaluation.ParseCollectionManifest(raw); err == nil {
		t.Fatal("unreviewed source acquired a benign label")
	}
}

func TestCollectionPreflightAndStrictJSON(t *testing.T) {
	manifest := collectionFixture("fixture")
	manifest.Cases[0].Files[0].URL, manifest.Cases[0].Files[0].Local = "https://example.invalid/SKILL.md", ""
	if _, _, err := evaluation.Collect(t.Context(), manifest, t.TempDir(), fetch.DefaultOptions()); err == nil || !strings.Contains(err.Error(), "--allow-download") {
		t.Fatal("ungranted collection did not fail before network access", err)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
		bytes.Replace(raw, []byte(`"sha256":`), []byte(`"sha256":null,"unexpected":`), 1),
	} {
		if _, err := evaluation.ParseCollectionManifest(bad); err == nil {
			t.Fatal("ambiguous manifest accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := evaluation.Collect(ctx, collectionFixture("fixture"), t.TempDir(), fetch.DefaultOptions()); err == nil {
		t.Fatal("cancelled collection succeeded")
	}
}

func TestCollectionRechecksActualSplitIsolation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "source.md"), []byte("shared bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := collectionFixture("shared bytes")
	other := manifest.Sources[0]
	other.ID, other.Origin = "other", "fixture:other"
	manifest.Sources = append(manifest.Sources, other)
	second := manifest.Cases[0]
	second.ID, second.SourceID, second.Split = "second", "other", "tune"
	manifest.Cases = append(manifest.Cases, second)
	if _, _, err := evaluation.Collect(t.Context(), manifest, root, fetch.DefaultOptions()); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatal("collected duplicate bytes crossed split boundary", err)
	}
}

func TestCollectionPreservesDownloadResponseBudget(t *testing.T) {
	content := "pinned remote source bytes"
	hash := sha256.Sum256([]byte(content))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, content)
	}))
	defer server.Close()
	file := evaluation.CollectionFile{URL: server.URL + "/source.md", SHA256: hex.EncodeToString(hash[:])}
	for _, limits := range [][2]int64{{4, 100}, {100, 4}, {int64(len(content)), int64(len(content))}} {
		options := fetch.DefaultOptions()
		options.Enabled, options.AllowLoopback, options.MaxBytes = true, true, limits[0]
		data, err := evaluation.CollectFileForTest(t.Context(), file, options, limits[1])
		if limits[0] < int64(len(content)) || limits[1] < int64(len(content)) {
			var failure *fetch.Error
			if !errors.As(err, &failure) || failure.Code != "byte_limit" || len(data) != 0 {
				t.Fatalf("response exceeded caller or collection budget %v: bytes=%d error=%v", limits, len(data), err)
			}
		} else if err != nil || string(data) != content {
			t.Fatalf("source at exact response budget was rejected: %v", err)
		}
	}
}

func collectionFixture(content string) evaluation.CollectionManifest {
	hash := sha256.Sum256([]byte(content))
	return evaluation.CollectionManifest{Schema: "scout.corpus-sources/v1", Kind: "external_unreviewed_corpus", Sources: []evaluation.Source{{ID: "fixture", Origin: "fixture:source", Revision: "fixture-revision", License: "MIT", LabelReview: "Pending independent review; synthetic test fixture only."}}, Cases: []evaluation.CollectionCase{{ID: "fixture", Category: "docs", Label: "ambiguous", SourceID: "fixture", Split: "holdout", Files: []evaluation.CollectionFile{{Path: "SKILL.md", Local: "source.md", SHA256: hex.EncodeToString(hash[:])}}}}}
}
