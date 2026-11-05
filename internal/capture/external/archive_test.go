package external_test

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/capture/external"
	"github.com/skarm/scout/report"
)

func TestReferencedArchivesHonorCaptureByteBudget(t *testing.T) {
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	member, err := w.Create("README.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = member.Write([]byte("ordinary documentation")); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	archive := buffer.Bytes()
	for _, tc := range []struct {
		name, path, body string
		limit            int64
		accepted         bool
	}{
		{name: "zip", path: "/bundle.zip", body: string(archive), limit: 16},
		{name: "renamed-magic", path: "/disguised.txt", body: string(archive), limit: 16},
		{name: "exact-boundary", path: "/bundle.zip", body: string(archive), limit: int64(len(archive)), accepted: true},
		{name: "ordinary-text", path: "/notes.txt", body: strings.Repeat("x", 64), limit: 16, accepted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			root := artifact.NewFile("SKILL.md", []byte("See "+server.URL+tc.path), false)
			snapshot := artifact.New("directory", []artifact.File{root}, nil, nil, true)
			limits := report.DefaultCaptureLimits()
			limits.MaxArchiveBytes, limits.MaxFileBytes = tc.limit, 1024
			download := fetch.DefaultOptions()
			download.Enabled, download.AllowLoopback = true, true
			options := external.Options{AllowedOrigins: []string{server.URL}, MaxDepth: 1, MaxRequests: 1, MaxBytes: 1024}
			got, closure, err := external.Expand(t.Context(), snapshot, options, download, limits)
			if err != nil || closure.Complete != tc.accepted || got.Complete() != tc.accepted || len(closure.References) != 1 {
				t.Fatalf("incorrect archive admission: %+v %+v %v", got.Metadata(), closure, err)
			}
			wantStatus, wantFiles := "archive_size_limit", 1
			if tc.accepted {
				wantStatus, wantFiles = report.CaptureCaptured, 2
			}
			if closure.References[0].Status != wantStatus || len(got.Files()) != wantFiles {
				t.Fatalf("archive budget bypass: %+v %+v", got.Metadata(), closure)
			}
		})
	}
}
