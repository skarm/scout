package registry_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/distribution/registry"
)

func TestRegistryPaginationSelectionAndHistory(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("cursor") == "" {
			if _, err := w.Write([]byte(`{"servers":[{"server":{"name":"example/tool","version":"1.0.0"}}],"metadata":{"nextCursor":"page&two"}}`)); err != nil {
				t.Error(err)
			}
			return
		}
		if r.URL.Query().Get("cursor") != "page&two" {
			t.Error("cursor was not preserved as one query value")
		}
		if _, err := w.Write([]byte(`{"servers":[{"server":{"name":"example/tool","version":"2.0.0"},"_meta":{"io.modelcontextprotocol.registry/official":{"isLatest":true}}}]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	o := registry.DefaultOptions()
	o.Endpoint = server.URL + "/servers"
	o.Download.AllowLoopback = true
	if _, err := registry.Fetch(context.Background(), o); err == nil || requests != 0 {
		t.Fatal("registry requested without a grant")
	}
	o.Download.Enabled = true
	all, err := registry.Fetch(context.Background(), o)
	if err != nil || !all.Complete || len(all.Servers) != 2 || len(all.Pages) != 2 {
		t.Fatalf("%+v %v", all, err)
	}
	o.Name = "example/tool"
	o.LatestOnly = true
	latest, err := registry.Fetch(context.Background(), o)
	if err != nil || len(latest.Servers) != 1 || !strings.Contains(string(latest.Servers[0]), "2.0.0") {
		t.Fatalf("%+v %v", latest, err)
	}
	diff, err := registry.Compare(context.Background(), all, latest)
	if err != nil || len(diff.Changes) != 1 || diff.Changes[0].AfterSHA256 != "" {
		t.Fatalf("%+v %v", diff, err)
	}
	latest.Complete = false
	if _, err := registry.Compare(context.Background(), all, latest); err == nil {
		t.Fatal("partial history compared as complete")
	}
}

func TestRegistryBoundsAndMalformedPages(t *testing.T) {
	for _, body := range []string{`{"servers":[],"metadata":{"nextCursor":"same"}}`, `{"servers":[],"servers":[]}`, `{"servers":[{"server":{"name":42}}]}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Error(err)
			}
		}))
		o := registry.DefaultOptions()
		o.Endpoint = server.URL
		o.Download.Enabled = true
		o.Download.AllowLoopback = true
		o.MaxPages = 2
		snapshot, err := registry.Fetch(context.Background(), o)
		server.Close()
		if err == nil || snapshot.Complete {
			t.Fatalf("invalid page certified: %+v %v", snapshot, err)
		}
	}
	before := registry.Snapshot{
		Schema:   registry.Schema,
		Complete: true,
		Servers:  []json.RawMessage{json.RawMessage(`{"server":{"name":"x","version":"1"}}`)},
	}
	after := before
	after.Servers = []json.RawMessage{json.RawMessage(`{"server":{"version":"1", "name":"x"}}`)}
	diff, err := registry.Compare(context.Background(), before, after)
	if err != nil || len(diff.Changes) != 0 {
		t.Fatalf("formatting became a record change: %+v %v", diff, err)
	}
}
