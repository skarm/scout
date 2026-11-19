package registry_test

import (
	"context"
	"encoding/json"
	"errors"
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

func TestRegistryLatestRequiresAnExplicitAssertion(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if _, err := writer.Write([]byte(`{"servers":[
			{"server":{"name":"example/selected","version":"1"},"_meta":{"io.modelcontextprotocol.registry/official":{"isLatest":true}}},
			{"server":{"name":"example/historical","version":"1"},"_meta":{"io.modelcontextprotocol.registry/official":{"isLatest":false}}},
			{"server":{"name":"example/unknown","version":"1"}}
		]}`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)

	options := registry.DefaultOptions()
	options.Endpoint = server.URL
	options.Download.Enabled = true
	options.Download.AllowLoopback = true
	options.LatestOnly = true

	snapshot, err := registry.Fetch(t.Context(), options)
	if err != nil || !snapshot.Complete || len(snapshot.Servers) != 1 || !strings.Contains(string(snapshot.Servers[0]), "example/selected") {
		t.Fatalf("expected one registry-asserted record, got %+v (%v)", snapshot, err)
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

func TestComparisonRejectsEmptyServerIdentity(t *testing.T) {
	snapshot := registry.Snapshot{
		Schema:   registry.Schema,
		Complete: true,
		Servers:  []json.RawMessage{json.RawMessage(`{"server":{"name":"","version":"1"}}`)},
	}
	if _, err := registry.Compare(t.Context(), snapshot, snapshot); err == nil {
		t.Fatal("an invalid server identity was certified as an unchanged registry")
	}
}

func TestComparisonRejectsNULInServerIdentity(t *testing.T) {
	before := registry.Snapshot{
		Schema:   registry.Schema,
		Complete: true,
		Servers:  []json.RawMessage{json.RawMessage(`{"server":{"name":"x","version":"z"}}`)},
	}
	for _, record := range []string{
		`{"server":{"name":"x\u0000y","version":"z"}}`,
		`{"server":{"name":"x","version":"y\u0000z"}}`,
	} {
		after := before
		after.Servers = []json.RawMessage{json.RawMessage(record)}
		if _, err := registry.Compare(t.Context(), before, after); err == nil {
			t.Fatal("ambiguous server identity accepted")
		}
		if _, err := registry.Compare(t.Context(), after, before); err == nil {
			t.Fatal("ambiguous prior identity accepted")
		}
	}
	before.Servers = []json.RawMessage{json.RawMessage(`{"server":{"name":"x/y","version":"z"}}`)}
	after := before
	after.Servers = []json.RawMessage{json.RawMessage(`{"server":{"name":"x","version":"y/z"}}`)}
	result, err := registry.Compare(t.Context(), before, after)
	if err != nil || len(result.Changes) != 2 {
		t.Fatalf("ordinary distinct identities should be removed and added: %+v, %v", result, err)
	}
}

func TestRegistryRejectsMalformedPaginationMetadata(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{"servers":[{"server":{"name":"example/first","version":"1"}}],"metadata":{"nextCursor":"next"}}`
		if r.URL.Query().Get("cursor") == "next" {
			body = `{"servers":[{"server":{"name":"example/second","version":"1"}}],"metadata":[]}`
		}

		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)

	options := registry.DefaultOptions()
	options.Endpoint = server.URL
	options.Download.Enabled = true
	options.Download.AllowLoopback = true

	snapshot, err := registry.Fetch(t.Context(), options)
	if err == nil || snapshot.Complete || len(snapshot.Pages) != 1 || len(snapshot.Servers) != 1 ||
		!strings.Contains(string(snapshot.Servers[0]), "example/first") {
		t.Fatalf("expected only the first valid page in an incomplete snapshot, got %+v (%v)", snapshot, err)
	}
}

func TestRegistryComparisonHonorsCancellationWithoutRecords(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	snapshot := registry.Snapshot{Schema: registry.Schema, Complete: true}
	if _, err := registry.Compare(ctx, snapshot, snapshot); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled comparison, got %v", err)
	}
}

func TestRegistryRetainsPageReceiptAtRecordLimit(t *testing.T) {
	t.Parallel()

	const body = `{"servers":[{"server":{"name":"example/first","version":"1"}},{"server":{"name":"example/second","version":"1"}}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)

	options := registry.DefaultOptions()
	options.Endpoint = server.URL
	options.MaxRecords = 1
	options.Download.Enabled = true
	options.Download.AllowLoopback = true

	snapshot, err := registry.Fetch(t.Context(), options)
	if err == nil || snapshot.Complete || len(snapshot.Servers) != 1 || len(snapshot.Pages) != 1 || snapshot.Pages[0].Bytes != len(body) {
		t.Fatalf("expected a partial snapshot retaining both the first record and its page receipt, got %+v (%v)", snapshot, err)
	}
}
