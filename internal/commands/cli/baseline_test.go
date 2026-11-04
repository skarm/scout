package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/scout/baseline"
	"github.com/skarm/scout/internal/commands/cli"
)

func TestBaselineSelectiveApprovalAndPreview(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source.json"), filepath.Join(dir, "approved.json")
	doc := selectiveBaseline(t, source)
	args := make([]string, 0, 13)
	args = append(args, "baseline", "approve", "--from", source, "--output", destination, "--fingerprint", doc.Entries[0].Fingerprint, "--reason", "reviewed first finding", "--expires", "2099-01-01T00:00:00Z")
	var out, diagnostics bytes.Buffer
	if code := cli.Run(context.Background(), append(args, "--dry-run"), &out, &diagnostics); code != 0 {
		t.Fatalf("preview: %d %s", code, &diagnostics)
	}
	var preview struct {
		Schema  string `json:"schema"`
		Changes []struct {
			Index  int            `json:"entry_index"`
			Before baseline.Entry `json:"before"`
			After  baseline.Entry `json:"after"`
		} `json:"changes"`
	}
	if json.Unmarshal(out.Bytes(), &preview) != nil || preview.Schema != "scout.baseline-preview/v1" || len(preview.Changes) != 1 || preview.Changes[0].Index != 0 || preview.Changes[0].Before.Approved || !preview.Changes[0].After.Approved {
		t.Fatalf("incorrect preview: %s", &out)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("dry run wrote its destination")
	}
	if got := readBaseline(t, source); !reflect.DeepEqual(got, doc) {
		t.Fatal("preview changed its source")
	}
	if code := cli.Run(context.Background(), args, &out, &diagnostics); code != 0 {
		t.Fatalf("approval: %d %s", code, &diagnostics)
	}
	got := readBaseline(t, destination)
	if !got.Entries[0].Approved || got.Entries[0].Reason != "reviewed first finding" || !reflect.DeepEqual(got.Entries[1:], doc.Entries[1:]) {
		t.Fatalf("approval changed unselected entries: %+v", got.Entries)
	}
}

func TestBaselineRenewDoesNotApprovePendingEntries(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source.json"), filepath.Join(dir, "renewed.json")
	doc := selectiveBaseline(t, source)
	args := []string{"baseline", "renew", "--from", source, "--output", destination, "--expires", "2099-01-01T00:00:00Z"}
	var out, diagnostics bytes.Buffer
	if code := cli.Run(context.Background(), args, &out, &diagnostics); code != 0 {
		t.Fatalf("renew: %d %s", code, &diagnostics)
	}
	got := readBaseline(t, destination)
	if got.Entries[0] != doc.Entries[0] || got.Entries[1].Reason != doc.Entries[1].Reason || !got.Entries[1].Approved || got.Entries[1].Expires != "2099-01-01T00:00:00Z" {
		t.Fatalf("renew changed approval or reason: %+v", got.Entries)
	}
	for _, extra := range [][]string{
		{"--fingerprint", doc.Entries[0].Fingerprint},
		{"--expires", "2097-01-01T00:00:00Z"},
		{"--fingerprint", strings.Repeat("c", 64)},
	} {
		before, err := os.ReadFile(destination)
		if err != nil {
			t.Fatal(err)
		}
		if code := cli.Run(context.Background(), append(args, extra...), &out, &diagnostics); code != 2 {
			t.Fatalf("invalid renewal accepted: %v code=%d", extra, code)
		}
		after, err := os.ReadFile(destination)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("failed renewal replaced a previous baseline")
		}
	}
}

func selectiveBaseline(t *testing.T, path string) baseline.Document {
	t.Helper()
	d := baseline.Document{Version: baseline.Version, EngineVersion: "fixture", Profile: "custom", Entries: []baseline.Entry{
		{Kind: "fingerprint", Fingerprint: strings.Repeat("a", 64), Reason: "pending", Expires: "2098-01-01T00:00:00Z"},
		{Kind: "fingerprint", Fingerprint: strings.Repeat("b", 64), Reason: "reviewed earlier", Expires: "2098-01-01T00:00:00Z", Approved: true},
	}}
	data, err := baseline.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

func readBaseline(t *testing.T, name string) baseline.Document {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := baseline.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
