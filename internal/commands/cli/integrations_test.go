package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
)

func TestIntegrationsCLI(t *testing.T) {
	for _, args := range [][]string{{"integrations"}, {"integrations", "list"}} {
		var out, err bytes.Buffer
		if code := cli.Run(context.Background(), args, &out, &err); code != 0 || !json.Valid(out.Bytes()) {
			t.Fatalf("list=%d %s", code, err.String())
		}
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "bundle.zip")
	args := []string{"integrations", "export", "--bundle", "pi", "--output", dst}
	var out, err bytes.Buffer
	if code := cli.Run(context.Background(), args, &out, &err); code != 0 {
		t.Fatalf("export=%d: %s", code, err.String())
	}
	before, e := os.ReadFile(dst)
	if e != nil || len(before) < 100 {
		t.Fatal(e)
	}
	out.Reset()
	err.Reset()
	if code := cli.Run(context.Background(), args, &out, &err); code != 2 {
		t.Fatalf("overwrite accepted %d", code)
	}
	after, _ := os.ReadFile(dst)
	if !bytes.Equal(before, after) {
		t.Fatal("output overwritten")
	}
	for _, a := range [][]string{{"integrations", "install"}, {"integrations", "export"}, {"integrations", "export", "--bundle", "unknown", "--output", filepath.Join(dir, "bad.zip")}, {"integrations", "export", "--bundle", "pi", "--output", filepath.Join(dir, "bad.zip"), "target"}} {
		out.Reset()
		err.Reset()
		if code := cli.Run(context.Background(), a, &out, &err); code != 2 {
			t.Fatalf("invalid accepted %v", a)
		}
	}
}
