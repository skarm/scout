package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

func TestDiscoverEnvironmentRequiresOneAgentAndProjectContext(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "repo")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{filepath.Join(home, ".claude.json"), filepath.Join(project, ".mcp.json")} {
		if err := os.WriteFile(file, []byte(`{"mcpServers":{"api":{"command":"ls"}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := []string{"discover", "--home", home, "--system=false", "--project", project}
	scan := []string{"--scan", "--", "--environment", "--profile", "custom", "--checks", "none", "--format", "json", "--scope", "selected"}
	var out, diagnostics bytes.Buffer
	code := cli.Run(context.Background(), append(append(append([]string{}, base...), "--agent", "claude-code"), scan...), &out, &diagnostics)
	var document report.Document
	if json.Unmarshal(out.Bytes(), &document) != nil || document.Validate() != nil || document.Run.Environment == nil || len(document.Run.Environment.Observations) == 0 || code != policy.Code(document) {
		t.Fatalf("joint discovered scan failed: code=%d diagnostics=%s output=%s", code, &diagnostics, &out)
	}
	for _, extra := range [][]string{nil, {"--agent", "claude-code", "--project", project}} {
		out.Reset()
		diagnostics.Reset()
		args := append(append(append([]string{}, base...), extra...), scan...)
		if code := cli.Run(context.Background(), args, &out, &diagnostics); code != 2 || out.Len() != 0 || !strings.Contains(diagnostics.String(), "one --agent") {
			t.Fatalf("independent contexts were grouped: %d %s", code, &diagnostics)
		}
	}
}

func TestEnvironmentRejectsRemoteAndStdinBeforeCapture(t *testing.T) {
	for _, inputs := range [][]string{{"https://example.invalid/never-fetch"}, {"--input", "-", "--name", "SKILL.md"}} {
		var out, diagnostics bytes.Buffer
		args := append([]string{"scan", "--environment", "--profile", "custom", "--checks", "none"}, inputs...)
		if code := cli.Run(context.Background(), args, &out, &diagnostics); code != 2 || out.Len() != 0 || !strings.Contains(diagnostics.String(), "local paths") {
			t.Fatalf("invalid environment input accepted: code=%d %s", code, &diagnostics)
		}
	}
}
