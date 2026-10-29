package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/report"
)

func TestProfilePreflightAndDowngradeRejection(t *testing.T) {
	var out, errs bytes.Buffer
	if code := cli.Run(context.Background(), []string{"profiles"}, &out, &errs); code != 0 {
		t.Fatal(code, errs.String())
	}
	var profiles []string
	if err := json.Unmarshal(out.Bytes(), &profiles); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(profiles, []string{"standard", "review", "custom"}) {
		t.Fatalf("unexpected profiles: %v", profiles)
	}
	for _, args := range [][]string{
		{"profiles", "invalid"},
		{"profiles", "standard", "review"},
		{"scan", "--profile", "standard", "--yara=false", "does-not-exist"},
		{"scan", "--profile", "standard", "--python-ast=false", "does-not-exist"},
		{"scan", "--profile", "extended", "--yara=false", "does-not-exist"},
		{"scan", "--profile", "semantic", "--semantic=false", "does-not-exist"},
		{"scan", "--profile", "semantic", "does-not-exist"},
	} {
		out.Reset()
		errs.Reset()
		if code := cli.Run(context.Background(), args, &out, &errs); code != 2 || out.Len() != 0 || errs.Len() == 0 {
			t.Fatalf("%v: code=%d stdout_bytes=%d diagnostics=%q", args, code, out.Len(), errs.String())
		}
	}
}

func TestProfileReportAcrossFormats(t *testing.T) {
	input := filepath.Join(t.TempDir(), "readme.txt")
	if err := os.WriteFile(input, []byte("plain text"), 0o600); err != nil {
		t.Fatal(err)
	}
	available := standardProfileAvailable()
	for _, format := range []string{"json", "sarif", "markdown", "text"} {
		t.Run(format, func(t *testing.T) {
			var out, errs bytes.Buffer
			code := cli.Run(context.Background(), []string{"scan", "--profile", "standard", "--format", format, input}, &out, &errs)
			if !available {
				if code != 2 || !strings.Contains(errs.String(), "backend_unavailable") || out.Len() != 0 {
					t.Fatalf("unavailable standard profile: code=%d stdout_bytes=%d diagnostics=%q", code, out.Len(), errs.String())
				}
				return
			}
			if code != 0 || errs.Len() != 0 {
				t.Fatalf("code=%d diagnostics=%q", code, errs.String())
			}
			if !strings.Contains(out.String(), "standard") || !strings.Contains(out.String(), "selected") {
				t.Fatal("standard inspection selection missing")
			}
			if format == "json" {
				var d report.Document
				if err := json.Unmarshal(out.Bytes(), &d); err != nil {
					t.Fatal(err)
				}
				if err := d.Validate(); err != nil {
					t.Fatal(err)
				}
				if d.Run.Plan.Name != "standard" || d.Run.Plan.RequestedProfile != "standard" {
					t.Fatalf("unexpected plan: %s/%s", d.Run.Plan.Name, d.Run.Plan.RequestedProfile)
				}
				selected := make([]string, 0)
				for _, check := range d.Run.Plan.Checks {
					if check.Selected {
						selected = append(selected, check.ID)
					}
				}
				if !slices.Equal(selected, []string{"builtins", "adapted_patterns", "python", "yaml", "toml", "yara"}) {
					t.Fatalf("standard checks changed: %v", selected)
				}
			}
		})
	}
}

func TestLegacyProfilesAreOnlyCommandAliases(t *testing.T) {
	input := filepath.Join(t.TempDir(), "readme.txt")
	if err := os.WriteFile(input, []byte("plain text"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []struct{ name, canonical string }{{name: "basic", canonical: "custom"}, {
		name:      "extended",
		canonical: "standard",
	}} {
		t.Run(alias.name, func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "scout.json")
			data := []byte(`{"schema":"scout.config/v1","profile":"` + alias.name + `"}`)
			if err := os.WriteFile(config, data, 0o600); err != nil {
				t.Fatal(err)
			}
			var configOut, configDiag bytes.Buffer
			if code := cli.Run(context.Background(), []string{"config", "validate", "--config", config}, &configOut, &configDiag); code != 2 || configOut.Len() != 0 || configDiag.Len() == 0 {
				t.Fatalf("legacy config profile accepted: code=%d diagnostics=%q", code, configDiag.String())
			}
			var out, diag bytes.Buffer
			code := cli.Run(context.Background(), []string{"scan", "--profile", alias.name, "--format", "json", input}, &out, &diag)
			if alias.canonical == "standard" && !standardProfileAvailable() {
				if code != 2 || out.Len() != 0 || !strings.Contains(diag.String(), "backend_unavailable") {
					t.Fatalf("alias bypassed required engines: code=%d diagnostics=%q", code, diag.String())
				}
				return
			}
			if code != 0 || diag.Len() != 0 {
				t.Fatalf("code=%d diagnostics=%q", code, diag.String())
			}
			var d report.Document
			if err := json.Unmarshal(out.Bytes(), &d); err != nil {
				t.Fatal(err)
			}
			if err := d.Validate(); err != nil {
				t.Fatal(err)
			}
			if d.Run.Plan.Name != alias.canonical || d.Run.Plan.RequestedProfile != alias.canonical {
				t.Fatalf("legacy name leaked into plan: %s/%s", d.Run.Plan.Name, d.Run.Plan.RequestedProfile)
			}
		})
	}
}

func standardProfileAvailable() bool {
	return frontend.BackendFor("python").Available && frontend.BackendFor("yaml").Available && frontend.BackendFor("toml").Available && signatures.Backend().Available
}
