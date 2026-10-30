package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
)

func TestFullHelpAndManualCoverEveryCommandFlag(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if code := cli.Run(context.Background(), []string{"-h"}, &out, &diagnostics); code != 0 || diagnostics.Len() != 0 {
		t.Fatalf("help failed: code=%d diagnostics=%s", code, &diagnostics)
	}

	full := out.String()
	for _, alias := range []string{"--help", "help"} {
		out.Reset()
		if code := cli.Run(context.Background(), []string{alias}, &out, &diagnostics); code != 0 || out.String() != full || diagnostics.Len() != 0 {
			t.Fatalf("help alias %s does not print the full reference", alias)
		}
	}

	manuals := map[string]string{"scout -h": full}
	for _, name := range []string{"cli.md", "cli.ru.md"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "reference", name))
		if err != nil {
			t.Fatal(err)
		}

		manuals[name] = string(data)
	}

	flagName := regexp.MustCompile(`(?m)^  -([a-z][a-z0-9-]*)(?:\s|$)`)
	referenceName := regexp.MustCompile(`--([a-z][a-z0-9-]*)`)
	for _, command := range [][]string{
		{"scan"},
		{"compare"},
		{"discover"},
		{"mcp"},
		{"config", "validate"},
		{"doctor"},
		{"baseline", "create"},
		{"baseline", "approve"},
		{"knowledge"},
		{"integrations", "export"},
		{"registry", "fetch"},
		{"registry", "compare"},
		{"attestation", "verify"},
	} {
		out.Reset()
		diagnostics.Reset()
		args := append(append([]string(nil), command...), "--help")
		if code := cli.Run(context.Background(), args, &out, &diagnostics); code != 0 || strings.Contains(diagnostics.String(), "panic") {
			t.Fatalf("%v help failed: code=%d diagnostics=%s", command, code, &diagnostics)
		}

		flags := flagName.FindAllStringSubmatch(diagnostics.String(), -1)
		if len(flags) == 0 {
			t.Fatalf("%v help did not list any flags", command)
		}

		for name, reference := range manuals {
			documented := map[string]bool{}
			for _, match := range referenceName.FindAllStringSubmatch(reference, -1) {
				documented[match[1]] = true
			}

			for _, match := range flags {
				if !documented[match[1]] {
					t.Errorf("%s omits %v flag --%s", name, command, match[1])
				}
			}
		}
	}
}

func TestFullHelpReportsOutputFailure(t *testing.T) {
	if code := cli.Run(context.Background(), []string{"-h"}, failWriter{}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("help output failure returned %d", code)
	}
}
