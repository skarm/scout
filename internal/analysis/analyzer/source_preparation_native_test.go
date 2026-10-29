//go:build !coreonly && cgo

package analyzer_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
)

func TestDerivedConfigurationFailureRetainsExplicitOutcome(t *testing.T) {
	registry, err := parse.WithFrontends(frontend.Options{
		YAML:    true,
		TOML:    true,
		Timeout: frontend.DefaultOptions().Timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		count      int
		gap        bool
	}{
		{name: "valid", body: "npmRegistryServer: https://private.invalid\n", count: 1, gap: false},
		{
			name:  "ambiguous",
			body:  "npmRegistryServer: https://private.invalid\nnpmRegistryServer: https://registry.npmjs.org\n",
			count: 0,
			gap:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "cat > .yarnrc.yml <<'EOF'\n" + tc.body + "EOF\n"
			docs := analyzer.PrepareDerived(context.Background(), document.PrepareAllWithRegistry(context.Background(), []artifact.File{artifact.NewFile("input.sh", []byte(text), false)}, registry))
			out, err := pluginRule(t, "NV-SC10").Find(context.Background(), docs[0], 16)
			if err != nil || len(out.Matches) != tc.count || out.Truncated != tc.gap {
				children, gap := docs[0].DerivedConfigs()
				t.Logf("outer diagnostics=%+v derived gap=%v", docs[0].Diagnostics(), gap)
				for _, c := range children {
					t.Logf("derived=%s units=%+v diagnostics=%+v", c.File.Artifact().Metadata().Path, c.File.Units(), c.File.Diagnostics())
				}
				t.Fatalf("%+v %v", out, err)
			}
			if tc.gap {
				found := false
				for _, d := range docs[0].Diagnostics() {
					found = found || d.AffectsScope && strings.HasPrefix(d.Code, "derived_")
				}
				if !found {
					t.Fatal("derived parse failure disappeared from run diagnostics")
				}
			}
		})
	}
}

func TestDerivedConfigurationSharesAggregateParserBudget(t *testing.T) {
	registry, err := parse.WithFrontends(frontend.Options{YAML: true, Timeout: frontend.DefaultOptions().Timeout})
	if err != nil {
		t.Fatal(err)
	}
	inputs := make([]artifact.File, 0, 9)
	for i := range 8 {
		inputs = append(inputs, artifact.NewFile(fmt.Sprintf("%d.yaml", i), []byte("key: "+strings.Repeat("x", parse.MaxUnitBytes-len("key: \n"))+"\n"), false))
	}
	inputs = append(inputs, artifact.NewFile("input.sh", []byte("cat > .yarnrc.yml <<'EOF'\nnpmRegistryServer: https://private.invalid\nEOF\n"), false))
	docs := analyzer.PrepareDerived(context.Background(), document.PrepareAllWithRegistry(context.Background(), inputs, registry))
	out, err := pluginRule(t, "NV-SC10").Find(context.Background(), docs[len(docs)-1], 16)
	if err != nil || len(out.Matches) > 0 || !out.Truncated {
		t.Fatalf("nested parser reset aggregate quota: %+v %v", out, err)
	}
}

func TestParsedPythonPackageSourceFormats(t *testing.T) {
	registry, err := parse.WithFrontends(frontend.Options{TOML: true, Timeout: frontend.DefaultOptions().Timeout})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, text string
		count            int
	}{
		{
			name:  "pipfile-private",
			path:  "Pipfile",
			text:  "[[source]]\nurl = 'https://private.invalid/simple'\n",
			count: 1,
		},
		{name: "pipfile-default", path: "Pipfile", text: "[[source]]\nurl = 'https://pypi.org/simple'\n", count: 0},
		{name: "pipfile-empty", path: "Pipfile", text: "[packages]\n", count: 0},
		{
			name:  "pipfile-meta",
			path:  "Pipfile.lock",
			text:  `{"_meta":{"sources":[{"url":"https://private.invalid/simple"}]}}`,
			count: 1,
		},
		{
			name:  "pipfile-meta-default",
			path:  "Pipfile.lock",
			text:  `{"_meta":{"sources":[{"url":"https://pypi.org/simple"}]}}`,
			count: 0,
		},
		{
			name:  "uv-registry",
			path:  "uv.lock",
			text:  "[[package]]\nname = 'a'\nsource = { registry = 'https://private.invalid/simple' }\n",
			count: 1,
		},
		{
			name:  "uv-default",
			path:  "uv.lock",
			text:  "[[package]]\nname = 'a'\nsource = { registry = 'https://pypi.org/simple' }\n",
			count: 0,
		},
		{name: "uv-no-source", path: "uv.lock", text: "[[package]]\nname = 'a'\n", count: 0},
		{
			name:  "poetry-url",
			path:  "poetry.lock",
			text:  "[[package]]\nname = 'a'\nsource = { url = 'https://private.invalid/simple' }\n",
			count: 1,
		},
		{
			name:  "poetry-unresolved",
			path:  "poetry.lock",
			text:  "[[package]]\nname = 'a'\nsource = { type = 'git' }\n",
			count: 1,
		},
		{name: "lock-no-packages", path: "uv.lock", text: "version = 1\n", count: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := document.PrepareAllWithRegistry(context.Background(), []artifact.File{artifact.NewFile(tc.path, []byte(tc.text), false)}, registry)[0]
			out, err := pluginRule(t, "NV-SC10").Find(context.Background(), doc, 10)
			if err != nil || out.Truncated || len(out.Matches) != tc.count {
				t.Fatalf("source declaration mismatch: %+v %v; diagnostics=%+v units=%+v", out, err, doc.Diagnostics(), doc.Units())
			}
			for _, match := range out.Matches {
				if match.Start < 0 || match.End > len(tc.text) || match.End <= match.Start {
					t.Fatal("invalid source evidence", match)
				}
			}
		})
	}
}
