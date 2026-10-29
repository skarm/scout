package analyzer_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
)

func TestRegistryFactsStaySeparateFromUnavailableEvidence(t *testing.T) {
	for _, tc := range []struct {
		id, text, severity, signal string
		count                      int
	}{
		{
			id:       "MCP-REPOSITORY",
			text:     `{"servers":[{"server":{"name":"a/b"}}]}`,
			severity: "info",
			signal:   "evidence_unavailable",
			count:    1,
		},
		{
			id:       "MCP-REPOSITORY",
			text:     `{"servers":[{"server":{"name":"a/b","repository":{"url":"https://example.invalid/repo"}}}]}`,
			severity: "",
			signal:   "",
			count:    0,
		},
		{
			id:       "MCP-OFFICIAL-STATUS",
			text:     `{"servers":[{"server":{"name":"a/b"},"_meta":{"io.modelcontextprotocol.registry/official":{"status":"deprecated"}}}]}`,
			severity: "medium",
			signal:   "registry_assertion",
			count:    1,
		},
		{
			id:       "MCP-OFFICIAL-STATUS",
			text:     `{"servers":[{"server":{"name":"a/b"},"_meta":{"io.modelcontextprotocol.registry/official":{"status":7}}}]}`,
			severity: "info",
			signal:   "evidence_unavailable",
			count:    1,
		},
		{
			id:       "MCP-OFFICIAL-STATUS",
			text:     `{"servers":[{"server":{"name":"a/b"},"_meta":{"io.modelcontextprotocol.registry/official":{"status":"active"}}}]}`,
			severity: "",
			signal:   "",
			count:    0,
		},
		{
			id:       "MCP-PLAIN-HTTP",
			text:     `{"servers":[{"server":{"name":"a/b","remotes":[{"url":"HTTP://example.invalid/mcp"}]}}]}`,
			severity: "high",
			signal:   "registry_assertion",
			count:    1,
		},
		{
			id:       "MCP-PLAIN-HTTP",
			text:     `{"servers":[{"server":{"name":"a/b","remotes":[{"url":"https://example.invalid/mcp"}]}}]}`,
			severity: "",
			signal:   "",
			count:    0,
		},
		{
			id:       "MCP-PLAIN-HTTP",
			text:     `{"mcpServers":{"local":{"url":"http://example.invalid"}}}`,
			severity: "",
			signal:   "",
			count:    0,
		},
		{
			id:       "MCP-PACKAGE-SHA256",
			text:     `{"servers":[{"server":{"name":"a/b","packages":[{"fileSha256":"bad"}]}}]}`,
			severity: "high",
			signal:   "registry_assertion",
			count:    1,
		},
		{
			id:       "MCP-PACKAGE-SHA256",
			text:     `{"servers":[{"server":{"name":"a/b","packages":[{"fileSha256":0}]}}]}`,
			severity: "info",
			signal:   "evidence_unavailable",
			count:    1,
		},
		{
			id:       "MCP-PACKAGE-VERSION",
			text:     `{"servers":[{"server":{"name":"a/b","packages":[{"version":false}]}}]}`,
			severity: "info",
			signal:   "evidence_unavailable",
			count:    1,
		},
	} {
		r, e := registryResult(t, tc.id, tc.text, 10)
		if e != nil || len(r.Matches) != tc.count {
			t.Fatalf("%s %+v %v", tc.id, r, e)
		}
		for _, m := range r.Matches {
			if string(m.Severity) != tc.severity || len(m.ContextSignals) != 1 || m.ContextSignals[0] != tc.signal || m.Start < 0 || m.End > len(tc.text) || m.Start >= m.End {
				t.Fatalf("invalid fact/evidence: %+v", m)
			}
		}
	}
}

func TestRegistryVersionAndDigestGrammar(t *testing.T) {
	for _, tc := range []struct {
		kind, version string
		want          bool
	}{
		{kind: "npm", version: "1.2.3", want: false},
		{kind: "npm", version: "v1.2.3-beta.1+build.4", want: false},
		{kind: "npm", version: "1.2", want: true},
		{kind: "npm", version: "latest", want: true},
		{kind: "npm", version: "LATEST", want: true},
		{kind: "npm", version: "^1.2.3", want: true},
		{kind: "npm", version: "1.2.x", want: true},
		{kind: "npm", version: "1.2.3\u00a0", want: true},
		{kind: "pypi", version: "1.2.3rc1", want: false},
		{kind: "pypi", version: "1.0.0-linux-x64", want: false},
		{kind: "pypi", version: "1.x", want: true},
		{kind: "pypi", version: ">=1.2", want: true},
		{kind: "pypi", version: "stable", want: true},
		{kind: "custom", version: "branch", want: true},
	} {
		text := fmt.Sprintf(`{"servers":[{"server":{"name":"a/b","packages":[{"registryType":%q,"version":%q}]}}]}`, tc.kind, tc.version)
		r, e := registryResult(t, "MCP-PACKAGE-VERSION", text, 1)
		if e != nil || (len(r.Matches) > 0) != tc.want {
			t.Fatalf("%s %s: %+v %v", tc.kind, tc.version, r, e)
		}
	}
	text := `{"servers":[{"server":{"name":"a/b","packages":[{"fileSha256":"` + strings.Repeat("a", 64) + `"}]}}]}`
	r, e := registryResult(t, "MCP-PACKAGE-SHA256", text, 1)
	if e != nil || len(r.Matches) != 0 {
		t.Fatal(r, e)
	}
}

func TestMalformedRegistryNeverInventsFacts(t *testing.T) {
	for _, text := range []string{
		`{"servers":[{"not_server":{}}]}`,
		`{"servers":[{"server":{"name":"a/b","packages":{}}}]}`,
		`{"servers":[{"server":{"name":"a/b","remotes":[1]}}]}`,
		`{"servers":[{"server":{"name":"a/b","repository":"owner"}}]}`,
	} {
		for _, a := range analyzer.RegistryRules() {
			r, e := a.Find(context.Background(), prepared(context.Background(), artifact.NewFile("snapshot.json", []byte(text), false)), 10)
			if e == nil || len(r.Matches) != 0 {
				t.Fatalf("%s %s: %+v %v", a.Rule().ID, text, r, e)
			}
		}
	}
}

func TestRegistryBudgetAndMappedFenceEvidence(t *testing.T) {
	text := `{"servers":[{"server":{"name":"a/b"}},{"server":{"name":"c/d"}}]}`
	r, e := registryResult(t, "MCP-REPOSITORY", text, 1)
	if e != nil || len(r.Matches) != 1 || !r.Truncated {
		t.Fatal(r, e)
	}
	raw := "🙂 registry example\n```json\n" + text + "\n```"
	for _, a := range analyzer.RegistryRules() {
		if a.Rule().ID != "MCP-REPOSITORY" {
			continue
		}
		d := document.Prepare(context.Background(), artifact.NewFile("README.md", []byte(raw), false))
		r, e := a.Find(context.Background(), prepared(context.Background(), d), 10)
		if e != nil || len(r.Matches) != 2 {
			t.Fatal(r, e)
		}
		for _, m := range r.Matches {
			if !strings.HasPrefix(raw[m.Start:m.End], `{"name"`) {
				t.Fatalf("invented coordinates: %q", raw[m.Start:m.End])
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, e = analyzer.RegistryRules()[0].Find(ctx, prepared(ctx, artifact.NewFile("snapshot.json", []byte(text), false)), 1)
	if e == nil {
		t.Fatal("cancelled inspection completed", r)
	}
}

func registryResult(t *testing.T, id, text string, budget int) (analyzer.Result, error) {
	t.Helper()
	for _, a := range analyzer.RegistryRules() {
		if a.Rule().ID == id {
			return a.Find(context.Background(), prepared(context.Background(), artifact.NewFile("snapshot.json", []byte(text), false)), budget)
		}
	}
	t.Fatal(id)
	return analyzer.Result{}, nil
}
