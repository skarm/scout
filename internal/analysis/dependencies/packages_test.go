package dependencies_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/internal/analysis/dependencies"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/scantest"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/report"
)

func TestPackageDeclarations(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		count     int
	}{
		{
			name:  "package.json",
			src:   `{"dependencies":{"sample":"1.2.3","other":"^2.0.0","remote":"https://user:PRIVATE_PASSWORD@example.invalid/archive"}}`,
			count: 3,
		},
		{
			name:  "package-lock.json",
			src:   `{"lockfileVersion":3,"packages":{"":{"name":"root","version":"1.0.0"},"node_modules/sample":{"version":"1.2.3"},"node_modules/a/node_modules/b":{"version":"2.3.4"}}}`,
			count: 2,
		},
		{
			name:  "npm-shrinkwrap.json",
			src:   `{"lockfileVersion":1,"dependencies":{"sample":{"version":"1.2.3","dependencies":{"nested":{"version":"2.0.0"}}}}}`,
			count: 2,
		},
		{
			name:  "Pipfile.lock",
			src:   `{"default":{"requests":{"version":"==2.32.3"}},"develop":{"pytest":{"version":"==8.0.0"}}}`,
			count: 2,
		},
		{name: "requirements.txt", src: "requests==2.32.3\npackage>=1.0\n-r /tmp/DO_NOT_READ\n", count: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile(tc.name, []byte(tc.src), false)})
			r := dependencies.Collect(context.Background(), d)
			if len(r.Declarations) != tc.count {
				t.Fatalf("%+v", r)
			}
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), "PRIVATE_PASSWORD") {
				t.Fatal("credential leaked")
			}
			for _, x := range r.Declarations {
				if x.Source.ByteEnd > len(tc.src) || x.Source.SpanSHA256 == "" {
					t.Fatal("evidence")
				}
			}
		})
	}
}

func TestInvalidLockfileDoesNotBecomeEmptyClean(t *testing.T) {
	d := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("package-lock.json", []byte(`{"packages":{},"packages":{"hidden":{}}}`), false)})
	r := dependencies.Collect(context.Background(), d)
	if len(r.Manifests) != 1 || r.Manifests[0].Status == "completed" {
		t.Fatalf("%+v", r)
	}
}

func TestNPMShortVersionsAreRanges(t *testing.T) {
	docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("package.json", []byte(`{"dependencies":{"one":"1","two":"1.2","three":"1.2.3","pre":"1.2.3-beta.1"}}`), false)})
	r := dependencies.Collect(context.Background(), docs)
	for _, d := range r.Declarations {
		exact := d.VersionSemantics == "exact-declaration-not-install-evidence"
		want := d.Module == "three" || d.Module == "pre"
		if exact != want {
			t.Fatalf("%+v", d)
		}
	}
}

func TestPipfileLockCategoriesReachAdvisoryLookup(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	options := osv.DefaultOptions()
	options.Enabled = true
	var err error
	options.Offline, err = json.Marshal(osv.Cache{Version: 1, QueriedAt: now, Records: []osv.Record{{
		Ecosystem: "PyPI", Name: "sample", Version: "1.2.3", Vulnerabilities: []osv.ID{{ID: "GHSA-fixture"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, category := range []string{"default", "develop", "docs", "tests"} {
		t.Run(category, func(t *testing.T) {
			text := fmt.Sprintf(`{"%s":{"sample":{"version":"==1.2.3"}}}`, category)
			deps := pipfileDeclarations(text)
			result, err := osv.Check(t.Context(), deps, options, now)
			if err != nil || result.Completeness != report.Complete || len(result.Matches) != 1 || len(result.Queries) != 1 {
				t.Fatalf("category disappeared from advisory scope: deps=%+v result=%+v err=%v", deps, result, err)
			}
		})
	}
	for _, text := range []string{`{"docs":[]}`, `{"docs":false}`, `{"docs":{"sample":{}}}`} {
		deps := pipfileDeclarations(text)
		if deps.Manifests[0].InventoryComplete() {
			t.Fatalf("malformed category became a complete inventory: %s", text)
		}
	}
}

func TestPipfileLockRespectsPackageIndexIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, sources, declaration string
		exact                      bool
	}{
		{name: "public", sources: `[{"name":"pypi","url":"https://pypi.org/simple"}]`, declaration: `"version":"==1.2.3","index":"pypi"`, exact: true},
		{name: "private", sources: `[{"name":"private","url":"https://private.invalid/simple"}]`, declaration: `"version":"==1.2.3","index":"private"`},
		{name: "default-private", sources: `[{"name":"private","url":"https://private.invalid/simple"}]`, declaration: `"version":"==1.2.3"`},
		{name: "unknown-index", sources: `[{"name":"pypi","url":"https://pypi.org/simple"}]`, declaration: `"version":"==1.2.3","index":"missing"`},
		{name: "invalid-index", sources: `[{"name":"pypi","url":"https://pypi.org/simple"}]`, declaration: `"version":"==1.2.3","index":true`},
		{name: "malformed-sources", sources: `{}`, declaration: `"version":"==1.2.3"`},
		{name: "duplicate-index", sources: `[{"name":"pypi","url":"https://pypi.org/simple"},{"name":"pypi","url":"https://private.invalid/simple"}]`, declaration: `"version":"==1.2.3","index":"pypi"`},
		{name: "git", sources: `[{"name":"pypi","url":"https://pypi.org/simple"}]`, declaration: `"version":"==1.2.3","git":"https://example.invalid/fork"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := fmt.Sprintf(`{"_meta":{"sources":%s},"default":{"sample":{%s}}}`, tc.sources, tc.declaration)
			deps := pipfileDeclarations(text)
			if len(deps.Declarations) != 1 {
				t.Fatal("declaration was discarded", deps)
			}
			if got := deps.Declarations[0].VersionSemantics == report.VersionExactLockfile; got != tc.exact {
				t.Fatalf("origin changed public ecosystem identity: %+v", deps.Declarations[0])
			}
		})
	}
	for _, metadata := range []string{`null`, `[]`, `false`, `{"sources":false}`, `{"sources":[{"name":"pypi"}]}`} {
		text := fmt.Sprintf(`{"_meta":%s,"default":{"sample":{"version":"==1.2.3"}}}`, metadata)
		deps := pipfileDeclarations(text)
		if len(deps.Declarations) != 1 || deps.Manifests[0].InventoryComplete() || deps.Declarations[0].VersionSemantics != report.VersionUnresolved {
			t.Fatalf("malformed provenance became a public coordinate: %s: %+v", metadata, deps)
		}
	}
}

func pipfileDeclarations(text string) report.DependencyReport {
	ctx := context.Background()
	docs := document.PrepareAll(ctx, []artifact.File{artifact.NewFile("Pipfile.lock", []byte(text), false)})
	return dependencies.Collect(ctx, docs)
}

func TestRequirementsSourcesConstrainPublicAdvisories(t *testing.T) {
	config := scantest.DefaultConfig()
	options := osv.DefaultOptions()
	options.Enabled = true
	var err error
	options.Offline, err = json.Marshal(osv.Cache{Version: 1, QueriedAt: time.Now().UTC(), Records: []osv.Record{{
		Ecosystem: "PyPI", Name: "sample", Version: "1.2.3", Vulnerabilities: []osv.ID{{ID: "GHSA-fixture-only"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	config.Scanner.Vulnerabilities = &options
	scanner, err := scantest.New(config, t)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, text string
		exact      bool
	}{
		{"no override", "sample==1.2.3\n", true},
		{"comment", "# --index-url https://private.invalid/simple\nsample==1.2.3\n", true},
		{"public", "--index-url https://pypi.org/simple\nsample==1.2.3\n", true},
		{"public extra", "--extra-index-url=https://pypi.org/simple/\nsample==1.2.3\n", true},
		{"public quoted", "-i 'https://pypi.org/simple'\nsample==1.2.3\n", true},
		{"last public index", "-i https://private.invalid/simple\n-i https://pypi.org/simple\nsample==1.2.3\n", true},
		{"last private index", "-i https://pypi.org/simple\n-i https://private.invalid/simple\nsample==1.2.3\n", false},
		{"same line alternate", "--index-url https://pypi.org/simple --extra-index-url https://private.invalid/simple\nsample==1.2.3\n", false},
		{"extra index cannot be reset", "--extra-index-url https://private.invalid/simple\n-i https://pypi.org/simple\nsample==1.2.3\n", false},
		{"private before", "--index-url https://private.invalid/simple\nsample==1.2.3\n", false},
		{"private after", "sample==1.2.3\n--index-url https://private.invalid/simple\n", false},
		{"private equals", "--index-url=https://private.invalid/simple\nsample==1.2.3\n", false},
		{"private short", "-ihttps://private.invalid/simple\nsample==1.2.3\n", false},
		{"extra index", "sample==1.2.3\n--extra-index-url https://private.invalid/simple\n", false},
		{"local links", "--no-index\n-f /not-opened\nsample==1.2.3\n", false},
		{"include", "sample==1.2.3\n-r /not-opened\n", false},
		{"constraints", "sample==1.2.3\n--constraint=/not-opened\n", false},
		{"find links", "sample==1.2.3\n--find-links=https://private.invalid/wheels\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := scanner.ScanBytes(t.Context(), "requirements.txt", []byte(tc.text))
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}
			if err := report.ValidateSealedRun(result.Run); err != nil {
				t.Fatal(err)
			}
			if len(result.Dependencies.Declarations) != 1 || len(result.Vulnerabilities.Queries) != 1 {
				t.Fatalf("lost declaration/query: %+v %+v", result.Dependencies, result.Vulnerabilities)
			}
			declaration := result.Dependencies.Declarations[0]
			if got := declaration.VersionSemantics == report.VersionExactDeclaration; got != tc.exact {
				t.Errorf("public coordinate=%t want=%t: %+v", got, tc.exact, declaration)
			}
			if !strings.Contains(tc.text[declaration.Source.ByteStart:declaration.Source.ByteEnd], "sample==1.2.3") {
				t.Fatal("lost physical declaration evidence")
			}
			count := 0
			for _, finding := range result.Findings {
				if finding.RuleID == "OSV001" {
					count++
				}
			}
			want := 0
			if tc.exact {
				want = 1
			}
			if count != want || len(result.Vulnerabilities.Matches) != want {
				t.Errorf("public advisory findings=%d matches=%d want=%d", count, len(result.Vulnerabilities.Matches), want)
			}
			if !tc.exact && (result.Vulnerabilities.Queries[0].Status != "unresolved_version" || !errors.Is(err, scantest.ErrIncomplete)) {
				t.Errorf("unresolved origin lost partial state: %+v err=%v", result.Vulnerabilities, err)
			}
		})
	}
}
