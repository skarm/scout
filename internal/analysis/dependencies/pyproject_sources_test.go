//go:build !coreonly && cgo

package dependencies_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/internal/scantest"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/report"
)

func TestPyprojectSourcesConstrainPublicAdvisories(t *testing.T) {
	config := scantest.DefaultConfig()
	config.Scanner.Checks.TOML = true
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
		{"no override", "", true},
		{"public default", "[[tool.uv.index]]\nurl='https://pypi.org/simple/'\ndefault=true\n", true},
		{"private default", "[[tool.uv.index]]\nurl='https://private.invalid/simple'\ndefault=true\n", false},
		{"private additional", "[[tool.uv.index]]\nurl='https://private.invalid/simple'\n", false},
		{"unrelated explicit private", "[[tool.uv.index]]\nname='private'\nurl='https://private.invalid/simple'\nexplicit=true\n", true},
		{"explicit private default", "[[tool.uv.index]]\nname='private'\nurl='https://private.invalid/simple'\nexplicit=true\ndefault=true\n", false},
		{"public pinned", "[tool.uv.sources]\nsample={index='public'}\n[[tool.uv.index]]\nname='public'\nurl='https://pypi.org/simple'\n", true},
		{"private pinned", "[tool.uv.sources]\nsample={index='private'}\n[[tool.uv.index]]\nname='private'\nurl='https://private.invalid/simple'\nexplicit=true\n", false},
		{"public pin overrides private default", "[tool.uv.sources]\nsample={index='public'}\n[[tool.uv.index]]\nname='public'\nurl='https://pypi.org/simple'\n[[tool.uv.index]]\nurl='https://private.invalid/simple'\ndefault=true\n", true},
		{"missing named index", "[tool.uv.sources]\nsample={index='missing'}\n", false},
		{"path source", "[tool.uv.sources]\nsample={path='/not-opened'}\n", false},
		{"unrelated source", "[tool.uv.sources]\nother={path='/not-opened'}\n", true},
		{"marker-dependent source", "[tool.uv.sources]\nsample=[{index='public',marker=\"sys_platform == 'linux'\"}]\n[[tool.uv.index]]\nname='public'\nurl='https://pypi.org/simple'\n", false},
		{"malformed source", "[tool.uv.sources]\nsample=3\n", false},
		{"duplicate index names", "[[tool.uv.index]]\nname='same'\nurl='https://pypi.org/simple'\n[[tool.uv.index]]\nname='same'\nurl='https://private.invalid/simple'\n", false},
		{"malformed explicit flag", "[[tool.uv.index]]\nurl='https://private.invalid/simple'\nexplicit='true'\n", false},
		{"legacy private index", "[tool.uv]\nindex-url='https://private.invalid/simple'\n", false},
		{"legacy public index", "[tool.uv]\nindex-url='https://pypi.org/simple'\n", true},
		{"private extra index", "[tool.uv]\nextra-index-url=['https://private.invalid/simple']\n", false},
		{"find links", "[tool.uv]\nfind-links=['/not-opened']\n", false},
		{"normalized package source", "[tool.uv.sources]\nSAMPLE={path='/not-opened'}\n", false},
		{"duplicate normalized package sources", "[tool.uv.sources]\nSAMPLE={index='public'}\nsample={path='/not-opened'}\n[[tool.uv.index]]\nname='public'\nurl='https://pypi.org/simple'\n", false},
		{"explicit public default without pin", "[[tool.uv.index]]\nname='public'\nurl='https://pypi.org/simple'\nexplicit=true\ndefault=true\n", false},
		{"sources disabled", "[tool.uv]\nno-sources=true\n[tool.uv.sources]\nsample={path='/not-opened'}\n", true},
		{"no index false", "[tool.uv]\nno-index=false\nfind-links=[]\n", true},
		{"no index true", "[tool.uv]\nno-index=true\n", false},
		{"simple index", "[[tool.uv.index]]\nurl='https://pypi.org/simple'\nformat='simple'\n", true},
		{"unknown format", "[[tool.uv.index]]\nurl='https://pypi.org/simple'\nformat='unknown'\n", false},
		{"flat index", "[[tool.uv.index]]\nurl='https://pypi.org/simple'\nformat='flat'\n", false},
		{"Poetry explicit PyPI", "[[tool.poetry.source]]\nname='PyPI'\npriority='primary'\n", true},
		{"Poetry public URL", "[[tool.poetry.source]]\nname='public'\nurl='https://pypi.org/simple'\npriority='primary'\n", true},
		{"Poetry missing private URL", "[[tool.poetry.source]]\nname='private'\npriority='primary'\n", false},
		{"Poetry mixed sources", "[[tool.poetry.source]]\nname='PyPI'\npriority='primary'\n[[tool.poetry.source]]\nname='private'\nurl='https://private.invalid/simple'\npriority='supplemental'\n", false},
		{"Poetry source", "[[tool.poetry.source]]\nname='private'\nurl='https://private.invalid/simple'\npriority='primary'\n", false},
	} {
		for _, shape := range []struct{ name, declaration string }{
			{"project", "[project]\nname='fixture'\nversion='0.0.1'\ndependencies=['sample==1.2.3']\n"},
			{"optional", "[project.optional-dependencies]\ntest=['sample==1.2.3']\n"},
			{"group", "[dependency-groups]\ntest=['sample==1.2.3']\n"},
			{"build", "[build-system]\nrequires=['sample==1.2.3']\n"},
		} {
			t.Run(tc.name+"/"+shape.name, func(t *testing.T) {
				text := shape.declaration + tc.text
				result, err := scanner.ScanBytes(t.Context(), "pyproject.toml", []byte(text))
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
				if !strings.Contains(text[declaration.Source.ByteStart:declaration.Source.ByteEnd], "sample==1.2.3") {
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
}
