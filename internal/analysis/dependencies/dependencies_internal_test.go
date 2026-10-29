// Exercises private implementation details and package fixtures.
package dependencies

import (
	"context"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
)

func TestTrustedNPMResolutionGrammar(t *testing.T) {
	for _, tc := range []struct {
		text    string
		trusted bool
	}{
		{text: `null`, trusted: false},
		{text: `1`, trusted: false},
		{text: `"https://registry.npmjs.org/sample/-/sample-1.2.3.tgz"`, trusted: true},
		{text: `"http://registry.npmjs.org/sample"`, trusted: false},
		{text: `"https://other.invalid/sample"`, trusted: false},
		{text: `"https://user:secret@registry.npmjs.org/sample"`, trusted: false},
		{text: `"https://registry.npmjs.org/sample?q=1"`, trusted: false},
		{text: `"https://registry.npmjs.org/sample#fragment"`, trusted: false},
		{text: `"https://%"`, trusted: false},
	} {
		n, err := jsonconfig.Parse(context.Background(), tc.text)
		if err != nil {
			t.Fatal(err)
		}
		if trustedNPMResolution(n) != tc.trusted {
			t.Fatal(tc)
		}
	}
	if !trustedNPMResolution(nil) {
		t.Fatal("absent origin should retain declaration semantics")
	}
}

func TestPythonTOMLDeclarationsRetainIncompleteStates(t *testing.T) {
	if !frontend.BackendFor("toml").Available {
		t.Skip("TOML parser unavailable in this build")
	}
	options := frontend.DefaultOptions()
	options.TOML = true
	registry, err := parse.WithFrontends(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, text string
		count      int
		complete   bool
	}{
		{
			name:     "pyproject.toml",
			text:     "[project]\ndependencies=['requests==2.32.3']\n[project.optional-dependencies]\ntest=['pytest>=8']\n[build-system]\nrequires=['build==1.0']\n",
			count:    3,
			complete: false,
		},
		{
			name:     "pyproject.toml",
			text:     "[tool.poetry.dependencies]\npython='^3.12'\nrequests={version='^2',source='other'}\n[tool.poetry.dev-dependencies]\npytest='^8'\n[tool.poetry.group.dev]\n",
			count:    2,
			complete: false,
		},
		{
			name:     "pyproject.toml",
			text:     "[project]\ndependencies=false\noptional-dependencies=false\n",
			count:    0,
			complete: false,
		},
		{name: "pyproject.toml", text: "[project]\ndependencies=[1,'@invalid']\n", count: 0, complete: false},
		{name: "pyproject.toml", text: "[tool.poetry]\ndependencies=false\n", count: 0, complete: false},
		{
			name:     "Pipfile",
			text:     "[packages]\nrequests='==2.32.3'\n[dev-packages]\npytest={version='>=8'}\n",
			count:    2,
			complete: false,
		},
		{name: "Pipfile", text: "packages=[]\n", count: 0, complete: false},
		{
			name:     "uv.lock",
			text:     "[[package]]\nname='requests'\nversion='2.32.3'\nsource={registry='https://pypi.org/simple'}\n",
			count:    1,
			complete: true,
		},
		{
			name:     "uv.lock",
			text:     "[[package]]\nname='requests'\nversion='2.32.3'\nsource={registry='https://other.invalid/simple'}\n",
			count:    1,
			complete: false,
		},
		{name: "uv.lock", text: "[[package]]\nversion='2.32.3'\n", count: 0, complete: false},
		{
			name:     "poetry.lock",
			text:     "[[package]]\nname='requests'\nversion='2.32.3'\nsource={type='legacy',url='https://pypi.org/simple/'}\n",
			count:    1,
			complete: true,
		},
		{
			name:     "poetry.lock",
			text:     "[[package]]\nname='requests'\nversion='2.32.3'\nsource={type='git',url='https://other.invalid'}\n",
			count:    1,
			complete: false,
		},
		{name: "poetry.lock", text: "package=false\n", count: 0, complete: false},
	} {
		t.Run(tc.name+tc.text, func(t *testing.T) {
			docs := document.PrepareAllWithRegistry(context.Background(), []artifact.File{artifact.NewFile(tc.name, []byte(tc.text), false)}, registry)
			r := Collect(context.Background(), docs)
			if len(r.Declarations) != tc.count || len(r.Manifests) != 1 || r.Manifests[0].InventoryComplete() != tc.complete {
				t.Fatal(r)
			}
		})
	}
}

func TestCancelledDeclarationInventoryRemainsIncomplete(t *testing.T) {
	docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("go.mod", []byte("module example.invalid/demo\nrequire example.invalid/dep v1.2.3\n"), false), artifact.NewFile("requirements.txt", []byte("requests==2.32.3\n"), false)})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Collect(ctx, docs)
	if len(r.Manifests) != 1 || r.Manifests[0].Status != "cancelled" {
		t.Fatal(r)
	}
}
