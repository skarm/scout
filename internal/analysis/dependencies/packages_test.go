package dependencies_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/dependencies"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
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
