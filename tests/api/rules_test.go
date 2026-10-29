package scout_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/skarm/scout/internal/scantest"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
)

func TestPublishedCatalogDescribesSelectedChecks(t *testing.T) {
	all := map[string]scantest.Rule{}
	for _, rule := range scantest.Rules(true) {
		if _, exists := all[rule.ID]; exists || rule.ID == "" {
			t.Fatalf("duplicate or empty rule: %q", rule.ID)
		}
		all[rule.ID] = rule
	}
	for _, name := range []string{"basic", "extended"} {
		t.Run(name, func(t *testing.T) {
			config := scantest.DefaultConfig()
			if name == "extended" {
				config = scantest.FullConfig()
			}
			missing := name == "extended" && (!frontend.BackendFor("python").Available || !signatures.Backend().Available)
			scanner, err := scantest.New(config, t)
			if missing {
				if err == nil {
					if err := scanner.Close(); err != nil {
						t.Error(err)
					}
					t.Fatal("unavailable required backend accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			report, err := scanner.ScanBytes(context.Background(), "notes.txt", []byte("Public documentation."))
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}
			selected := map[string]scantest.Rule{}
			for _, rule := range report.Rules {
				if !reflect.DeepEqual(all[rule.ID], rule) {
					t.Fatalf("published descriptor disagrees with executed check %q", rule.ID)
				}
				selected[rule.ID] = rule
			}
			if name == "basic" {
				if len(selected) != len(scantest.Rules(false)) {
					t.Fatal("basic catalog differs from selected check set")
				}
				for _, rule := range scantest.Rules(false) {
					if !reflect.DeepEqual(selected[rule.ID], rule) {
						t.Fatalf("basic descriptor disagrees with executed check %q", rule.ID)
					}
				}
			}
		})
	}
}

func TestPublishedCatalogCannotChangeLaterScans(t *testing.T) {
	original := scantest.Rules(true)
	changed := scantest.Rules(true)
	for i := range changed {
		changed[i].ID = "caller-controlled"
		if g := changed[i].Guidance; g != nil {
			g.Explanation = "caller-controlled"
			if len(g.ReviewChecks) > 0 {
				g.ReviewChecks[0] = "caller-controlled"
			}
			if len(g.Sources) > 0 {
				g.Sources[0].URL = "caller-controlled"
			}
		}
	}
	if !reflect.DeepEqual(original, scantest.Rules(true)) {
		t.Fatal("published catalog mutated trusted descriptors")
	}
}
