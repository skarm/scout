package review_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/review"
)

func TestRouterAcceptsEveryPublishedPromptMode(t *testing.T) {
	calls := 0
	p := routedProvider{name: "all-stages", n: &calls, fail: false}
	router, err := review.NewRouter(p, map[string]review.Provider{"tool_consistency": p})
	if err != nil {
		t.Fatal(err)
	}
	for _, prompt := range knowledge.Inventory().Prompts {
		t.Run(prompt.Mode, func(t *testing.T) {
			payload, err := json.Marshal(map[string]string{"mode": prompt.Mode})
			if err != nil {
				t.Fatal(err)
			}
			before := calls
			if _, err := router.Complete(context.Background(), payload); err != nil || calls != before+1 {
				t.Fatalf("published stage cannot reach its provider: %v", err)
			}
		})
	}
	modes := knowledge.Modes()
	modes[0] = "caller-controlled"
	if _, err := review.NewRouter(p, map[string]review.Provider{"caller-controlled": p}); err == nil {
		t.Fatal("caller changed the supported route set")
	}
}

func TestExplicitModeRoutingWithoutFallback(t *testing.T) {
	a, b := 0, 0
	first := routedProvider{name: "first", n: &a, fail: false}
	second := routedProvider{name: "second", n: &b, fail: true}
	r, e := review.NewRouter(first, map[string]review.Provider{"proposal_assessment": second})
	if e != nil {
		t.Fatal(e)
	}
	_, e = r.Complete(context.Background(), []byte(`{"mode":"proposal_assessment"}`))
	if e == nil || a != 0 || b != 1 {
		t.Fatal("hidden fallback")
	}
	_, e = r.Complete(context.Background(), []byte(`{"mode":"discovery"}`))
	if e != nil || a != 1 {
		t.Fatal(e)
	}
	for _, raw := range []string{`{"mode":"tool_execution"}`, `{"mode":"discovery","mode":"intent"}`} {
		if _, e := r.Complete(context.Background(), []byte(raw)); e == nil {
			t.Fatal("invalid route accepted")
		}
	}
	routesCopy := r.Routes()
	routesCopy["discovery"] = review.Identity{}
	if r.Routes()["discovery"].Model != "first" {
		t.Fatal("routes mutated")
	}
	other, _ := review.NewRouter(first, nil)
	if other.Identity() == r.Identity() {
		t.Fatal("route selection absent from digest")
	}
}

type routedProvider struct {
	name string
	n    *int
	fail bool
}

func (p routedProvider) Identity() review.Identity {
	return review.Identity{Provider: "fixture", Model: p.name}
}

func (p routedProvider) Complete(context.Context, []byte) (review.Completion, error) {
	*p.n++
	if p.fail {
		return review.Completion{}, errors.New("fixture failure")
	}
	return review.Completion{Model: p.name}, nil
}
