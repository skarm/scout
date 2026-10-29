package review

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/knowledge"
)

// Router deterministically selects an explicitly configured provider for each
// semantic stage. It never retries another model after an error. Providers and
// endpoints are operator code/configuration, never selected from scanned data.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type Router struct {
	providers map[string]Provider
	identity  Identity
}

// NewRouter validates explicit mode overrides and a required default provider.
// It copies routing configuration and never configures fallback retries.
func NewRouter(defaultProvider Provider, overrides map[string]Provider) (*Router, error) {
	if defaultProvider == nil {
		return nil, errors.New("explicit default review provider required")
	}

	if e := defaultProvider.Identity().Validate(); e != nil {
		return nil, e
	}

	r := &Router{providers: map[string]Provider{}}
	ids := map[string]Identity{}

	modes := knowledge.Modes()
	for _, mode := range modes {
		r.providers[mode] = defaultProvider
	}

	for mode, p := range overrides {
		if _, ok := r.providers[mode]; !ok || p == nil {
			return nil, errors.New("invalid provider route")
		}

		if e := p.Identity().Validate(); e != nil {
			return nil, e
		}

		r.providers[mode] = p
	}

	for _, mode := range modes {
		ids[mode] = r.providers[mode].Identity()
	}

	b, _ := json.Marshal(ids)
	h := hashBytes(b)
	r.identity = Identity{Provider: "explicit-mode-router", Model: "routes:" + h, SettingsSHA256: h}

	return r, nil
}

// Identity returns the digest-bound identity of the configured provider
// routes.
func (r *Router) Identity() Identity { return r.identity }

// Routes returns an independent map of review modes to requested provider
// identities.
func (r *Router) Routes() map[string]Identity {
	out := map[string]Identity{}
	for k, p := range r.providers {
		out[k] = p.Identity()
	}

	return out
}

// Complete dispatches a bounded, unambiguous request to its configured mode
// provider. Provider failure does not select another route.
func (r *Router) Complete(ctx context.Context, b []byte) (Completion, error) {
	if ctx == nil || len(b) > MaxRequestBytes {
		return Completion{}, errors.New("invalid routed request")
	}

	tree, e := jsonconfig.Parse(ctx, string(b))
	if e != nil {
		return Completion{}, errors.New("ambiguous routed request")
	}

	mode, ok := tree.Get("mode").Text()

	p := r.providers[mode]
	if !ok || p == nil {
		return Completion{}, errors.New("unknown review mode")
	}
	// No fallback: the caller's ledger retains the selected provider's failure.
	return p.Complete(ctx, b)
}
