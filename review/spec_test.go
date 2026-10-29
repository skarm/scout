package review_test

import (
	"testing"

	"github.com/skarm/scout/review"
)

func TestProviderSpecValidationPrecedesCredentialLookup(t *testing.T) {
	spec := review.DefaultProviderSpec()
	spec.Kind, spec.Endpoint, spec.Model = "bedrock", "https://example.invalid/model/test/invoke", "test"
	spec.Region, spec.AccessEnv, spec.SecretEnv = "us-east-1", "ACCESS", "BAD-NAME"
	calls := 0
	if _, err := spec.Build(func(string) (string, bool) { calls++; return "fixture-value", true }); err == nil || calls != 0 {
		t.Fatalf("invalid name reached credential lookup: calls=%d err=%v", calls, err)
	}
	spec.SecretEnv = "SECRET"
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("passive validation accessed credentials")
	}
}

func TestProviderSpecBuildUsesOnlyExplicitEnvironmentNames(t *testing.T) {
	spec := review.DefaultProviderSpec()
	spec.Endpoint, spec.Model, spec.KeyEnv = "https://example.invalid/v1/chat/completions", "test", "EXPLICIT_KEY"
	calls := 0
	provider, err := spec.Build(func(name string) (string, bool) { calls++; return "fixture-key", name == "EXPLICIT_KEY" })
	if err != nil || calls != 1 || provider.Identity().Model != "test" {
		t.Fatalf("provider=%v calls=%d err=%v", provider, calls, err)
	}
	if _, err := spec.Build(nil); err == nil {
		t.Fatal("missing lookup silently discovered credentials")
	}
}
