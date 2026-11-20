package rulepack_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/skarm/scout/report"
	"github.com/skarm/scout/rulepack"
)

const (
	sampleRules       = "rule sample { condition: true }\n"
	sampleRulesSHA256 = "aca6aa1a2a7dad5e6e6f8f3a2bc6a187fa560b1b6a021316745c9e2151546988"
)

func TestParsePinnedArtifact(t *testing.T) {
	const artifact = `{"schema":"scout.rulepack/v1","id":"team/sample","version":"1.2.3","abi":"scout.yara-source/v1","yara":{"sha256":"` + sampleRulesSHA256 + `","source":"rule sample { condition: true }\n"}}`
	data := []byte(artifact)
	digest := sha256.Sum256(data)
	pin := hex.EncodeToString(digest[:])
	got, err := rulepack.Parse(data, pin)
	if err != nil {
		t.Fatalf("Parse() pinned fixture: %v", err)
	}
	want := report.RulepackIdentity{
		ID: "team/sample", Version: "1.2.3", ABI: "scout.yara-source/v1", SHA256: pin, RulesSHA256: sampleRulesSHA256,
	}
	if got.Identity != want || string(got.Rules) != sampleRules {
		t.Errorf("Parse() = %+v with source %q; want %+v with source %q", got.Identity, got.Rules, want, sampleRules)
	}

	withWhitespace := append([]byte(artifact), '\n')
	if _, err := rulepack.Parse(withWhitespace, ""); err != nil {
		t.Fatalf("Parse() unpinned fixture with trailing whitespace: %v", err)
	}
	if _, err := rulepack.Parse(withWhitespace, pin); err == nil {
		t.Error("Parse() accepted different artifact bytes with the original pin")
	}
}

func TestCreateIsDeterministic(t *testing.T) {
	first, err := rulepack.Create("team/sample", "1.2.3", []byte(sampleRules))
	if err != nil {
		t.Fatalf("first Create(): %v", err)
	}
	second, err := rulepack.Create("team/sample", "1.2.3", []byte(sampleRules))
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("second Create() = %q, %v; want %q, nil", second, err, first)
	}
	got, err := rulepack.Parse(first, "")
	if err != nil || got.Identity.ID != "team/sample" || got.Identity.Version != "1.2.3" || got.Identity.RulesSHA256 != sampleRulesSHA256 || string(got.Rules) != sampleRules {
		t.Fatalf("Parse(Create()) = %+v with source %q and error %v; want team/sample 1.2.3 with digest %s and source %q", got.Identity, got.Rules, err, sampleRulesSHA256, sampleRules)
	}
}
