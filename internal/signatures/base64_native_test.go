//go:build !coreonly && cgo

//nolint:testpackage // Differential oracle exercises the private projection against the original native rule.
package signatures

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	yrx "github.com/VirusTotal/yara-x/go"
)

func TestLongBase64MatchesNativeOracle(t *testing.T) {
	rules, err := yrx.Compile(`rule Original { strings: $a=/[A-Za-z0-9+\/]{120,}={0,2}/ condition:$a }`)
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Destroy()
	scanner := yrx.NewScanner(rules)
	defer scanner.Destroy()
	scanner.SetTimeout(30 * time.Second)
	cases := make([][]byte, 0, 45)
	cases = append(cases, nil, []byte("plain text"), []byte(strings.Repeat("x ", 300)))
	for _, n := range []int{119, 120, 121, 127, 128, 4093, 4094, 4095, 4096, 4097} {
		for _, padding := range []string{"", "=", "==", "==="} {
			cases = append(cases, []byte("!"+strings.Repeat("x", n)+padding+"!"))
		}
	}
	cases = append(cases, []byte(strings.Repeat(strings.Repeat("+/Ab9", 24)+"==!", 12)))
	cases = append(cases, append([]byte{0, 0xff, 0xc3, 0xa9}, []byte(strings.Repeat("+/", 65)+"==\x00")...))
	for i, data := range cases {
		result, err := scanner.Scan(data)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		var want []Span
		for _, rule := range result.MatchingRules() {
			for _, pattern := range rule.Patterns() {
				matches := pattern.Matches()
				for _, hit := range matches[:min(9, len(matches))] {
					want = append(want, Span{Start: int(hit.Offset()), End: int(hit.Offset() + hit.Length())})
				}
			}
		}
		if got := longBase64Spans(data); !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d: got %v want %v", i, got, want)
		}
	}
}

func TestMetadataRuleProjectionMatchesOriginal(t *testing.T) {
	legacy := strings.Replace(agentRules, "or scout_long_base64 or", "or $long_base64 or", 1)
	legacy = strings.Replace(legacy, "  $rtl_lro =", "  $long_base64 = /[A-Za-z0-9+\\/]{120,}={0,2}/\n  $rtl_lro =", 1)
	rules, err := yrx.Compile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Destroy()
	scanner := yrx.NewScanner(rules)
	defer scanner.Destroy()
	scanner.SetTimeout(30 * time.Second)
	engine, err := compileRules(t.Context(), agentRules)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.close()
	original, err := os.ReadFile("testdata/yara-load-original.txt")
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{string(original), "description: " + strings.Repeat("x", 120), "description: " + strings.Repeat("x", 121) + "==", "description: ordinary words", strings.Repeat("x", 130), "description: <!--SYSTEM-->\n" + strings.Repeat("x", 130), strings.Repeat("description: ", 10) + strings.Repeat("x", 130), "description: data:text/plain;base64," + strings.Repeat("x", 130) + " description ignore previous", "description: <!--SYSTEM-->\n", "description: ordinary words"}
	for i, data := range cases {
		result, err := scanner.Scan([]byte(data))
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		want, truncated, err := collectNativeRules(result.MatchingRules(), nativeSource{data: []byte(data), text: data})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		got, err := engine.scan(ctx, []byte(data))
		cancel()
		if err != nil || got.Status != "completed" || got.Truncated != truncated || !reflect.DeepEqual(got.Matches, want) {
			t.Fatalf("case %d: got %+v err=%v want %v truncated=%v", i, got, err, want, truncated)
		}
	}
}
