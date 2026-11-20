//go:build !coreonly && cgo

//nolint:testpackage // Exercises internal witness projections with inert YARA-X patterns.
package signatures

import (
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/report"

	yrx "github.com/VirusTotal/yara-x/go"
)

func TestAlternativeWitnessesComeFromCompletePatternGroup(t *testing.T) {
	// The detector's two alternative pattern groups use inert stand-ins here.
	rules, err := yrx.Compile(`rule Scout_Cisco_EncodedArchive_StageExec {
		strings:
			$py_decode = "MARK_A1"
			$py_archive = "MARK_A2"
			$py_extract = "MARK_A3"
			$py_exec = "MARK_A4"
			$sh_decode = "MARK_B1"
			$sh_archive = "MARK_B2"
			$sh_exec = "MARK_B3"
		condition: all of ($py_*) or all of ($sh_*)
	}`)
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Destroy()
	scanner := yrx.NewScanner(rules)
	defer scanner.Destroy()
	scanner.SetTimeout(time.Second)

	const first = "MARK_A1 MARK_A2 MARK_A3 MARK_A4"
	const second = "MARK_B1 MARK_B2 MARK_B3"
	for _, tc := range []struct {
		name, text, witnesses string
		truncated             bool
	}{
		{name: "first only", text: first, witnesses: first, truncated: false},
		{name: "second only", text: second, witnesses: second, truncated: false},
		{name: "both complete", text: first + " " + second, witnesses: first, truncated: false},
		{name: "only second complete", text: strings.Repeat("MARK_A1 ", 12) + "MARK_A2 " + second, witnesses: second, truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.text)
			result, err := scanner.Scan(data)
			if err != nil || len(result.MatchingRules()) != 1 {
				t.Fatalf("native match not returned: %v", err)
			}

			match, accepted, truncated, err := projectNativeRule(result.MatchingRules()[0], nativeSource{data: data, text: tc.text})
			if err != nil || !accepted || match.Severity != report.Medium || truncated != tc.truncated {
				t.Fatalf("projection changed verdict: %+v, accepted=%v, truncated=%v, err=%v", match, accepted, truncated, err)
			}

			want := strings.Fields(tc.witnesses)
			if len(match.Spans) < len(want) {
				t.Fatalf("missing witness spans: %+v", match.Spans)
			}

			for i, marker := range want {
				span := match.Spans[i]
				if got := tc.text[span.Start:span.End]; got != marker {
					t.Fatalf("witness %d = %q, want %q", i, got, marker)
				}
			}
		})
	}
}
