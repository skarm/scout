//nolint:testpackage // Exercises the native reply boundary without a native backend.
package signatures

import (
	"testing"

	"github.com/skarm/scout/report"
)

func TestReplyRejectsUnownedSeverity(t *testing.T) {
	for _, tc := range []struct {
		rule     string
		severity report.Severity
		valid    bool
	}{
		{rule: webhookRule, severity: report.Medium, valid: true},
		{rule: webhookRule, severity: report.High, valid: false},
		{rule: remoteBootstrapRule, severity: report.Low, valid: true},
		{rule: remoteBootstrapRule, severity: report.High, valid: true},
		{rule: metadataPoisoningRule, severity: report.Low, valid: true},
		{rule: metadataPoisoningRule, severity: report.High, valid: true},
		{rule: metadataPoisoningRule, severity: report.Critical, valid: false},
		{rule: "reverse_shell", severity: report.High, valid: true},
		{rule: "reverse_shell", severity: report.Low, valid: false},
		{rule: "info_stealer", severity: report.Low, valid: true},
		{rule: "info_stealer", severity: report.Medium, valid: true},
		{rule: "info_stealer", severity: report.High, valid: true},
		{rule: "info_stealer", severity: report.Critical, valid: false},
		{rule: "Operator", severity: "", valid: true},
		{rule: "Operator", severity: report.Low, valid: false},
		{rule: "Operator", severity: report.Critical, valid: false},
	} {
		match := Match{Rule: tc.rule, Category: "malware", Spans: []Span{{Start: 0, End: 1}}, Severity: tc.severity}
		if err := validateReply(reply{Status: "completed", Matches: []Match{match}}, 1); (err == nil) != tc.valid {
			t.Fatalf("rule=%s severity=%s accepted=%v want=%v: %v", tc.rule, tc.severity, err == nil, tc.valid, err)
		}
	}
}
