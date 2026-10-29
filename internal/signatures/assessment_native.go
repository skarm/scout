//go:build !coreonly && cgo

package signatures

import (
	"strings"

	"github.com/skarm/scout/internal/analysis/promptguard"
	"github.com/skarm/scout/report"

	yrx "github.com/VirusTotal/yara-x/go"
)

func strongAssessmentPattern(rule, pattern string) bool {
	if p1BaseSeverity(rule) != "" {
		return strings.HasPrefix(pattern, "$attack_") || rule == ransomwareRule &&
			(pattern == "$ransom_note" || pattern == "$payment_then_context" || pattern == contextPaymentPattern || pattern == "$explicit_ransom_payment")
	}

	return rule == remoteBootstrapRule && strings.HasPrefix(pattern, "$execute_") ||
		rule == metadataPoisoningRule && pattern == metadataInstruction
}

func assessmentPatternRank(rule, pattern string) int {
	if strongAssessmentPattern(rule, pattern) {
		return 0
	}

	if p1BaseSeverity(rule) != "" && (strings.HasPrefix(pattern, "$use_") || strings.HasPrefix(pattern, "$config_")) {
		return 1
	}

	return 2
}

func (s nativeSource) assessRule(rule string, patterns []yrx.Pattern) (report.Severity, bool, bool, error) {
	eligible, limited, err := s.selectPatterns(rule, patterns)
	if err != nil || !eligible {
		return "", eligible, limited, err
	}

	if p1BaseSeverity(rule) != "" {
		return s.assessP1Rule(rule, patterns)
	}

	if rule != metadataPoisoningRule && rule != remoteBootstrapRule {
		return builtinSeverity(rule, false), eligible, limited, nil
	}

	strong, weak, count := false, len(s.longBase64) > 0, 0
	for _, pattern := range patterns {
		if rule == metadataPoisoningRule && !strings.HasPrefix(pattern.Identifier(), "$schema_") && pattern.Identifier() != metadataInstruction && len(pattern.Matches()) > 0 {
			weak = true
		}

		if !strongAssessmentPattern(rule, pattern.Identifier()) {
			continue
		}

		for _, hit := range pattern.Matches() {
			count++
			if count > 4096 {
				return builtinSeverity(rule, strong), strong || weak, true, nil
			}

			span, err := s.span(hit)
			if err != nil {
				return "", false, limited, err
			}

			if s.acceptsInstance(rule, pattern.Identifier(), span) {
				strong = true
				break
			}
		}
	}

	if rule == metadataPoisoningRule {
		eligible = strong || weak
	}

	return builtinSeverity(rule, strong), eligible, limited, nil
}

func (s nativeSource) metadataProhibited(span Span) bool {
	if promptguard.Prohibited(s.text, span.Start, span.End) {
		return true
	}

	// Treat a metadata scalar's label and quotes as boundaries, retaining the
	// surrounding anti-reversal context used by the shared prohibition guard.
	left, right := max(0, span.Start-1024), min(len(s.text), span.End+1024)
	start, end := span.Start-left, span.End-left
	window := []byte(s.text[left:right])

	before := strings.LastIndexAny(string(window[:start]), "\r\n:\"")
	if before < 0 {
		return false
	}

	window[before] = '\n'
	if after := strings.IndexAny(string(window[end:]), "\r\n\""); after >= 0 {
		window[end+after] = '\n'
	}

	return promptguard.Prohibited(string(window), start, end)
}
