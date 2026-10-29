//go:build !coreonly && cgo

package signatures

import (
	"strings"

	"github.com/skarm/scout/report"

	yrx "github.com/VirusTotal/yara-x/go"
)

func (s nativeSource) assessP1Rule(rule string, patterns []yrx.Pattern) (report.Severity, bool, bool, error) {
	if len(s.p1RequiredPatterns(rule, patterns)) > 0 {
		return report.High, true, false, nil
	}

	severity := p1BaseSeverity(rule)
	eligible, count := false, 0

	for _, pattern := range patterns {
		if rule == multilineShellRule && !strings.HasPrefix(pattern.Identifier(), "$attack_") {
			continue
		}

		for _, hit := range pattern.Matches() {
			count++
			if count > 4096 {
				return severity, eligible, true, nil
			}

			span, err := s.span(hit)
			if err != nil {
				return "", false, false, err
			}

			if !s.acceptsInstance(rule, pattern.Identifier(), span) {
				continue
			}

			eligible = true

			if strongAssessmentPattern(rule, pattern.Identifier()) {
				return report.High, true, false, nil
			}

			if strings.HasPrefix(pattern.Identifier(), "$use_") || rule == ransomwareRule && pattern.Identifier() == "$ext_rename" {
				severity = report.Medium
			}

			break
		}
	}

	return severity, eligible, false, nil
}

// Complete structural combinations stay visible across padding and declaration
// reordering. Proximity only improves the witness; it never exempts a full chain.
func (s nativeSource) p1RequiredPatterns(rule string, patterns []yrx.Pattern) []string {
	var groups [][]string

	switch rule {
	case multilineShellRule:
		groups = [][]string{
			{pythonSocketPattern, "$py_redir", "$py_shell"},
			{pythonSocketPattern, "$py_redir", pythonShellAliasPattern},
			{pythonSocketPattern, pythonSocketStreamPattern, "$py_shell"},
			{pythonSocketPattern, pythonSocketStreamPattern, pythonShellAliasPattern},
			{"$pl_sock", "$pl_redir", "$pl_shell"},
		}
	case c2FrameworkRule:
		groups = [][]string{{"$config_type", "$config_server", "$config_public", "$config_watermark"}}
	default:
		return nil
	}

	for _, group := range groups {
		found := 0

		for _, name := range group {
			for _, pattern := range patterns {
				if pattern.Identifier() != name {
					continue
				}

				if _, ok := s.p1PatternWitness(pattern); ok {
					found++
					break
				}
			}
		}

		if found == len(group) {
			return group
		}
	}

	return nil
}

func (s nativeSource) seedP1Evidence(rule string, patterns []yrx.Pattern, collector *nativeSpanCollector) error {
	names := append(s.p1RequiredPatterns(rule, patterns), ciscoRequiredPatterns(rule, patterns)...)
	for _, name := range names {
		for _, pattern := range patterns {
			if pattern.Identifier() != name {
				continue
			}

			index, ok := s.p1PatternWitness(pattern)
			if !ok {
				continue
			}

			_, err := collector.add(s, rule, name, pattern.Matches()[index])
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s nativeSource) p1PatternWitness(pattern yrx.Pattern) (int, bool) {
	hits := pattern.Matches()
	if pattern.Identifier() != pythonSocketStreamPattern && pattern.Identifier() != pythonShellAliasPattern {
		return 0, len(hits) > 0
	}

	for i, hit := range hits {
		if i >= 4096 {
			break
		}

		span, err := s.span(hit)
		if err == nil && s.acceptsInstance(multilineShellRule, pattern.Identifier(), span) {
			return i, true
		}
	}

	return 0, false
}

func ciscoRequiredPatterns(rule string, patterns []yrx.Pattern) []string {
	var groups [][]string

	switch rule {
	case "Scout_Cisco_CredentialRead_NetworkWrite":
		groups = [][]string{{"$read_py", "$read_js", "$read_go", "$read_sh"}, {"$write"}, {"$destination"}}
	case "Scout_Cisco_RemoteMiner_AcquireExec":
		groups = [][]string{{"$acquire"}, {"$execute"}, {"$remote"}}
	case "Scout_Cisco_Cron_C2_Persistence":
		groups = [][]string{{"$endpoint"}, {"$schedule"}, {"$execute"}}
	case "Scout_Cisco_EncodedArchive_StageExec":
		groups = [][]string{{"$py_decode"}, {"$py_archive"}, {"$py_extract"}, {"$py_exec"}}
		if !nativePatternPresent(patterns, "$py_decode") {
			groups = [][]string{{"$sh_decode"}, {"$sh_archive"}, {"$sh_exec"}}
		}
	default:
		return nil
	}

	var out []string

	for _, choices := range groups {
		for _, name := range choices {
			if nativePatternPresent(patterns, name) {
				out = append(out, name)
				break
			}
		}
	}

	return out
}

func nativePatternPresent(patterns []yrx.Pattern, name string) bool {
	for _, p := range patterns {
		if p.Identifier() == name && len(p.Matches()) > 0 {
			return true
		}
	}

	return false
}
