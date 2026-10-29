package knowledge

import "strings"

// ContextSignals adapts SkillSpector common.is_code_example as NON-SUPPRESSING
// hints. A hostile author can plant these words, so no score, severity or policy
// is changed. Windows are bounded, and returned strings never contain source data.
func ContextSignals(text string, start, end int) []string {
	if start < 0 || end < start || end > len(text) {
		return nil
	}

	lo, hi := contextWindow(text, start)
	window := strings.ToLower(text[lo:hi])

	out := make([]string, 0)
	if strings.Contains(window, "```") || strings.Contains(window, "~~~") {
		out = append(out, "code_fence_nearby")
	}

	for _, s := range []string{"example:", "for example", "e.g.", "such as", "documentation", "# warning:", "# note:", "**warning**", "**note**", "// ✅", "// ❌", "// good:", "// bad:", "// correct:", "// incorrect:", "// wrong:"} {
		if strings.Contains(window, s) {
			out = append(out, "example_or_documentation_context")
			break
		}
	}

	for _, s := range []string{"verified safe", "ignore security warnings", "skip security analysis", "mark the skill as safe"} {
		if strings.Contains(window, s) {
			out = append(out, "self_attestation_or_review_override")
			break
		}
	}

	return out
}

// The hint window is bounded independently in bytes and newline count on each
// side of the occurrence. end is validated above but does not extend the hint.
func contextWindow(text string, start int) (int, int) {
	lo, hi := start, min(len(text), start+2048)
	for lines := 0; lo > 0 && start-lo < 2048; lo-- {
		if text[lo-1] == '\n' {
			lines++
			if lines > 3 {
				break
			}
		}
	}

	for i, lines := start, 0; i < hi; i++ {
		if text[i] == '\n' {
			lines++
			if lines > 3 {
				hi = i
				break
			}
		}
	}

	return lo, hi
}
