package analyzer

import (
	"regexp/syntax"
	"strings"
)

// A prefilter is a necessary condition, never evidence. Every accepted input
// still goes through the original RE2 expression, guards and source mapping.
// Nil means that no useful mandatory literal could be proven.
type patternLiteralFilter [][]string

func patternLiterals(expression string) patternLiteralFilter {
	tree, err := syntax.Parse(expression, syntax.Perl)
	if err != nil {
		return nil
	}

	return requiredLiteralGroups(tree)
}

// A pointer keeps literal analyzer values comparable when immutable hints are
// attached. Binding stages can still compare unchanged analyzer instances.
func literalFilter(expression string) *patternLiteralFilter {
	filter := patternLiterals(expression)
	if len(filter) == 0 {
		return nil
	}

	return &filter
}

// A concatenation must satisfy each mandatory group. Within a group any
// alternative suffices. Keep only a bounded subset: omitting a condition can
// admit extra RE2 work, but can never suppress a match.
func requiredLiteralGroups(tree *syntax.Regexp) patternLiteralFilter {
	switch tree.Op {
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiteralGroups(tree.Sub[0])
	case syntax.OpRepeat:
		if tree.Min > 0 {
			return requiredLiteralGroups(tree.Sub[0])
		}
	case syntax.OpConcat:
		var groups patternLiteralFilter
		for _, child := range tree.Sub {
			groups = append(groups, requiredLiteralGroups(child)...)
			if len(groups) >= 16 {
				return groups[:16]
			}
		}

		return groups
	default:
		if literals := requiredLiterals(tree); len(literals) > 0 {
			return patternLiteralFilter{literals}
		}
	}

	return nil
}

func (filter patternLiteralFilter) allows(text string) bool {
	for _, literals := range filter {
		if !containsPatternLiteral(text, literals) {
			return false
		}
	}

	return true
}

func requiredLiterals(tree *syntax.Regexp) []string {
	switch tree.Op {
	case syntax.OpLiteral:
		// Only ASCII input uses the filter. An expression with a non-ASCII
		// literal can still have a mandatory ASCII substring.
		longest, start := "", 0

		for i := 0; i <= len(tree.Rune); i++ {
			if i < len(tree.Rune) && tree.Rune[i] < 128 {
				continue
			}

			if i-start > len(longest) {
				longest = strings.ToLower(string(tree.Rune[start:i]))
			}

			start = i + 1
		}

		if longest != "" {
			return []string{longest}
		}
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(tree.Sub[0])
	case syntax.OpRepeat:
		if tree.Min > 0 {
			return requiredLiterals(tree.Sub[0])
		}
	case syntax.OpConcat:
		var best []string

		for _, child := range tree.Sub {
			literals := requiredLiterals(child)
			if literalScore(literals) > literalScore(best) {
				best = literals
			}
		}

		return best
	case syntax.OpAlternate:
		var choices []string

		for _, child := range tree.Sub {
			literals := requiredLiterals(child)
			if len(literals) == 0 || len(choices)+len(literals) > 64 {
				return nil
			}

			choices = append(choices, literals...)
		}

		return choices
	default:
		// Other regexp operations prove no mandatory literal.
		return nil
	}

	return nil
}

func literalScore(literals []string) int {
	if len(literals) == 0 {
		return 0
	}

	score := len(literals[0])
	for _, literal := range literals[1:] {
		score = min(score, len(literal))
	}

	return score
}

func containsPatternLiteral(text string, literals []string) bool {
	if len(literals) == 0 {
		return true
	}

	for _, literal := range literals {
		if strings.Contains(text, literal) {
			return true
		}
	}

	return false
}

func asciiPatternText(text string) (string, bool) {
	for i := range len(text) {
		if text[i] >= 128 {
			// Unicode simple folding includes Kelvin sign and long s. Bypass
			// the filter entirely for Unicode and invalid UTF-8 inputs.
			return "", false
		}
	}

	return strings.ToLower(text), true
}
