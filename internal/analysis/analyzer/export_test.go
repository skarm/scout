package analyzer

import "slices"

// PatternFamilyForTest exposes immutable catalog inputs to the independent test oracle.
type PatternFamilyForTest struct {
	ID          string
	Expressions []string
	Example     string
}

func PatternFamiliesForTest() []PatternFamilyForTest {
	out := make([]PatternFamilyForTest, 0, len(families))
	for _, family := range families {
		out = append(out, PatternFamilyForTest{
			ID:          family.id,
			Expressions: slices.Clone(family.expressions),
			Example:     family.example,
		})
	}
	return out
}

func PatternPrefilterAllowsForTest(expression, text string) bool {
	folded, ascii := asciiPatternText(text)
	return !ascii || patternLiterals(expression).allows(folded)
}

// LiteralRulesForTest retains the prefilter-free matcher as an independent
// observation oracle for budgets, guards and transformed source coordinates.
func LiteralRulesForTest(filtered bool) []Analyzer {
	var out []Analyzer
	for _, a := range NewCatalog(Selection{}).Analyzers() {
		if value, ok := a.(literal); ok {
			if !filtered {
				value.hint = nil
			}
			out = append(out, value)
		}
	}
	return out
}
