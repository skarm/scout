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
	return !ascii || containsPatternLiteral(folded, patternLiterals(expression))
}
