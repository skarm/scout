package analyzer

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/source"
)

var (
	formatRulesHeading      = regexp.MustCompile(`(?i)^[\t ]{0,3}#{1,6}[\t ]+(?:(?:json|html|markdown|csv|xml|yaml|report)[\t ]+)?output[\t ]+(?:rules|instructions)(?:[\t ]+\((?:both[\t ]+modes|offline[- ]safe|formatting|report)\))?[\t ]*#*[\t ]*$`)
	rawPromptTarget         = regexp.MustCompile(`(?i)\b(?:prompts|prompt|instructions|instruction|rules|rule|guidelines|guideline|directives|directive)\b`)
	privilegedPromptRequest = regexp.MustCompile(`(?i)\b(?:your\s+(?:full\s+)?|(?:system|developer|internal|secret|hidden)\s+)`)
	headingFormat           = regexp.MustCompile(`(?i)\b(?:json|html|markdown|csv|xml|yaml|report)\s+output|\(both\s+modes\)`)
	forwardProcedure        = regexp.MustCompile(`(?i)follow\s+the\s+steps\s+below|do\s+(?:the\s+)?following`)
	headingDirective        = regexp.MustCompile(`(?i)\b(?:commands?|verbatim|execute|recite|reproduce)\b|\b(?:repeat|reveal|disclose|print|show)\b[^\r\n]{0,80}\b(?:them|rules|instructions|prompt)\b|\brules\s+means\b|\b(?:use|follow|repeat)[^\r\n]{0,80}\b(?:instructions|rules|commands)[^\r\n]{0,40}\b(?:without\s+changes|exactly)\b`)
)

func promptPrecision(d document.File, m Match) bool {
	input := sourceForPattern(d)
	if input.kind&patternMarkdown != 0 && formattingRulesHeading(input.text, input.line(m)) {
		return true
	}

	if input.kind&patternCode == 0 || privilegedPromptRequest.MatchString(input.text[m.Start:m.End]) {
		return false
	}

	return promptIdentifierSuffix(input.text, m)
}

func formattingRulesHeading(text string, line source.Span) bool {
	content := text[line.Start:line.End]
	if strings.HasPrefix(content, "\t") || !formatRulesHeading.MatchString(content) || !headingFormat.MatchString(content) || len(text) > 16384 {
		return false
	}

	context := strings.NewReplacer("*", "", "_", "", "`", "", "\u200b", "", "<br>", " ").Replace(text)

	return !headingDirective.MatchString(context) && !forwardProcedure.MatchString(text[:line.Start]) && !strings.ContainsAny(context, "<>")
}

func promptIdentifierSuffix(text string, m Match) bool {
	// Some Unicode identifier suffixes normalize to a space plus a letter.
	// Inspect the physical token as well as the mapped match boundary.
	for _, at := range rawPromptTarget.FindAllStringIndex(text[m.Start:m.End], -1) {
		if end := m.Start + at[1]; end < len(text) {
			r, _ := utf8.DecodeRuneInString(text[end:])
			if identifierContinuation(r) {
				return true
			}
		}
	}

	if m.End < len(text) {
		r, _ := utf8.DecodeRuneInString(text[m.End:])
		if identifierContinuation(r) {
			return true
		}
	}

	r, _ := utf8.DecodeLastRuneInString(text[m.Start:m.End])

	return unicode.IsMark(r) || unicode.Is(unicode.Cf, r)
}

func identifierContinuation(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) || unicode.Is(unicode.Pc, r) || unicode.Is(unicode.Cf, r) || r == '$'
}
