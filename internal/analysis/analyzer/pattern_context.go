// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Adapted Unicode/SC7 guards from SkillSpector; original byte coordinates,
// explicit candidate caps and no general example-based suppression.

package analyzer

import (
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/scout/internal/analysis/promptguard"
)

var credentialNounPrefix = regexp.MustCompile(`(?i)\b(?:validate|verify|refresh|rotate|expire|parse|manage|revoke)\s+$`)

// Adapted from SkillSpector prohibition_context: only an unambiguous bounded
// direct prohibition. Conditional exceptions and a second instruction retain
// detection. Paths, quotation labels and examples never grant an exemption.
var (
	standardSkillMkdir      = regexp.MustCompile(`^mkdir[\t ]+(?:(?:-p|--parents)[\t ]+)?(?:--[\t ]+)?['"]?~/\.(?:claude|codex|gemini)/skills(?:/[A-Za-z0-9][A-Za-z0-9_.-]*)?/?['"]?[\t ]*$`)
	hiddenDirectoryTargets  = regexp.MustCompile(`(?:~/|/home/|/tmp/)\.([a-z_-]+)`)
	directProhibition       = regexp.MustCompile(`(?i)^(?:please[\t ]+)?(?:(?:you|the[\t ]+(?:agent|assistant|model))[\t ]+)?(?:do[\t ]+not|don't|don’t|never|must[\t ]+not|shall[\t ]+not)[\t ]+(?:(?:ever)[\t ]+)?$`)
	prohibitionException    = regexp.MustCompile(`(?i)\b(?:unless|except|until|but|however|instead|if|when|only|otherwise|else)\b`)
	prohibitionUndo         = regexp.MustCompile(`(?i)^[\s.!?;]*(?:(?:instead[, ]+|actually[\t ]+yes[, ]+)(?:do|execute|perform|run)\s+(?:it|that|them)\b|(?:do|execute|perform|run)\s+(?:it|that|them)\s+(?:anyway|instead|remotely)\b)`)
	prohibitionFollowup     = regexp.MustCompile(`(?i)^[\s.!?;]*(?:but|however|instead|unless|except|until|only)\b`)
	prohibitionContinuation = regexp.MustCompile(`(?i)^(?:unless|except|until|if|when|only|in|to|for|as)\b`)
	prohibitionReversal     = regexp.MustCompile(`(?i)\b(?:opposit\w*|invers\w*|invert\w*|revers\w*|contrar\w*|negat\w*|ignore|disregard|override|bypass|suspend|violat\w*)\b`)
	prohibitionSubject      = regexp.MustCompile(`(?i)\b(?:meaning|prohibition|instructions?|rules?|assistant|agent|negation)\b`)
	negatedReversal         = regexp.MustCompile(`(?i)(?:do[\t ]+not|don't|don’t|never|must[\t ]+not)[\t ]+$`)
)

var protectedDirectoryName = regexp.MustCompile(`(?i)^(?:git|ssh|aws)`)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var emojiBases = &unicode.RangeTable{
	R16: []unicode.Range16{{Lo: 0x00a9, Hi: 0x00ae, Stride: 5}, {Lo: 0x203c, Hi: 0x2049, Stride: 13}, {
		Lo:     0x2122,
		Hi:     0x2139,
		Stride: 23,
	}, {
		Lo:     0x2600,
		Hi:     0x27bf,
		Stride: 1,
	}, {
		Lo:     0x3030,
		Hi:     0x303d,
		Stride: 13,
	}},
	R32: []unicode.Range32{{Lo: 0x1f000, Hi: 0x1faff, Stride: 1}},
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var safeSubdivisionFlags = stringSet("gbeng gbsct gbwls")

// An unmatched quotation from earlier in the paragraph makes a prohibition
// referential/ambiguous. Apostrophes inside words are not quotation delimiters.
//
//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	instructionQuoteClosers = map[rune]rune{
		'\'': '\'',
		'"':  '"',
		'‘':  '’',
		'’':  '’',
		'“':  '”',
		'”':  '”',
	}
	wordApostrophes = map[rune]bool{'\'': true, '’': true}
)

// A prohibition is interpreted within a bounded paragraph and one physical
// sentence. Parsing these extents once keeps quotation and reversal decisions
// on the same source bytes.
type prohibitionText struct {
	text                    string
	start, end, left, right int
	context                 string
}

func familyVersion(id string) string {
	switch id {
	case ruleSC2:
		return "7"
	case ruleP2, ruleP6, ruleP8, rulePE2, rulePE3, rulePE4, ruleEA1, ruleEA3, ruleEA5, ruleE5, ruleOH1, ruleTM1, ruleTM3, ruleTM4, ruleRA1, ruleRA2, ruleAS3:
		return "6"
	case ruleE1, ruleEA2:
		return "5"
	case ruleMP2, ruleMP3, ruleP7, ruleP9:
		return "4"
	case ruleP3, ruleP4, ruleP5, ruleE2, ruleSC1, ruleSC3, ruleSC7:
		return "3"
	}

	return "2"
}

func patternGuard(id string) func(string, int, int) bool {
	guards := map[string]func(string, int, int) bool{
		ruleEA2: directlyProhibited, ruleMP3: directlyProhibited, ruleAS3: directlyProhibited,
		ruleRA2: func(text string, start, end int) bool {
			return directlyProhibited(text, start, end) || protectedDirectoryExample(text, start, end)
		},
		rulePE3: func(text string, start, end int) bool {
			return directlyProhibited(text, start, end) || credentialNounExempt(text, start, end)
		},
		ruleP6: promptPatternExempt, ruleP7: promptPatternExempt, ruleP8: promptPatternExempt,
		ruleSC7: disabledTrustExempt, ruleP2: emojiCarrierExempt,
	}

	return guards[id]
}

func promptPatternExempt(text string, start, end int) bool {
	return directlyProhibited(text, start, end) || promptguard.Prohibited(text, start, end)
}

func credentialNounExempt(text string, start, end int) bool {
	return strings.HasPrefix(strings.ToLower(text[start:end]), "access ") && credentialNounPrefix.MatchString(text[max(0, start-64):start])
}

func disabledTrustExempt(text string, start, end int) bool {
	if strings.ToLower(text[start:end]) != "--disable-content-trust" {
		return false
	}

	rest := strings.ToLower(text[end:])

	return strings.HasPrefix(rest, "=false") && (len(rest) == 6 || strings.ContainsRune(" \t\r\n;|&)", rune(rest[6])))
}

func emojiCarrierExempt(text string, start, end int) bool {
	r, _ := utf8.DecodeRuneInString(text[start:end])
	return r == 0x200d && end-start == 3 && emojiBefore(text, start) && emojiAfter(text, end)
}

func protectedDirectoryExample(text string, start, end int) bool {
	matched := text[start:end]
	if strings.HasPrefix(matched, "mkdir") || strings.HasPrefix(matched, "create") || strings.HasPrefix(matched, "write") {
		paths := hiddenDirectoryTargets.FindAllStringSubmatch(matched, 32)
		if len(paths) > 0 && !slices.ContainsFunc(paths, func(path []string) bool { return !protectedDirectoryName.MatchString(path[1]) }) {
			return true
		}
	}

	left := strings.LastIndex(text[:start], "\n") + 1

	right := len(text)
	if i := strings.IndexByte(text[end:], '\n'); i >= 0 {
		right = end + i
	}

	line := strings.TrimSpace(text[left:right])
	if standardSkillMkdir.MatchString(line) && strings.Count(line, "'")%2 == 0 && strings.Count(line, `"`)%2 == 0 {
		return true
	}

	return false
}

func readProhibition(text string, start, end int) (prohibitionText, bool) {
	if start < 0 || end < start || end > len(text) {
		return prohibitionText{}, false
	}

	contextStart, contextEnd := max(0, start-512), min(len(text), end+512)
	if boundaries := paragraphBoundaries(text[contextStart:start]); len(boundaries) > 0 {
		contextStart += boundaries[len(boundaries)-1][1]
	}

	if boundaries := paragraphBoundaries(text[end:contextEnd]); len(boundaries) > 0 {
		contextEnd = end + boundaries[0][0]
	}

	left, right := max(0, start-512), min(len(text), end+512)
	if at := strings.LastIndexAny(text[left:start], "\r\n.!?;"); at >= 0 {
		left += at + 1
	}

	if at := strings.IndexAny(text[end:right], "\r\n.!?;"); at >= 0 {
		right = end + at
	}

	return prohibitionText{
		text:    text,
		start:   start,
		end:     end,
		left:    left,
		right:   right,
		context: text[contextStart:contextEnd],
	}, !openInstructionQuote(text[contextStart:start])
}

func (p prohibitionText) reversed() bool {
	if !prohibitionSubject.MatchString(p.context) {
		return false
	}

	for _, at := range prohibitionReversal.FindAllStringIndex(p.context, -1) {
		if !negatedReversal.MatchString(p.context[max(0, at[0]-64):at[0]]) {
			return true
		}
	}

	return false
}

func (p prohibitionText) direct() bool {
	prefix := strings.TrimLeft(p.text[p.left:p.start], " \t-+*")

	prefix = strings.NewReplacer("`", "", "*", "", "_", "").Replace(prefix)
	if !directProhibition.MatchString(prefix) {
		return false
	}

	if p.right < len(p.text) {
		following := p.text[p.right:min(len(p.text), p.right+160)]
		if prohibitionUndo.MatchString(following) || prohibitionFollowup.MatchString(following) {
			return false
		}
	}

	tail := strings.TrimSpace(p.text[p.end:p.right])
	if !prohibitionContinuesSafely(p.text, p.right) {
		return false
	}

	action := p.text[p.start:p.end]
	if prohibitionException.MatchString(tail) || prohibitionException.MatchString(action) || strings.Contains(strings.ToLower(action), " then ") {
		return false
	}

	return strings.Trim(tail, " \t`*_\"'") == ""
}

func directlyProhibited(text string, start, end int) bool {
	prohibition, valid := readProhibition(text, start, end)
	return valid && !prohibition.reversed() && prohibition.direct()
}

func prohibitionContinuesSafely(text string, right int) bool {
	if right < len(text) {
		next := text[right:min(len(text), right+128)]
		// A sentence terminator before the line break does not make an
		// immediately following list qualifier a separate safe prohibition.
		if at := strings.IndexByte(next, '\n'); at >= 0 && strings.Trim(next[:at], " \t\r.!?;") == "" && !strings.HasPrefix(next[at+1:], "\n") {
			next = next[at+1:]
		}

		continuation := strings.TrimLeft(next, " \t\r\n-*+>0123456789.)")
		if prohibitionContinuation.MatchString(continuation) {
			return false
		}

		if strings.HasPrefix(continuation, "#") {
			if _, after, ok := strings.Cut(continuation, "\n"); ok {
				following := strings.TrimLeft(after, " \t\r\n-*+>0123456789.)")
				if prohibitionContinuation.MatchString(following) {
					return false
				}
			}
		}
	}

	return true
}

func emojiBase(r rune) bool { return unicode.Is(emojiBases, r) }

func emojiModifier(r rune) bool { return r >= 0x1f3fb && r <= 0x1f3ff }
func variation(r rune) bool     { return r == 0xfe0e || r == 0xfe0f }
func emojiBefore(s string, at int) bool {
	for count := 0; at > 0 && count < 8; count++ {
		r, n := utf8.DecodeLastRuneInString(s[:at])
		at -= n

		if variation(r) || emojiModifier(r) {
			continue
		}

		return emojiBase(r)
	}

	return false
}

func emojiAfter(s string, at int) bool {
	for count := 0; at < len(s) && count < 8; count++ {
		r, n := utf8.DecodeRuneInString(s[at:])
		at += n

		if variation(r) || emojiModifier(r) {
			continue
		}

		return emojiBase(r)
	}

	return false
}

// safeFlagEnd recognizes only the three known subdivision sequences, a stricter
// exception than upstream's generic 2..6 lower-case/digit tag allowance. A black
// flag around an arbitrary short instruction is not an exemption.
func safeFlagEnd(s string, at int) int {
	r, n := utf8.DecodeRuneInString(s[at:])
	if r != 0x1f3f4 {
		return at
	}

	pos := at + n

	var code [6]byte

	count := 0
	for pos < len(s) && count < len(code) {
		r, n = utf8.DecodeRuneInString(s[pos:])
		if r == 0xe007f {
			if safeSubdivisionFlags[string(code[:count])] {
				return pos + n
			}

			return at
		}

		if r < 0xe0020 || r > 0xe007e {
			return at
		}

		code[count] = byte(r - 0xe0000)
		count++
		pos += n
	}

	return at
}

func openInstructionQuote(text string) bool {
	quote := rune(0)
	// Sentinels let tokenization inspect neighboring letters uniformly at both
	// boundaries, including curly apostrophes inside a word.
	runes := append([]rune{0}, []rune(text)...)

	runes = append(runes, 0)
	for i := 1; i+1 < len(runes); i++ {
		r := runes[i]
		if instructionQuoteClosers[r] == 0 {
			continue
		}

		if wordApostrophes[r] && unicode.IsLetter(runes[i-1]) && unicode.IsLetter(runes[i+1]) {
			continue
		}

		if quote == 0 {
			quote = r
			continue
		}

		if r == quote || r == instructionQuoteClosers[quote] {
			quote = 0
		}
	}

	return quote != 0
}
