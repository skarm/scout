package analyzer

import (
	"context"
	"regexp"
	"strings"
)

var (
	referenceOpener          = regexp.MustCompile(`(?m)(?:^|[\r\n])[\t ]{0,3}\[//\]:`)
	referenceKeyword         = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])(?:system|instructions?|ignore|post|get|send|transmit|upload|execute|override)(?:$|[^A-Za-z0-9])`)
	referenceCamelBoundary   = regexp.MustCompile(`([a-z])([A-Z])`)
	referenceAcronymBoundary = regexp.MustCompile(`([A-Z])([A-Z][a-z])`)
	referenceAction          = regexp.MustCompile(`(?i)\b(?:ignoring|transmitting|uploading|sending)\b|ignorepreviousinstructions|transmitconversationto(?:attacker|external)|systemprompt|postrequestto`)
)

// Exactly one optional logical line break is part of this comment grammar.
var referenceSpace = regexp.MustCompile(`^[\t ]*(?:\r\n|[\r\n])?[\t ]*`)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	referenceTitleClosers      = map[byte]byte{'(': ')', '"': '"', '\'': '\''}
	referenceBlankContinuation = regexp.MustCompile(`^[\t ]*(?:[\r\n]|$)`)
)

func referenceHasKeyword(text string) bool {
	words := referenceCamelBoundary.ReplaceAllString(text, "$1 $2")
	words = referenceAcronymBoundary.ReplaceAllString(words, "$1 $2")

	return referenceKeyword.MatchString(words) || referenceAction.MatchString(words)
}

// Inspect only the destination and optional title of this comment convention.
// A bounded continuation may cross one logical line, never a blank paragraph.
func referenceCommentSignals(ctx context.Context, text string, emit func(int, int) bool) bool {
	openers := referenceOpener.FindAllStringIndex(text, 65537)
	if len(openers) > 65536 {
		return true
	}

	for _, at := range openers {
		if ctx.Err() != nil {
			return true
		}

		if inspectReferenceComment(text, at[0], at[1], emit) {
			return true
		}
	}

	return false
}

func inspectReferenceComment(text string, start, cursor int, emit func(int, int) bool) bool {
	start += len(text[start:]) - len(strings.TrimLeft(text[start:], "\r\n"))

	bound := min(len(text), cursor+2048)

	cursor = skipReferenceSpace(text, cursor, bound)
	if cursor >= bound || text[cursor] != '#' {
		return false
	}

	destination := cursor
	cursor = referenceDestinationEnd(text, cursor, bound)
	found := referenceHasKeyword(text[destination:cursor])
	end := cursor

	cursor = skipReferenceSpace(text, cursor, bound)
	if cursor < bound && strings.ContainsRune("(\"'", rune(text[cursor])) {
		title := cursor + 1
		cursor = referenceTitleEnd(text, cursor, bound)
		found = found || referenceHasKeyword(text[title:cursor])
		end = cursor
	}

	if found && !emit(start, end) {
		return true
	}

	return cursor == bound && bound < len(text)
}

func skipReferenceSpace(text string, cursor, bound int) int {
	return cursor + referenceSpace.FindStringIndex(text[cursor:bound])[1]
}

func referenceDestinationEnd(text string, cursor, bound int) int {
	depth := 0

	for cursor < bound {
		c := text[cursor]
		if c == '\\' && cursor+1 < bound {
			cursor += 2
			continue
		}

		if strings.ContainsRune("\r\n \t", rune(c)) {
			break
		}

		if c == '(' {
			depth++
		}

		if c == ')' {
			depth--
			if depth < 0 {
				break
			}
		}

		cursor++
	}

	return cursor
}

func referenceTitleEnd(text string, cursor, bound int) int {
	closing := referenceTitleClosers[text[cursor]]

	cursor++
	lines := 0

	for cursor < bound {
		c := text[cursor]
		if c == '\\' && cursor+1 < bound {
			cursor += 2
			continue
		}

		if c == closing {
			break
		}

		if strings.ContainsRune("\r\n", rune(c)) {
			lines++
			if lines > 1 {
				break
			}

			if strings.HasPrefix(text[cursor:bound], "\r\n") {
				cursor++
			}

			if referenceBlankContinuation.MatchString(text[cursor+1 : bound]) {
				break
			}
		}

		cursor++
	}

	return cursor
}
