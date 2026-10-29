// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Selected output-handling guards adapted to bounded Go syntax inspection.

package analyzer

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/scout/internal/analysis/document"
)

// Recognize only a complete, ordinary single-line regexp operand. Ambiguous
// division, comments, templates and truncated lookback retain the review signal.
func regexpLiteralExec(d document.File, m Match) bool {
	source := sourceForPattern(d)

	text := source.text
	if source.kind&patternJavaScript == 0 || !strings.HasPrefix(text[m.Start:m.End], "exec") {
		return false
	}

	floor := max(0, m.Start-4096)

	start := strings.LastIndexAny(text[floor:m.Start], "\r\n")
	if start < 0 && floor > 0 {
		return false
	}

	start += floor + 1

	prefix := strings.TrimRightFunc(text[start:m.Start], unicode.IsSpace)
	if !strings.HasSuffix(prefix, ".") {
		return false
	}

	prefix = strings.TrimRightFunc(strings.TrimSuffix(prefix, "."), unicode.IsSpace)
	prefix = strings.TrimRightFunc(strings.TrimSuffix(prefix, "?"), unicode.IsSpace)

	closing := len(strings.TrimRight(prefix, "dgimsuvy"))

	if closing == 0 || prefix[closing-1] != '/' {
		return false
	}

	closing--

	return completeRegexpPrefix(prefix, closing, start)
}

func completeRegexpPrefix(prefix string, closing, start int) bool {
	inClass := false

	for opening := closing - 1; opening >= 0; opening-- {
		b := prefix[opening]
		if !strings.ContainsRune("/[]", rune(b)) {
			continue
		}

		escaped := opening - len(strings.TrimRight(prefix[:opening], "\\"))

		if escaped%2 != 0 {
			continue
		}

		if b != '/' {
			inClass = b == ']'
			continue
		}

		if inClass {
			continue
		}

		if opening+1 == closing {
			return false
		}

		before := strings.TrimSpace(prefix[:opening])

		return regexpAllowedPrefix(before, start)
	}

	return false
}

func regexpAllowedPrefix(before string, start int) bool {
	// Require the whole prefix to be free of other slash/comment/template
	// syntax; this intentionally recognizes less than a JavaScript parser.
	if strings.ContainsAny(before, "/`\\") || strings.Contains(before, "<!--") || strings.Contains(before, "-->") || !completeQuotes(before) {
		return false
	}

	if before == "" {
		return start == 0
	}

	last, _ := utf8.DecodeLastRuneInString(before)
	if strings.ContainsRune("=([{,:;?&|*%^~", last) {
		return true
	}

	keyword := regexpKeywordStart(before)
	if keyword < 0 {
		return false
	}

	if keyword == 0 {
		return true
	}

	previous, _ := utf8.DecodeLastRuneInString(before[:keyword])

	return !identifierContinuation(previous) && previous != '.' && previous != '#'
}
