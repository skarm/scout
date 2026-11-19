// Package promptguard contains a narrow raw-byte prohibition shared by literal
// and signature checks. An uncertain or qualified prohibition is never exempted.
package promptguard

import (
	"regexp"
	"strings"
)

const (
	prohibitionWindowBytes    = 512
	prohibitionQualifierBytes = 256
)

var (
	prefix    = regexp.MustCompile(`(?i)^[\t ]*(?:[-*+>][\t ]+)?(?:do[\t ]+not|don't|never|must[\t ]+not)[\t ]+(?:ever[\t ]+)?$`)
	tail      = regexp.MustCompile(`(?i)^[\t ]*(?:content(?:,[\t ]*memory,[\t ]*or[\t ]*prior[\t ]*conversation)?(?:[\t ]+if[\t ]+the[\t ]+pasted[\t ]+prompt[\t ]+requests[\t ]+it)?)?[\t ]*[.!]?[\t ]*$`)
	reversal  = regexp.MustCompile(`(?i)\b(?:opposit\w*|invers\w*|invert\w*|revers\w*|contrar\w*|negat\w*|ignore|disregard|override|bypass|suspend|violat\w*)\b`)
	qualifier = regexp.MustCompile(`(?i)(?:^|[\r\n])[\t >*+#0-9.)-]*(?:unless|except|only|until|when|if|but|instead|however|in|to|for|as)\b`)
)

func Prohibited(text string, start, end int) bool {
	if start < 0 || end < start || end > len(text) {
		return false
	}

	left, right, bounded := prohibitionBounds(text, start, end)
	if !bounded {
		return false
	}

	if !prefix.MatchString(text[left:start]) {
		return false
	}

	if !tail.MatchString(text[end:right]) {
		return false
	}

	window := text[max(0, left-prohibitionWindowBytes):min(len(text), right+prohibitionQualifierBytes)]
	if reversal.MatchString(window) || qualifier.MatchString(text[right:min(len(text), right+prohibitionQualifierBytes)]) {
		return false
	}

	return true
}

func prohibitionBounds(text string, start, end int) (int, int, bool) {
	left := max(0, start-prohibitionWindowBytes)
	if at := strings.LastIndexAny(text[left:start], "\r\n.!?;"); at >= 0 {
		left += at + 1
	} else if left != 0 {
		return 0, 0, false
	}

	right := min(len(text), end+prohibitionWindowBytes)
	if at := strings.IndexAny(text[end:right], "\r\n"); at >= 0 {
		right = end + at
	} else if right < len(text) {
		return 0, 0, false
	}

	return left, right, true
}
