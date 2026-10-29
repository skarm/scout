package analyzer

import "unicode/utf8"

// CRLF is one logical boundary; regex backtracking must not turn it into two.
func logicalBreak(text string, at int) int {
	if at >= len(text) {
		return at
	}

	r, n := utf8.DecodeRuneInString(text[at:])
	switch r {
	case '\r':
		if at+1 < len(text) && text[at+1] == '\n' {
			return at + 2
		}

		return at + 1
	case '\n', '\v', '\f', 0x85, 0x2028, 0x2029:
		return at + n
	}

	return at
}

func paragraphBoundaries(text string) [][2]int {
	var out [][2]int

	for i := 0; i < len(text); {
		next := logicalBreak(text, i)
		if next == i {
			_, n := utf8.DecodeRuneInString(text[i:])
			i += n

			continue
		}

		j := next
		for j < len(text) && (text[j] == ' ' || text[j] == '\t') {
			j++
		}

		end := logicalBreak(text, j)
		if end > j {
			out = append(out, [2]int{i, end})
			i = end
		} else {
			i = next
		}
	}

	return out
}
