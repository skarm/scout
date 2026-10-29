package textmatch

// FencePrefix returns the initial run of at least three backticks or tildes.
func FencePrefix(s string) (marker byte, width int) {
	if len(s) < 3 || s[0] != '`' && s[0] != '~' {
		return 0, 0
	}

	for width < len(s) && s[width] == s[0] {
		width++
	}

	if width < 3 {
		return 0, 0
	}

	return s[0], width
}
