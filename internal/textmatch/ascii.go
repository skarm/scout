// Package textmatch implements small, fixed text grammars without regular expressions.
package textmatch

import "strings"

// Alnum reports whether b is an ASCII letter or digit.
func Alnum(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

// Token accepts 1..maximum ASCII letters, digits, or bytes from punctuation.
func Token(s string, maximum int, punctuation string) bool {
	if len(s) == 0 || len(s) > maximum {
		return false
	}

	for i := range len(s) {
		b := s[i]
		if b >= 128 || !Alnum(b) && strings.IndexByte(punctuation, b) < 0 {
			return false
		}
	}

	return true
}

// Identifier accepts an ASCII identifier beginning with a letter or underscore.
func Identifier(s string, maximum int) bool {
	return Token(s, maximum, "_") && (s[0] == '_' || s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z')
}

// Slug accepts lowercase ASCII letters, digits and interior hyphens.
func Slug(s string, maximum int) bool {
	if len(s) == 0 || len(s) > maximum || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}

	for i := range len(s) {
		b := s[i]
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}

	return true
}

// LowerHex accepts exactly size lowercase hexadecimal bytes.
func LowerHex(s string, size int) bool {
	if len(s) != size {
		return false
	}

	for i := range len(s) {
		if b := s[i]; !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}

	return true
}

// Version accepts three decimal components and optional -prerelease/+build
// suffixes made of ASCII letters, digits, dots and hyphens. This preserves the
// scanner's lexical grammar; it deliberately does not enforce full SemVer.
func Version(s string) bool {
	for part := range 3 {
		end := 0
		for end < len(s) && s[end] >= '0' && s[end] <= '9' {
			end++
		}

		if end == 0 {
			return false
		}

		s = s[end:]
		if part < 2 {
			if len(s) == 0 || s[0] != '.' {
				return false
			}

			s = s[1:]
		}
	}

	if strings.HasPrefix(s, "-") {
		pre, rest, found := strings.Cut(s[1:], "+")
		if !Token(pre, len(pre), ".-") {
			return false
		}

		return !found || Token(rest, len(rest), ".-")
	}

	return s == "" || strings.HasPrefix(s, "+") && Token(s[1:], len(s)-1, ".-")
}
