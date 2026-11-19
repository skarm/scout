package scriptsyntax

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// IdentifierText resolves Unicode escapes only in identifier tokens. It preserves
// literal strings and source coordinates; equal identifiers share code points,
// without Unicode normalization. The parser owns all other syntax validation.
func IdentifierText(kind, text string) (string, error) {
	switch kind {
	case kindPrivatePropertyIdentifier:
		if !strings.HasPrefix(text, "#") {
			return "", errors.New("invalid private script identifier")
		}

		name, err := IdentifierText(KindIdentifier, text[1:])
		if err != nil {
			return "", err
		}

		return "#" + name, nil
	case KindIdentifier, kindTypeIdentifier, kindStatementIdentifier, KindPropertyIdentifier,
		KindShorthandPropertyIdentifier, KindShorthandPropertyIdentifierPattern:
	default:
		return text, nil
	}

	plainASCII := true

	for i := range len(text) {
		if text[i] == '\\' || text[i] >= utf8.RuneSelf {
			plainASCII = false
			break
		}
	}

	if plainASCII {
		return text, nil
	}

	var out strings.Builder

	for rest := text; rest != ""; {
		r, size := utf8.DecodeRuneInString(rest)
		if r == utf8.RuneError && size == 1 {
			return "", errors.New("invalid script identifier encoding")
		}

		if r == '\\' {
			var err error

			r, size, err = identifierEscape(rest)
			if err != nil {
				return "", err
			}
		}

		// Preserve parser admission for scalars that this SDK cannot classify.
		// Its Unicode tables may predate the grammar; this is deliberately not
		// a complete ECMAScript identifier validator.
		unclassified := !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs)

		unicodeIdentifier := !unicode.In(r, unicode.Pattern_Syntax, unicode.Pattern_White_Space)

		start := r == '$' || r == '_' || unicodeIdentifier && (unclassified || unicode.In(r, unicode.L, unicode.Nl, unicode.Other_ID_Start))

		continuation := start || r == '\u200c' || r == '\u200d' || unicodeIdentifier && unicode.In(r, unicode.Mn, unicode.Mc, unicode.Nd, unicode.Pc, unicode.Other_ID_Continue)
		if out.Len() == 0 && !start || out.Len() > 0 && !continuation {
			return "", errors.New("invalid script identifier code point")
		}

		out.WriteRune(r)

		rest = rest[size:]
	}

	return out.String(), nil
}

func identifierEscape(text string) (rune, int, error) {
	if !strings.HasPrefix(text, `\u`) {
		return 0, 0, errors.New("invalid script identifier escape")
	}

	end, after := 6, 6
	if len(text) > 2 && text[2] == '{' {
		i := strings.IndexByte(text[3:], '}')
		if i < 0 {
			return 0, 0, errors.New("invalid script identifier escape")
		}

		end, after = 3+i, 4+i
	} else if len(text) < end {
		return 0, 0, errors.New("invalid script identifier escape")
	}

	start := 2
	if text[2] == '{' {
		start = 3
	}

	digits := text[start:end]
	if digits == "" {
		return 0, 0, errors.New("invalid script identifier escape")
	}
	// Leading zeroes do not change the value, including in braced escapes.
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		digits = "0"
	}

	value, err := strconv.ParseUint(digits, 16, 32)
	if err != nil || value > utf8.MaxRune || value >= 0xd800 && value <= 0xdfff {
		return 0, 0, errors.New("invalid script identifier code point")
	}

	return rune(value), after, nil
}
