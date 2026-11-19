package shellsyntax

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func literalReplacement(n *syntax.ParamExp, raw string) *LiteralReplacement {
	r := n.Repl
	if r == nil || !r.All || !shellIdentifier(n.Param.Value) || !strings.HasPrefix(raw, "${"+n.Param.Value+"//") {
		return nil
	}

	pattern, ok := replacementOperand(r.Orig, true)
	if !ok || pattern == "" {
		return nil
	}

	value, ok := replacementOperand(r.With, false)
	if !ok {
		return nil
	}

	return &LiteralReplacement{Pattern: pattern, Value: value}
}

func replacementOperand(word *syntax.Word, pattern bool) (string, bool) {
	if word == nil {
		return "", true
	}

	if len(word.Parts) != 1 {
		return "", false
	}

	switch part := word.Parts[0].(type) {
	case *syntax.Lit:
		return replacementLiteral(part.Value, pattern)
	case *syntax.SglQuoted:
		if pattern && part.Dollar && len(part.Value) == 2 && part.Value[0] == '\\' {
			switch part.Value[1] {
			case 'n':
				return "\n", true
			case 'r':
				return "\r", true
			case 't':
				return "\t", true
			}
		}
	}

	return "", false
}

func replacementLiteral(raw string, pattern bool) (string, bool) {
	var value strings.Builder

	for i := 0; i < len(raw); i++ {
		b := raw[i]
		switch {
		case b == '\\':
			// Bash versions differ on other backslash escapes here.
			i++
			if i == len(raw) || raw[i] != '\\' && raw[i] != '"' && raw[i] != '/' {
				return "", false
			}

			b = raw[i]
		case b < ' ' || b > '~' || strings.ContainsRune("$&~\x60\"'", rune(b)):
			return "", false
		case pattern && strings.ContainsRune("*?[]()|@!+/#%", rune(b)):
			return "", false
		}

		value.WriteByte(b)
	}

	return value.String(), true
}
