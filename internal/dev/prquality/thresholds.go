package main

import (
	"math"
	"strconv"
	"strings"
	"text/scanner"
)

func (i inventory) readEvaluationFlags(key commandKey, args []shellWord) {
	for index := 0; index < len(args); index++ {
		word := args[index]

		name, value, inline := strings.Cut(word.text, "=")
		switch name {
		case "--min-recall", "--max-fpr", "--max-incomplete":
		default:
			continue
		}

		if !inline && index+1 < len(args) {
			index++
			value = args[index].text
		}

		if number, ok := finiteNumber(value); ok {
			i.addBound(gateKey{key.path, key.scope, name, name == "--min-recall"}, bound{location{key.path, word.line}, number, false})
		}
	}
}

func (i inventory) readJQ(key commandKey, args []shellWord) bool {
	gate := false
	options := true

	for index := 0; index < len(args); index++ {
		arg := args[index]
		if options && arg.text == "--" {
			options = false
			continue
		}

		if options && strings.HasPrefix(arg.text, "-") {
			name, _, inline := strings.Cut(arg.text, "=")
			switch name {
			case "--from-file", "--run-tests":
				return false
			case "--exit-status":
				gate = true
			case "--arg", "--argjson", "--slurpfile", "--rawfile":
				index += 2
			case "--indent", "-L":
				if !inline {
					index++
				}
			default:
				short := jqShortOptions(name)
				if strings.ContainsRune(short, 'f') {
					return false
				}

				gate = gate || strings.ContainsRune(short, 'e')
			}

			continue
		}

		if gate && arg.literal {
			i.readJQFilter(key, arg.line, arg.text)
		}

		return gate
	}

	return false
}

func jqShortOptions(arg string) string {
	// An attached library path is not a cluster of jq short flags.
	if strings.HasPrefix(arg, "-L") {
		return ""
	}

	short := strings.TrimPrefix(arg, "-")
	if strings.ContainsFunc(short, func(r rune) bool { return !asciiLetter(r) }) {
		return ""
	}

	return short
}

type jqToken struct {
	text string
	line int
}

func (i inventory) readJQFilter(key commandKey, line int, filter string) {
	tokens := jqTokens(filter)
	for index, token := range tokens {
		if !strings.HasPrefix(token.text, ".") || len(token.text) < 2 {
			continue
		}

		operator, value, ok := literalBound(tokens[index+1:])
		if !ok {
			continue
		}

		loc := location{key.path, line + token.line - 1}
		if operator == ">" || operator == ">=" || operator == "==" {
			i.addBound(gateKey{key.path, key.scope, token.text, true}, bound{loc, value, operator == ">"})
		}

		if operator == "<" || operator == "<=" || operator == "==" {
			i.addBound(gateKey{key.path, key.scope, token.text, false}, bound{loc, value, operator == "<"})
		}
	}
}

func jqTokens(filter string) []jqToken {
	var lexer scanner.Scanner
	lexer.Init(strings.NewReader(filter))
	lexer.Mode = scanner.ScanIdents | scanner.ScanInts | scanner.ScanFloats | scanner.ScanStrings
	lexer.IsIdentRune = func(r rune, index int) bool {
		return asciiLetter(r) || r == '_' || r == '.' || index > 0 && asciiDigit(r)
	}
	lexer.Error = func(*scanner.Scanner, string) {}

	var tokens []jqToken

	for kind := lexer.Scan(); kind != scanner.EOF; kind = lexer.Scan() {
		if kind == '#' {
			for next := lexer.Peek(); next != '\n' && next != scanner.EOF; next = lexer.Peek() {
				lexer.Next()
			}

			continue
		}

		text := lexer.TokenText()
		if kind == scanner.String {
			// Comparisons written inside jq string constants are not gates.
			text = ""
		}

		tokens = append(tokens, jqToken{text, lexer.Line})
	}

	return tokens
}

func literalBound(tokens []jqToken) (string, float64, bool) {
	if len(tokens) < 2 {
		return "", 0, false
	}

	operator := tokens[0].text
	if operator != ">" && operator != "<" && operator != "=" {
		return "", 0, false
	}

	tokens = tokens[1:]
	if tokens[0].text == "=" {
		operator += "="
		tokens = tokens[1:]
	}

	if operator == "=" || len(tokens) == 0 {
		return "", 0, false
	}

	number := tokens[0].text
	end := 1

	if number == "-" && len(tokens) > 1 {
		number += tokens[1].text
		end++
	}

	if end < len(tokens) && !endsJQComparison(tokens[end].text) {
		return "", 0, false
	}

	value, ok := finiteNumber(number)

	return operator, value, ok
}

func endsJQComparison(token string) bool {
	switch token {
	case "and", "or", "then", "else", "elif", "end", "|", ",", ";", ")", "]", "}":
		return true
	default:
		return false
	}
}

func finiteNumber(text string) (float64, bool) {
	value, err := strconv.ParseFloat(text, 64)
	return value, err == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
}
