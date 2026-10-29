// Package sqlsyntax tokenizes bounded SQL statements without connecting to a
// database. It preserves quoted data and identifiers as distinct token kinds.
package sqlsyntax

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	MaxBytes  = 256 << 10
	MaxTokens = 32768
	MaxDepth  = 64
)

type Token struct {
	Kind, Text string
	Start, End int
}

type Statement struct {
	Tokens     []Token
	Start, End int
}

type Tree struct {
	Statements []Statement
	Limited    bool
}

type lexer struct {
	ctx              context.Context
	text             string
	at, count, depth int
	limited          bool
}

func Parse(ctx context.Context, text string) (Tree, error) {
	if ctx == nil {
		return Tree{}, errors.New("nil SQL context")
	}

	if err := ctx.Err(); err != nil {
		return Tree{}, err
	}

	if len(text) > MaxBytes || !utf8.ValidString(text) {
		return Tree{}, errors.New("SQL input limit or encoding")
	}

	l := lexer{ctx: ctx, text: text}

	return l.parse()
}

// QueryPrefix recognizes SQL-shaped text for host-language query construction
// checks. It is an applicability hint, never SQL validity or database execution.
func QueryPrefix(text string) bool {
	text = strings.TrimSpace(text)
	if len(text) > 128 {
		text = text[:128]
	}

	fields := strings.Fields(strings.ToUpper(text))
	if len(fields) == 0 {
		return false
	}

	switch fields[0] {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "DROP", "ALTER", "CREATE", "TRUNCATE", "EXEC", "EXECUTE":
		return true
	}

	return false
}

func (l *lexer) parse() (Tree, error) {
	var (
		out     Tree
		current []Token
	)

	finish := func() {
		if len(current) > 0 {
			command := current[0].Text
			if command == "EXECUTE" || command == "EXEC" || command == "DO" || command == "CALL" {
				out.Limited = true
			}

			out.Statements = append(out.Statements, Statement{
				Tokens: current,
				Start:  current[0].Start,
				End:    current[len(current)-1].End,
			})
			current = nil
		}
	}

	for l.at < len(l.text) {
		if err := l.ctx.Err(); err != nil {
			finish()
			return out, err
		}

		t, err := l.next()
		if err != nil {
			finish()
			return out, err
		}

		if t.Kind == "" {
			continue
		}

		l.count++
		if l.count > MaxTokens {
			finish()
			return out, errors.New("SQL token limit")
		}

		if t.Text == ";" && t.Kind == "punctuation" && l.depth == 0 {
			finish()
			continue
		}

		current = append(current, t)
		if t.Kind == "body" {
			out.Limited = true
		}
	}

	finish()

	out.Limited = out.Limited || l.limited

	if l.depth != 0 {
		return out, errors.New("unclosed SQL parentheses")
	}

	return out, nil
}

func (l *lexer) next() (Token, error) {
	s := l.text
	start := l.at
	c := s[l.at]

	if strings.ContainsRune(" \t\r\n\f", rune(c)) {
		l.at++
		return Token{}, nil
	}

	if strings.HasPrefix(s[l.at:], "--") {
		for l.at < len(s) && s[l.at] != '\n' {
			l.at++
		}

		return Token{}, nil
	}

	if strings.HasPrefix(s[l.at:], "/*") {
		return Token{}, l.comment()
	}

	if c == '\'' || c == '"' || c == '`' || c == '[' {
		return l.quoted(c)
	}

	if c == '$' {
		if end := dollarDelimiter(s, l.at); end > l.at {
			delim := s[l.at:end]

			closing := strings.Index(s[end:], delim)
			if closing < 0 {
				l.at = len(s)
				return Token{}, errors.New("unclosed SQL dollar string")
			}

			l.at = end + closing + len(delim)

			return Token{Kind: "body", Text: s[end : end+closing], Start: start, End: l.at}, nil
		}
	}

	if wordByte(c) {
		for l.at < len(s) && wordByte(s[l.at]) {
			l.at++
		}

		return Token{Kind: "word", Text: strings.ToUpper(s[start:l.at]), Start: start, End: l.at}, nil
	}

	l.at++
	if c == '(' {
		l.depth++
		if l.depth > MaxDepth {
			return Token{}, errors.New("SQL nesting limit")
		}
	}

	if c == ')' {
		l.depth--
		if l.depth < 0 {
			return Token{}, errors.New("unbalanced SQL parentheses")
		}
	}

	return Token{Kind: "punctuation", Text: string(c), Start: start, End: l.at}, nil
}

func (l *lexer) comment() error {
	depth := 1
	l.at += 2

	for l.at < len(l.text) {
		if strings.HasPrefix(l.text[l.at:], "/*") {
			depth++
			l.at += 2
		} else if strings.HasPrefix(l.text[l.at:], "*/") {
			depth--
			l.at += 2

			if depth == 0 {
				return nil
			}
		} else {
			l.at++
		}

		if depth > MaxDepth {
			return errors.New("SQL comment limit")
		}
	}

	return errors.New("unclosed SQL comment")
}

func (l *lexer) quoted(open byte) (Token, error) {
	start := l.at
	l.at++
	closing := open

	kind := "identifier"
	if open == '\'' {
		kind = "string"
	}

	if open == '[' {
		closing = ']'
	}

	var value strings.Builder

	for l.at < len(l.text) {
		c := l.text[l.at]

		l.at++
		if c == closing {
			if l.at < len(l.text) && l.text[l.at] == closing {
				value.WriteByte(c)

				l.at++

				continue
			}

			return Token{Kind: kind, Text: value.String(), Start: start, End: l.at}, nil
		}

		if c == '\\' && l.at < len(l.text) {
			l.limited = true
			value.WriteByte(l.text[l.at])
			l.at++

			continue
		}

		value.WriteByte(c)
	}

	return Token{}, errors.New("unclosed SQL quoted token")
}

func dollarDelimiter(s string, at int) int {
	for i := at + 1; i < len(s) && i-at <= 64; i++ {
		if s[i] == '$' {
			return i + 1
		}

		if !(s[i] == '_' || s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z' || i > at+1 && s[i] >= '0' && s[i] <= '9') {
			break
		}
	}

	return at
}

func wordByte(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 128
}
