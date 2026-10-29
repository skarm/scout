package shellsyntax

import (
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/source"
)

type wordMode byte

const (
	ordinaryWord     wordMode = 0
	doubleQuotedWord wordMode = '"'
)

func (p *parser) lex() (token, error) {
	if err := p.tick(); err != nil {
		return token{}, err
	}

	p.skipTrivia()

	start := p.at
	if start == p.end {
		return token{kind: "eof", span: source.Span{Start: start, End: start}}, nil
	}

	if p.text[p.at] == '\n' {
		p.at++
		return token{kind: "newline", span: source.Span{Start: start, End: p.at}}, nil
	}

	for _, op := range []string{";;&", ";&", ";;", "((", "<(", ">("} {
		if strings.HasPrefix(p.text[p.at:p.end], op) {
			return token{}, p.fail("unsupported_operator")
		}
	}

	for _, op := range []string{"&>>", "<<-", "<<<", "&&", "||", "|&", ">>", "<<", "<&", ">&", "<>", ">|", "&>", ";", "&", "|", "(", ")", "<", ">"} {
		if strings.HasPrefix(p.text[p.at:p.end], op) {
			p.at += len(op)
			return token{kind: op, span: source.Span{Start: start, End: p.at}}, nil
		}
	}

	return p.lexWord(start)
}

func (p *parser) lexWord(start int) (token, error) {
	w := &Word{Span: source.Span{Start: start}}
	if err := p.parts(w, 0); err != nil {
		return token{}, err
	}

	w.Span.End = p.at
	if p.at == start {
		return token{}, p.fail("unexpected_token")
	}

	return token{kind: "word", word: w, span: w.Span}, nil
}

func (p *parser) parts(w *Word, mode wordMode) error {
	for p.at < p.end {
		if err := p.budget.ctx.Err(); err != nil {
			return err
		}

		if mode.boundary(p.text[p.at]) {
			if mode == doubleQuotedWord {
				p.at++
			}

			return nil
		}

		if err := p.part(w, mode); err != nil {
			return err
		}
	}

	if mode == doubleQuotedWord {
		return p.fail("unclosed_double_quote")
	}

	return nil
}

func (p *parser) part(w *Word, mode wordMode) error {
	start := p.at
	switch p.text[p.at] {
	case '\'':
		if mode == ordinaryWord {
			return p.singleQuotedPart(w, start)
		}
	case '"':
		if mode == ordinaryWord {
			return p.doubleQuotedPart(w, start)
		}
	case '\\':
		return p.escapedPart(w, mode, start)
	case '`':
		return p.fail("unsupported_backtick_substitution")
	case '$':
		return p.expansion(w, mode == doubleQuotedWord)
	}

	return p.literalPart(w, mode, start)
}

func (p *parser) doubleQuotedPart(w *Word, start int) error {
	w.Quoted = true
	p.at++
	// Preserve the presence of an empty quote in word concatenation.
	if err := p.literal(w, start, p.at, "", true); err != nil {
		return err
	}

	return p.parts(w, '"')
}

func (p *parser) singleQuotedPart(w *Word, start int) error {
	w.Quoted = true
	p.at++
	inner := p.at

	n := strings.IndexByte(p.text[p.at:p.end], '\'')
	if n < 0 {
		return p.fail("unclosed_single_quote")
	}

	p.at += n + 1

	return p.literal(w, start, p.at, p.text[inner:p.at-1], true)
}

func (p *parser) escapedPart(w *Word, mode wordMode, start int) error {
	p.at++
	if p.at == p.end {
		return p.fail("trailing_escape")
	}

	next := p.text[p.at]
	if width := shellContinuationWidth(p.text[p.at:p.end]); width > 0 {
		p.at += width
		return nil
	}

	if mode != 0 && !strings.ContainsRune("$`\\", rune(next)) && !(mode == '"' && next == '"') {
		return p.literal(w, start, p.at, "\\", mode == '"')
	}

	w.Quoted = true
	_, n := utf8.DecodeRuneInString(p.text[p.at:p.end])
	p.at += n

	return p.literal(w, start, p.at, p.text[start+1:p.at], true)
}

func (p *parser) literalPart(w *Word, mode wordMode, start int) error {
	for p.at < p.end {
		c := p.text[p.at]
		if mode.literalBoundary(c) {
			break
		}

		if mode == 0 && strings.ContainsRune("*?[{}~", rune(c)) {
			w.Expands = true
		}

		p.at++
	}

	return p.literal(w, start, p.at, p.text[start:p.at], mode == '"')
}

func (p *parser) literal(w *Word, start, end int, text string, quoted bool) error {
	if err := p.tick(); err != nil {
		return err
	}

	w.Parts = append(w.Parts, Part{
		Kind:   "literal",
		Text:   text,
		Span:   source.Span{Start: start, End: end},
		Quoted: quoted,
	})

	return nil
}

func (p *parser) expansion(w *Word, quoted bool) error {
	if err := p.tick(); err != nil {
		return err
	}

	start := p.at

	p.at++
	if p.at == p.end {
		return p.literal(w, start, p.at, "$", quoted)
	}

	c := p.text[p.at]
	if c == '\'' || c == '"' {
		return p.fail("unsupported_dollar_quoting")
	}

	if c == '(' {
		return p.commandSubstitution(w, quoted, start)
	}

	return p.parameterExpansion(w, quoted, start, c)
}

func (p *parser) commandSubstitution(w *Word, quoted bool, start int) error {
	p.at++
	if p.at < p.end && p.text[p.at] == '(' {
		return p.fail("unsupported_arithmetic_expansion")
	}

	q, err := p.child(p.at, p.end)
	if err != nil {
		return err
	}

	tree, err := q.list(true)
	if err != nil {
		return err
	}

	closing, err := q.take()
	if err != nil || closing.kind != ")" {
		return p.fail("unclosed_substitution")
	}

	p.at = q.at
	w.Parts = append(w.Parts, Part{
		Kind:   "substitution",
		Tree:   tree,
		Span:   source.Span{Start: start, End: p.at},
		Quoted: quoted,
	})

	return nil
}

func (p *parser) parameterExpansion(w *Word, quoted bool, start int, c byte) error {
	begin := p.at
	if c == '{' {
		return p.bracedParameter(w, quoted, start)
	}

	if ident(c, true) {
		p.at++
		for p.at < p.end && ident(p.text[p.at], false) {
			p.at++
		}
	} else if strings.ContainsRune("0123456789@*#?$!-", rune(c)) {
		p.at++
	} else {
		return p.literal(w, start, p.at, "$", quoted)
	}

	w.Parts = append(w.Parts, Part{
		Kind: "parameter",
		Text: p.text[begin:p.at],
		Span: source.Span{
			Start: start,
			End:   p.at,
		},
		Quoted: quoted,
	})

	return nil
}

func (p *parser) hereBodies() error {
	pending := p.pending

	p.pending = nil
	for _, r := range pending {
		delim, _ := r.Target.Literal()
		start := p.at

		end, found, err := p.heredocEnd(r.Op, delim)
		if err != nil {
			return err
		}

		if !found {
			return p.fail("missing_heredoc")
		}

		body := &Word{Span: source.Span{Start: start, End: end}}
		if r.QuotedDelimiter {
			body.Quoted = true
			body.Parts = []Part{{Kind: "literal", Text: p.text[start:end], Span: body.Span, Quoted: true}}
		} else {
			q, err := p.child(start, end)
			if err != nil {
				return err
			}

			if err = q.parts(body, 'h'); err != nil {
				return err
			}
		}

		if r.Op == "<<-" {
			body.Expands = true
		} // tab-removal is not represented as a constant value

		r.Body = body
	}

	return nil
}

func (p *parser) skipTrivia() {
	for p.at < p.end {
		if p.text[p.at] == ' ' || p.text[p.at] == '\t' {
			p.at++
			continue
		}

		if strings.HasPrefix(p.text[p.at:p.end], "\\\r\n") {
			p.at += 3
			continue
		}

		if strings.HasPrefix(p.text[p.at:p.end], "\\\n") {
			p.at += 2
			continue
		}

		if p.text[p.at] == '#' {
			for p.at < p.end && p.text[p.at] != '\n' {
				p.at++
			}

			continue
		}

		break
	}
}

func shellContinuationWidth(text string) int {
	if strings.HasPrefix(text, "\r\n") {
		return 2
	}

	if strings.HasPrefix(text, "\n") {
		return 1
	}

	return 0
}

func (p *parser) bracedParameter(w *Word, quoted bool, start int) error {
	p.at++

	begin := p.at
	if p.at < p.end && ident(p.text[p.at], true) {
		p.at++
		for p.at < p.end && ident(p.text[p.at], false) {
			p.at++
		}
	}

	if p.at == begin || p.at == p.end || p.text[p.at] != '}' {
		return p.fail("unsupported_parameter_expansion")
	}

	name := p.text[begin:p.at]
	p.at++
	w.Parts = append(w.Parts, Part{
		Kind:   "parameter",
		Text:   name,
		Span:   source.Span{Start: start, End: p.at},
		Quoted: quoted,
	})

	return nil
}

func (p *parser) heredocEnd(op, delim string) (int, bool, error) {
	end := p.at
	for p.at < p.end {
		if err := p.budget.ctx.Err(); err != nil {
			return end, false, err
		}

		line := p.at
		end, next := shellLine(p.text, line, p.end)

		content := p.text[line:end]
		if op == "<<-" {
			content = strings.TrimLeft(content, "\t")
		}

		p.at = next

		if content == delim {
			return line, true, nil
		}
	}

	return end, false, nil
}

func shellLine(text string, start, end int) (int, int) {
	if n := strings.IndexByte(text[start:end], '\n'); n >= 0 {
		return start + n, start + n + 1
	}

	return end, end
}

func (mode wordMode) boundary(c byte) bool {
	switch mode {
	case ordinaryWord:
		return strings.ContainsRune(" \t\n;|&()<>", rune(c))
	case doubleQuotedWord:
		return c == '"'
	default:
		return false
	}
}

func (mode wordMode) literalBoundary(c byte) bool {
	switch c {
	case '$', '`', '\\':
		return true
	}

	switch mode {
	case doubleQuotedWord:
		return c == '"'
	case ordinaryWord:
		return strings.ContainsRune("'\" \t\n;|&()<>", rune(c))
	default:
		return false
	}
}
