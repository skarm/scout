package shellsyntax

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/source"
)

// Error contains only scanner-owned codes and a physical byte offset.
// Do not put source text, command names or parameter values in parse errors.
type Error struct {
	Code   string
	Offset int
}

type budget struct {
	ctx   context.Context
	nodes int
}

type token struct {
	kind string
	span source.Span
	word *Word
}

type parser struct {
	text           string
	at, end, depth int
	budget         *budget
	look           *token
	pending        []*Redirect
}

// Here-document delimiter words undergo quote removal, never parameter expansion.
type delimiterQuotes struct {
	quote  byte
	quoted bool
}

func Parse(ctx context.Context, text string) (*File, error) {
	if ctx == nil {
		return nil, errors.New("nil shell parser context")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(text) > MaxBytes {
		return nil, &Error{Code: "byte_limit"}
	}

	if !utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0 {
		return nil, &Error{Code: "invalid_text"}
	}

	p := parser{text: text, end: len(text), budget: &budget{ctx: ctx}}

	return p.list(false)
}

func (e *Error) Error() string { return "shell syntax: " + e.Code }

func (p *parser) fail(code string) error { return &Error{Code: code, Offset: p.at} }

func (p *parser) tick() error {
	if err := p.budget.ctx.Err(); err != nil {
		return err
	}

	p.budget.nodes++
	if p.budget.nodes > MaxNodes {
		return p.fail("node_limit")
	}

	return nil
}

func (p *parser) child(start, end int) (*parser, error) {
	if p.depth >= MaxDepth {
		return nil, p.fail("depth_limit")
	}

	return &parser{text: p.text, at: start, end: end, depth: p.depth + 1, budget: p.budget}, nil
}

func (p *parser) peek() (token, error) {
	if p.look != nil {
		return *p.look, nil
	}

	t, err := p.lex()
	if err == nil {
		p.look = &t
	}

	return t, err
}
func (p *parser) take() (token, error) { t, e := p.peek(); p.look = nil; return t, e }

func (p *parser) list(nested bool) (*File, error) {
	out := &File{}

	for {
		t, err := p.skipNewlines()
		if err != nil {
			return out, err
		}

		if t.kind == "eof" || t.kind == ")" {
			return out, p.listEnd(t.kind, nested)
		}

		s, err := p.statement()
		if err != nil {
			return out, err
		}

		if err := p.statementSeparator(s); err != nil {
			return out, err
		}

		out.Statements = append(out.Statements, s)
		if s.Next == "&&" || s.Next == "||" {
			if err := p.conditionalContinuation(); err != nil {
				return out, err
			}
		}
	}
}

func (p *parser) listEnd(kind string, nested bool) error {
	if kind == "eof" {
		if len(p.pending) > 0 {
			return p.fail("missing_heredoc")
		}

		if nested {
			return p.fail("unclosed_substitution_or_group")
		}

		return nil
	}

	if nested {
		return nil
	}

	return p.fail("unexpected_close")
}

func (p *parser) skipNewlines() (token, error) {
	for {
		t, err := p.peek()
		if err != nil {
			return t, err
		}

		if t.kind != "newline" {
			return t, nil
		}

		_, _ = p.take()
		if err := p.hereBodies(); err != nil {
			return token{}, err
		}
	}
}

func (p *parser) statementSeparator(s *Statement) error {
	t, err := p.peek()
	if err != nil {
		return err
	}

	switch t.kind {
	case "newline", ";", "&&", "||", "&":
		_, _ = p.take()

		s.Next = t.kind
		if t.kind == "newline" {
			return p.hereBodies()
		}
	case "eof", ")":
	default:
		return p.fail("expected_separator")
	}

	return nil
}

func (p *parser) conditionalContinuation() error {
	t, err := p.skipNewlines()
	if err != nil {
		return err
	}

	if t.kind == "eof" || t.kind == ")" {
		return p.fail("missing_conditional_command")
	}

	return nil
}

func (p *parser) statement() (*Statement, error) {
	if err := p.tick(); err != nil {
		return nil, err
	}

	c, err := p.command()
	if err != nil {
		return nil, err
	}

	s := &Statement{Span: c.Span, Commands: []*Command{c}}

	for {
		t, err := p.peek()
		if err != nil {
			return nil, err
		}

		if t.kind != "|" && t.kind != "|&" {
			break
		}

		_, _ = p.take() // peek already checked and cached this token.

		s.Pipes = append(s.Pipes, t.kind)

		if _, err = p.skipNewlines(); err != nil {
			return nil, err
		}

		c, err = p.command()
		if err != nil {
			return nil, err
		}

		s.Commands = append(s.Commands, c)
		s.Span.End = c.Span.End
	}

	return s, nil
}

func (p *parser) command() (*Command, error) {
	if err := p.tick(); err != nil {
		return nil, err
	}

	t, err := p.peek()
	if err != nil {
		return nil, err
	}

	c := &Command{Span: source.Span{Start: t.span.Start, End: t.span.End}}
	if t.kind == "(" {
		if err := p.commandGroup(c); err != nil {
			return nil, err
		}
	}

	return p.commandWords(c)
}

func (p *parser) commandGroup(c *Command) error {
	_, _ = p.take() // peek already checked and cached this token.

	q, err := p.child(p.at, p.end)
	if err != nil {
		return err
	}

	c.Subshell, err = q.list(true)
	if err != nil {
		return err
	}

	if len(c.Subshell.Statements) == 0 {
		return p.fail("empty_group")
	}

	closing, err := q.take()
	if err != nil || closing.kind != ")" {
		return p.fail("unclosed_group")
	}

	p.at = q.at
	c.Span.End = closing.span.End

	return nil
}

func (p *parser) commandWords(c *Command) (*Command, error) {
	for {
		t, err := p.peek()
		if err != nil {
			return nil, err
		}

		switch {
		case redirection(t.kind):
			r, err := p.redirect("")
			if err != nil {
				return nil, err
			}

			c.Redirects = append(c.Redirects, r)
			c.Span.End = r.Span.End
		case t.kind == "word":
			if err := p.commandToken(c, t.word); err != nil {
				return nil, err
			}
		default:
			if c.empty() {
				return nil, p.fail("expected_command")
			}

			return c, nil
		}
	}
}

func (p *parser) commandToken(c *Command, w *Word) error {
	if c.Subshell != nil {
		return p.fail("word_after_group")
	}

	_, _ = p.take()

	handled, err := p.wordRedirect(c, w)
	if err != nil {
		return err
	}

	if handled {
		return nil
	}

	return p.commandWord(c, w)
}

func (p *parser) wordRedirect(c *Command, w *Word) (bool, error) {
	if v, ok := w.Literal(); ok && !w.Quoted && digits(v) {
		next, err := p.peek()
		if err != nil {
			return false, err
		}

		if redirection(next.kind) && next.span.Start == w.Span.End {
			r, err := p.redirect(v)
			if err != nil {
				return false, err
			}

			r.Span.Start = w.Span.Start
			c.Redirects = append(c.Redirects, r)
			c.Span.End = r.Span.End

			return true, nil
		}
	}

	return false, nil
}

func (p *parser) redirect(fd string) (*Redirect, error) {
	op, err := p.take()
	if err != nil {
		return nil, err
	}

	var t token
	if op.kind == "<<" || op.kind == "<<-" {
		t, err = p.heredocWord()
	} else {
		t, err = p.take()
	}

	if err != nil {
		return nil, err
	}

	if t.kind != "word" {
		return nil, p.fail("missing_redirect_target")
	}

	r := &Redirect{Span: source.Span{Start: op.span.Start, End: t.span.End}, Op: op.kind, FD: fd, Target: t.word}
	if op.kind == "<<" || op.kind == "<<-" {
		if err := p.heredocRedirect(r, t); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// A heredoc delimiter is quote removal, not parameter/command expansion. Read
// it in that context so END$OF and locale quotes cannot become host lookups.
func (p *parser) heredocWord() (token, error) {
	for p.at < p.end && (p.text[p.at] == ' ' || p.text[p.at] == '\t') {
		p.at++
	}

	start := p.at
	if err := p.scanDelimiter(); err != nil {
		return token{}, err
	}

	delim, quoted, ok := literalDelimiter(p.text[start:p.at])
	if !ok {
		return token{}, p.fail("unsupported_heredoc_delimiter")
	}

	span := source.Span{Start: start, End: p.at}

	return token{
		kind: "word",
		span: span,
		word: &Word{
			Span:   span,
			Quoted: quoted,
			Parts: []Part{{
				Kind:   "literal",
				Text:   delim,
				Span:   span,
				Quoted: quoted,
			}},
		},
	}, nil
}

func redirection(s string) bool {
	switch s {
	case "<", ">", ">>", "<>", ">|", "<&", ">&", "<<", "<<-", "<<<", "&>", "&>>":
		return true
	}

	return false
}

func assignment(text string, w *Word) (Assignment, bool) {
	s := text[w.Span.Start:w.Span.End]

	i := 0
	for i < len(s) && ident(s[i], i == 0) {
		i++
	}

	if i == 0 || i >= len(s) || s[i] != '=' || len(w.Parts) == 0 || w.Parts[0].Kind != "literal" || !strings.HasPrefix(w.Parts[0].Text, s[:i+1]) {
		return Assignment{}, false
	}

	v := *w
	v.Span.Start += i + 1

	v.Parts = append([]Part(nil), w.Parts...)
	v.Parts[0].Text = v.Parts[0].Text[i+1:]
	v.Parts[0].Span.Start += i + 1

	return Assignment{Name: s[:i], Value: &v, Span: w.Span}, true
}

func reserved(s string) bool {
	switch s {
	case "if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case", "esac", "in", "select", "function", "coproc", "time", "!", "{", "}", "[[", "]]":
		return true
	}

	return false
}

func ident(c byte, first bool) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || !first && c >= '0' && c <= '9'
}

func digits(s string) bool {
	if s == "" {
		return false
	}

	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}

func (p *parser) scanDelimiter() error {
	q := delimiterQuotes{}

	for p.at < p.end {
		if err := p.tick(); err != nil {
			return err
		}

		c := p.text[p.at]
		if q.quote == 0 && strings.ContainsRune(" \t\r\n;|&()<>", rune(c)) {
			break
		}

		if c == '\\' && q.quote != '\'' {
			p.at += 2
			if p.at > p.end {
				return p.fail("unsupported_heredoc_delimiter")
			}

			continue
		}

		q.consume(c)

		p.at++
	}

	return nil
}

func invalidDelimiterExpansion(raw string, at int) bool {
	if raw[at] == '`' {
		return true
	}

	return raw[at] == '$' && at+1 < len(raw) && strings.ContainsRune("('", rune(raw[at+1]))
}

func literalDelimiter(raw string) (string, bool, bool) {
	// Bash locale quotes quote the delimiter; no locale lookup is performed.
	if strings.HasPrefix(raw, `$"`) && strings.HasSuffix(raw, `"`) {
		raw = raw[1:]
	}

	var b strings.Builder

	q := delimiterQuotes{}
	for i := 0; i < len(raw); i++ {
		next, value, ok := q.remove(raw, i)
		if !ok {
			return "", false, false
		}

		i = next

		b.WriteString(value)
	}

	return b.String(), q.quoted, q.quote == 0 && b.Len() > 0
}

func (p *parser) commandWord(c *Command, w *Word) error {
	if len(c.Words) == 0 {
		if a, ok := assignment(p.text, w); ok {
			c.Assignments = append(c.Assignments, a)
			c.Span.End = w.Span.End

			return nil
		}

		if !w.Quoted && reserved(p.text[w.Span.Start:w.Span.End]) {
			return p.fail("unsupported_compound_command")
		}
	}

	c.Words = append(c.Words, w)
	c.Span.End = w.Span.End

	return nil
}

func (p *parser) heredocRedirect(r *Redirect, t token) error {
	if _, ok := r.Target.Literal(); !ok {
		raw := p.text[t.span.Start:t.span.End]

		delim, quoted, ok := literalDelimiter(raw)
		if !ok {
			return p.fail("unsupported_heredoc_delimiter")
		}

		r.Target = &Word{
			Span:   t.span,
			Quoted: quoted,
			Parts: []Part{{
				Kind:   "literal",
				Text:   delim,
				Span:   t.span,
				Quoted: quoted,
			}},
		}
	}

	r.QuotedDelimiter = r.Target.Quoted
	p.pending = append(p.pending, r)

	return nil
}

func (c *Command) empty() bool {
	return c.Subshell == nil && len(c.Words) == 0 && len(c.Assignments) == 0 && len(c.Redirects) == 0
}

func (q *delimiterQuotes) consume(c byte) bool {
	if c != '\'' && c != '"' {
		return false
	}

	if q.quote == 0 {
		q.quote = c
		q.quoted = true

		return true
	}

	if q.quote == c {
		q.quote = 0
		return true
	}

	return false
}

func (q *delimiterQuotes) escaped(c byte) bool { return c == '\\' && q.quote != '\'' }
func (q *delimiterQuotes) remove(raw string, at int) (int, string, bool) {
	c := raw[at]
	if q.quote == 0 && invalidDelimiterExpansion(raw, at) {
		return at, "", false
	}

	if q.escaped(c) {
		if at+1 == len(raw) {
			return at, "", false
		}

		q.quoted = true

		return at + 1, raw[at+1 : at+2], true
	}

	if q.consume(c) {
		return at, "", true
	}

	return at, raw[at : at+1], true
}
