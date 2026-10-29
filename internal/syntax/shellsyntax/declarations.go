package shellsyntax

// A broader syntax frontend for declaration observation. It does not replace
// the bounded execution-flow grammar or claim POSIX execution semantics.
import (
	"context"
	"errors"
	"io"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/skarm/scout/internal/syntax/source"
)

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

type declarationProjection struct {
	ctx   context.Context
	text  string
	nodes int
	err   error
}

func ParseDeclarations(ctx context.Context, text string) (*File, error) {
	if ctx == nil {
		return nil, &Error{Code: "nil_context"}
	}

	if len(text) > MaxBytes {
		return nil, &Error{Code: "byte_limit"}
	}

	input := text

	var (
		tree *syntax.File
		err  error
	)
	for range 16 {
		tree, err = syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(contextReader{
			ctx:    ctx,
			reader: strings.NewReader(input),
		}, "")
		if err == nil {
			break
		}

		masked, ok := maskLiteralHeredoc(ctx, input, err)
		if !ok {
			break
		}

		input = masked
	}

	if err != nil || tree == nil {
		return nil, &Error{Code: "unsupported_declaration_syntax"}
	}

	p := declarationProjection{ctx: ctx, text: text}
	out := p.list(tree.Stmts, 0)

	return out, p.err
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}

	return r.reader.Read(p)
}

func (p *declarationProjection) step(depth int) bool {
	p.nodes++
	if p.err == nil && (depth > MaxDepth || p.nodes > MaxNodes || p.ctx.Err() != nil) {
		p.err = &Error{Code: "declaration_limit"}
	}

	return p.err == nil
}

func (p *declarationProjection) list(stmts []*syntax.Stmt, depth int) *File {
	f := &File{}
	for _, stmt := range stmts {
		f.Statements = append(f.Statements, p.statement(stmt, depth+1)...)
		if p.err != nil {
			break
		}
	}

	return f
}

func (p *declarationProjection) statement(s *syntax.Stmt, depth int) []*Statement {
	if s == nil || !p.step(depth) {
		return nil
	}

	if b, ok := s.Cmd.(*syntax.BinaryCmd); ok {
		return p.binaryStatement(s, b, depth)
	}

	c := &Command{Span: declarationSpan(s)}
	p.projectCommand(c, s.Cmd, depth)

	for _, r := range s.Redirs {
		c.Redirects = append(c.Redirects, p.projectRedirect(r, depth))
	}

	next := ""
	if s.Background {
		next = "&"
	}

	return []*Statement{{Span: c.Span, Commands: []*Command{c}, Next: next}}
}

func (p *declarationProjection) projectCommand(c *Command, cmd syntax.Command, depth int) {
	switch n := cmd.(type) {
	case *syntax.CallExpr:
		p.projectAssignments(c, n.Assigns, depth)

		for _, w := range n.Args {
			c.Words = append(c.Words, p.word(w, depth+1))
		}
	case *syntax.DeclClause:
		p.declarationAssignments(c, n, depth)
	default:
		p.projectCompound(c, cmd, depth)
	}
}

func (p *declarationProjection) declarationAssignments(c *Command, n *syntax.DeclClause, depth int) {
	for _, a := range n.Args {
		if a.Name == nil && a.Value != nil {
			if assignment, ok := p.declarationValue(a, depth); ok {
				c.Assignments = append(c.Assignments, assignment)
			}

			continue
		}

		if a.Name == nil || a.Naked {
			continue
		}

		c.Assignments = append(c.Assignments, Assignment{
			Name:  a.Name.Value,
			Value: p.word(a.Value, depth+1),
			Span:  declarationSpan(a),
		})
	}
}

func (p *declarationProjection) declarationValue(a *syntax.Assign, depth int) (Assignment, bool) {
	value := p.word(a.Value, depth+1)
	if len(value.Parts) == 0 || value.Parts[0].Kind != "literal" {
		return Assignment{}, false
	}

	key, tail, ok := strings.Cut(value.Parts[0].Text, "=")
	if !ok || !shellIdentifier(key) {
		return Assignment{}, false
	}

	value.Parts[0].Text = tail

	return Assignment{Name: key, Value: value, Span: declarationSpan(a)}, true
}

func shellIdentifier(name string) bool {
	if name == "" {
		return false
	}

	for i := range len(name) {
		if !ident(name[i], i == 0) {
			return false
		}
	}

	return true
}

func (p *declarationProjection) projectCompound(c *Command, cmd syntax.Command, depth int) {
	switch n := cmd.(type) {
	case *syntax.TimeClause:
		c.Group = &File{Statements: p.statement(n.Stmt, depth+1)}
	case *syntax.Block:
		c.Group = p.list(n.Stmts, depth+1)
	case *syntax.Subshell:
		c.Subshell = p.list(n.Stmts, depth+1)
	case *syntax.FuncDecl:
		if n.Name != nil {
			c.FunctionName = n.Name.Value
			c.FunctionBody = &File{Statements: p.statement(n.Body, depth+1)}
		}
	default:
		p.projectControl(c, cmd, depth)
	}
}

func (p *declarationProjection) projectControl(c *Command, cmd syntax.Command, depth int) {
	switch n := cmd.(type) {
	case *syntax.IfClause:
		p.projectConditional(c, n, depth)

	case *syntax.WhileClause:
		c.Prelude = p.list(n.Cond, depth+1)
		c.Alternatives = []*File{p.list(n.Do, depth+1), {}}
	case *syntax.ForClause:
		if loop, ok := n.Loop.(*syntax.WordIter); ok && loop.Name != nil {
			c.Invalidates = []string{loop.Name.Value}
		}

		c.Alternatives = []*File{p.list(n.Do, depth+1), {}}
	case *syntax.CaseClause:
		c.Alternatives = []*File{{}}
		for _, item := range n.Items {
			c.Alternatives = append(c.Alternatives, p.list(item.Stmts, depth+1))
		}
	default:
		// Unsupported execution effects form an explicit variable barrier.
		c.Invalidates = []string{"*"}
	}
}

func (p *declarationProjection) projectRedirect(r *syntax.Redirect, depth int) *Redirect {
	raw := p.word(r.Word, depth+1)

	red := &Redirect{Span: declarationSpan(r), Op: r.Op.String(), Target: raw}
	if r.N != nil {
		red.FD = r.N.Value
	}

	if r.Hdoc != nil {
		red.Body = p.word(r.Hdoc, depth+1)
		red.QuotedDelimiter = raw.Quoted
		// mvdan's final heredoc literal position can include its closing
		// delimiter. The analyzer needs the physical body only.
		if delim, quoted, ok := literalDelimiter(p.text[int(r.Word.Pos().Offset()):int(r.Word.End().Offset())]); ok {
			red.QuotedDelimiter = quoted

			red.Target = &Word{
				Span:   raw.Span,
				Quoted: quoted,
				Parts: []Part{{
					Kind:   "literal",
					Text:   delim,
					Span:   raw.Span,
					Quoted: quoted,
				}},
			}
			for start := red.Body.Span.Start; start < len(p.text); {
				end := len(p.text)
				if n := strings.IndexByte(p.text[start:], '\n'); n >= 0 {
					end = start + n
				}

				line := strings.TrimSuffix(p.text[start:end], "\r")
				if r.Op.String() == "<<-" {
					line = strings.TrimLeft(line, "\t")
				}

				if line == delim {
					red.Body.Span.End = start
					break
				}

				start = end + 1
			}
		}
	}

	return red
}

func (p *declarationProjection) word(w *syntax.Word, depth int) *Word {
	if w == nil {
		return &Word{}
	}

	out := &Word{Span: declarationSpan(w)}

	p.wordParts(out, w.Parts, false, depth+1)

	return out
}

func (p *declarationProjection) wordParts(out *Word, xs []syntax.WordPart, quoted bool, depth int) {
	for _, x := range xs {
		if !p.step(depth) {
			return
		}

		if part := p.wordPart(out, x, quoted, depth); part != nil {
			out.Parts = append(out.Parts, *part)
		}
	}
}

func (p *declarationProjection) wordPart(out *Word, x syntax.WordPart, quoted bool, depth int) *Part {
	part := Part{Span: declarationSpan(x), Quoted: quoted}
	switch n := x.(type) {
	case *syntax.Lit:
		part.Kind = "literal"
		part.Text = declarationLiteral(n.Value, quoted, out)
	case *syntax.SglQuoted:
		out.Quoted = true
		part.Quoted = true
		part.Kind = "literal"

		part.Text = n.Value
		if n.Dollar {
			out.Expands = true
		}
	case *syntax.DblQuoted:
		out.Quoted = true
		p.wordParts(out, n.Parts, true, depth+1)

		return nil
	case *syntax.ParamExp:
		p.parameterPart(out, n, &part)

	case *syntax.CmdSubst:
		part.Kind = "substitution"
		part.Tree = p.list(n.Stmts, depth+1)
	default:
		out.Expands = true
	}

	return &part
}

func (p *declarationProjection) parameterPart(out *Word, n *syntax.ParamExp, part *Part) {
	part.Kind = "parameter"
	if n.Param != nil {
		part.Text = n.Param.Value

		raw := p.text[part.Span.Start:part.Span.End]
		if raw != "$"+part.Text && raw != "${"+part.Text+"}" {
			out.Expands = true
		}
	} else {
		out.Expands = true
	}
}

func declarationLiteral(value string, quoted bool, out *Word) string {
	var literal strings.Builder

	for i := 0; i < len(value); i++ {
		b := value[i]
		if b == '\\' && i+1 < len(value) && (!quoted || strings.ContainsRune("$`\\\"\n", rune(value[i+1]))) {
			i++

			b = value[i]
			if b == '\n' {
				continue
			}
		} else if !quoted && strings.ContainsRune("*?[{~", rune(b)) {
			out.Expands = true
		}

		literal.WriteByte(b)
	}

	return literal.String()
}

// The syntax library rejects dollars in some literal heredoc delimiters.
// Only its explicit heredoc-word/unclosed-heredoc error authorizes this projection;
// quoted examples/comments and body bytes are never rewritten. The original
// delimiter is restored below, and all offsets remain physical byte offsets.
func maskLiteralHeredoc(ctx context.Context, text string, err error) (string, bool) {
	op, ok := heredocErrorOperator(text, err)
	if !ok {
		return "", false
	}

	start := op + 2
	stripTabs := false

	if start < len(text) && text[start] == '-' {
		start++
		stripTabs = true
	}

	p := parser{text: text, at: start, end: len(text), budget: &budget{ctx: ctx}}

	word, e := p.heredocWord()
	if e != nil {
		return "", false
	}

	delim, ok := word.word.Literal()
	if !ok || !strings.Contains(delim, "$") {
		return "", false
	}

	masked := []byte(text)
	maskDollars(masked, word.span.Start, word.span.End)

	return maskHeredocClosing(masked, text, word.span.End, delim, stripTabs)
}

func heredocErrorOperator(text string, err error) (int, bool) {
	var failure syntax.ParseError
	if !errors.As(err, &failure) {
		return 0, false
	}

	if failure.Text != "expansions not allowed in heredoc words" && !strings.HasPrefix(failure.Text, "unclosed here-document ") {
		return 0, false
	}

	offset := int(failure.Pos.Offset())
	if offset > len(text) {
		return 0, false
	}

	line := strings.LastIndexByte(text[:offset], '\n') + 1
	op := strings.LastIndex(text[line:min(len(text), offset+2)], "<<")

	return line + op, op >= 0
}

func maskDollars(masked []byte, start, end int) {
	for i := start; i < end; i++ {
		if masked[i] == '$' {
			masked[i] = '_'
		}
	}
}

func maskHeredocClosing(masked []byte, text string, wordEnd int, delim string, stripTabs bool) (string, bool) {
	for at := strings.IndexByte(text[wordEnd:], '\n') + wordEnd + 1; at > wordEnd && at < len(text); {
		end, next := shellLine(text, at, len(text))

		value := strings.TrimSuffix(text[at:end], "\r")
		if stripTabs {
			value = strings.TrimLeft(value, "\t")
		}

		if value == delim {
			maskDollars(masked, at, end)
			return string(masked), true
		}

		at = next
	}

	return "", false
}

func declarationSpan(n syntax.Node) source.Span {
	return source.Span{Start: int(n.Pos().Offset()), End: int(n.End().Offset())}
}

func (p *declarationProjection) binaryStatement(s *syntax.Stmt, b *syntax.BinaryCmd, depth int) []*Statement {
	x, y := p.statement(b.X, depth+1), p.statement(b.Y, depth+1)
	if b.Op.String() == "|" || b.Op.String() == "|&" {
		if len(x) == 1 && len(y) == 1 {
			x[0].Commands = append(x[0].Commands, y[0].Commands...)
			x[0].Pipes = append(append(x[0].Pipes, b.Op.String()), y[0].Pipes...)
			x[0].Span = declarationSpan(s)

			return x
		}
	} else if len(x) > 0 {
		x[len(x)-1].Next = b.Op.String()
	}

	return append(x, y...)
}

func (p *declarationProjection) projectAssignments(c *Command, assignments []*syntax.Assign, depth int) {
	for _, a := range assignments {
		if a.Name == nil {
			continue
		}

		value := p.word(a.Value, depth+1)
		if a.Append || a.Index != nil || a.Array != nil {
			value = &Word{Span: declarationSpan(a), Expands: true}
		}

		c.Assignments = append(c.Assignments, Assignment{Name: a.Name.Value, Value: value, Span: declarationSpan(a)})
	}
}

func (p *declarationProjection) projectConditional(c *Command, n *syntax.IfClause, depth int) {
	c.Prelude = p.list(n.Cond, depth+1)

	other := &File{}
	if n.Else != nil {
		other = &File{Statements: p.statement(&syntax.Stmt{Position: n.Else.Pos(), Cmd: n.Else}, depth+1)}
	}

	c.Alternatives = []*File{p.list(n.Then, depth+1), other}
}
