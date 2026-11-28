package shellsyntax

// A broader syntax frontend for declaration observation. It does not replace
// the bounded execution-flow grammar or claim POSIX execution semantics.
import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/skarm/scout/internal/syntax/source"

	"mvdan.cc/sh/v3/syntax"
)

const (
	codeByteLimit                    = "byte_limit"
	codeDeclarationLimit             = "declaration_limit"
	codeNilContext                   = "nil_context"
	codeUnsupportedDeclarationSyntax = "unsupported_declaration_syntax"
)

const (
	maxProjectedArrayItems = 8
)

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

type declarationProjection struct {
	ctx              context.Context
	text             string
	nodes            int
	err              error
	omittedExecution bool
}

func ParseDeclarations(ctx context.Context, text string) (*File, error) {
	if ctx == nil {
		return nil, &Error{Code: codeNilContext}
	}

	if len(text) > MaxBytes {
		return nil, &Error{Code: codeByteLimit}
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
		return nil, &Error{Code: codeUnsupportedDeclarationSyntax}
	}

	p := declarationProjection{ctx: ctx, text: text}
	out := p.list(tree.Stmts, 0)
	out.OmittedExecution = p.omittedExecution

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
		p.err = &Error{Code: codeDeclarationLimit}
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
		next = Background
	}

	return []*Statement{{
		Span:       c.Span,
		Commands:   []*Command{c},
		Next:       next,
		Negated:    s.Negated,
		Background: s.Background,
	}}
}

func (p *declarationProjection) projectCommand(c *Command, cmd syntax.Command, depth int) {
	switch n := cmd.(type) {
	case *syntax.CallExpr:
		p.projectAssignments(c, n.Assigns, depth)

		for _, w := range n.Args {
			c.Words = append(c.Words, p.word(w, depth+1))
		}
	case *syntax.DeclClause:
		c.Declaration = n.Variant.Value
		p.declarationAssignments(c, n, depth)
	default:
		p.projectCompound(c, cmd, depth)
	}
}

func (p *declarationProjection) declarationAssignments(c *Command, n *syntax.DeclClause, depth int) {
	for _, a := range n.Args {
		if a.Name == nil && a.Value != nil {
			word := p.word(a.Value, depth+1)

			// A word operand may expand into more than one declaration argument.
			if c.Declaration == "local" {
				c.ComplexLocal = true
			}

			if value, ok := declarationValue(a, word); ok {
				c.Assignments = append(c.Assignments, value)
			} else {
				c.DeclarationArgs = append(c.DeclarationArgs, word)
			}

			continue
		}

		if a.Name == nil {
			continue
		}

		if c.Declaration == "local" {
			switch {
			case a.Append || a.Index != nil:
				c.ComplexLocal = true
			case a.Naked:
				c.Assignments = append(c.Assignments, Assignment{Name: a.Name.Value, Span: declarationSpan(a)})
			}
		}

		if a.Naked {
			if a.Index != nil || a.Array != nil {
				p.omittedExecution = true
				c.Invalidates = []string{"*"}
			}

			continue
		}

		c.Assignments = append(c.Assignments, Assignment{
			Name:  a.Name.Value,
			Value: p.assignmentWord(a, depth),
			Span:  declarationSpan(a),
		})
	}
}

func declarationValue(a *syntax.Assign, value *Word) (Assignment, bool) {
	if len(value.Parts) == 0 || value.Parts[0].Kind != PartLiteral {
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
		c.Loop = true
		c.Until = n.Until
		c.Prelude = p.list(n.Cond, depth+1)
		c.Alternatives = []*File{p.list(n.Do, depth+1), {}}

		if !n.Until {
			c.WhileAssignments = whileAssignmentNames(c.Prelude, c.Alternatives[0])
		}
	case *syntax.ForClause:
		c.Loop = true

		if loop, ok := n.Loop.(*syntax.WordIter); ok && loop.Name != nil {
			c.Invalidates = []string{loop.Name.Value}
			p.projectForList(c, loop, depth)
		}

		p.omittedExecution = p.omittedExecution || c.ForFileGlob == nil && c.ForArguments == ""
		c.Alternatives = []*File{p.list(n.Do, depth+1), {}}
	case *syntax.CaseClause:
		p.projectCase(c, n, depth)
	case *syntax.TestClause:
		c.ReadOnlyTest = p.readOnlyTest(c, n.X, depth+1)
		if c.ReadOnlyTest {
			c.DecimalGuard = p.decimalGuard(n.X, depth+1)
			c.PositionalNonempty = p.positionalNonemptyTest(n.X)
			c.NonemptyParameter = p.nonemptyParameterTest(n.X)
		} else {
			p.omittedExecution = true
			c.Invalidates = []string{"*"}
		}
	case *syntax.ArithmCmd:
		if !n.Unsigned {
			c.ArithmeticUpdate = arithmeticUpdate(n.X)
		}

		if c.ArithmeticUpdate != "" {
			// Generic consumers have no proof of the operand's contents.
			c.Invalidates = []string{"*"}
			break
		}

		c.ReadOnlyTest = !n.Unsigned && p.arithmeticPredicate(c, n.X, depth+1)
		if !c.ReadOnlyTest {
			p.omittedExecution = true
			c.Invalidates = []string{"*"}
		}
	default:
		// Unsupported execution effects form an explicit variable barrier.
		p.omittedExecution = true
		c.Invalidates = []string{"*"}
	}
}

func whileAssignmentNames(cond, body *File) []string {
	if len(cond.Statements) != 1 || len(body.Statements) == 0 {
		return nil
	}

	predicate := plainLoopCommand(cond.Statements[0])
	if predicate == nil || !predicate.ReadOnlyTest || predicate.RegexTest || len(predicate.NumericTest) != 0 || len(predicate.IndirectTest) != 0 {
		return nil
	}

	var names []string

	for _, stmt := range body.Statements {
		cmd := plainLoopCommand(stmt)
		if cmd == nil || cmd.Declaration != "" || len(cmd.Assignments) == 0 {
			return nil
		}

		for _, assignment := range cmd.Assignments {
			if assignment.Value == nil || !sideEffectFreeWord(assignment.Value) {
				return nil
			}

			names = append(names, assignment.Name)
		}
	}

	return names
}

func plainLoopCommand(stmt *Statement) *Command {
	if stmt.Background || len(stmt.Commands) != 1 || stmt.Next == Background || stmt.Next == AndThen || stmt.Next == OrElse || stmt.Negated {
		return nil
	}

	cmd := stmt.Commands[0]
	if len(cmd.Words) != 0 || len(cmd.Redirects) != 0 || cmd.Subshell != nil || cmd.Group != nil || len(cmd.Alternatives) != 0 || cmd.FunctionName != "" {
		return nil
	}

	return cmd
}

func (p *declarationProjection) projectCase(c *Command, n *syntax.CaseClause, depth int) {
	selection := &CaseSelection{Word: p.word(n.Word, depth+1)}
	if !projectControlOperand(c, selection.Word) {
		p.omittedExecution = true
	}

	for _, item := range n.Items {
		c.Alternatives = append(c.Alternatives, p.list(item.Stmts, depth+1))
		if item.OpPos.IsValid() && item.Op != syntax.Break {
			selection = nil
			p.omittedExecution = true
		}

		if selection != nil {
			patterns := make([]*Word, 0, len(item.Patterns))
			for _, pattern := range item.Patterns {
				word := p.word(pattern, depth+1)
				p.omittedExecution = p.omittedExecution || !sideEffectFreeWord(word)
				patterns = append(patterns, word)
			}

			selection.Patterns = append(selection.Patterns, patterns)
		}
	}

	// Keep the conservative no-match path for rules that only inspect bodies.
	c.Alternatives = append(c.Alternatives, &File{})

	// Other analyzers may still inspect all bodies. The hook walker uses
	// patterns only where each match stops after its own arm.
	c.Case = selection
}

func (p *declarationProjection) readOnlyTest(c *Command, test syntax.TestExpr, depth int) bool {
	if !p.step(depth) {
		return false
	}

	switch n := test.(type) {
	case *syntax.BinaryTest:
		switch n.Op {
		case syntax.TsMatchShort, syntax.TsMatch, syntax.TsNoMatch, syntax.TsReMatch, syntax.TsBefore, syntax.TsAfter, syntax.TsNewer, syntax.TsOlder, syntax.TsDevIno, syntax.AndTest, syntax.OrTest:
			c.RegexTest = c.RegexTest || n.Op == syntax.TsReMatch

			return p.readOnlyTest(c, n.X, depth+1) && p.readOnlyTest(c, n.Y, depth+1)
		case syntax.TsEql, syntax.TsNeq, syntax.TsLss, syntax.TsLeq, syntax.TsGtr, syntax.TsGeq:
			return p.numericTestOperand(c, n.X, depth+1) && p.numericTestOperand(c, n.Y, depth+1)
		}
	case *syntax.UnaryTest:
		switch n.Op {
		case syntax.TsNot, syntax.TsEmpStr, syntax.TsNempStr, syntax.TsDirect, syntax.TsExists, syntax.TsRegFile, syntax.TsRead, syntax.TsWrite, syntax.TsExec, syntax.TsNoEmpty, syntax.TsSmbLink:
			return p.readOnlyTest(c, n.X, depth+1)
		case syntax.TsFdTerm:
			word, ok := n.X.(*syntax.Word)
			if ok {
				fd, literal := p.word(word, depth+1).Literal()
				return literal && digits(fd)
			}
		}
	case *syntax.ParenTest:
		return p.readOnlyTest(c, n.X, depth+1)
	case *syntax.Word:
		return projectControlOperand(c, p.word(n, depth+1))
	}

	return false
}

func (p *declarationProjection) numericTestOperand(c *Command, expr syntax.TestExpr, depth int) bool {
	word, ok := expr.(*syntax.Word)
	if !ok {
		return false
	}

	value := p.word(word, depth)
	if text, literal := value.Literal(); literal && digits(text) {
		return true
	}

	if !value.Writes && len(value.Parts) == 1 {
		part := value.Parts[0]
		if part.Kind == PartParameterLength || part.Kind == PartParameter && (part.Text == "?" || part.Text == "#") {
			return true
		}
	}

	if value.Expands || value.Writes || len(value.Parts) != 1 || value.Parts[0].Kind != PartParameter ||
		!shellIdentifier(value.Parts[0].Text) {
		return false
	}

	c.NumericTest = append(c.NumericTest, value)

	return true
}

func (p *declarationProjection) positionalNonemptyTest(expr syntax.TestExpr) bool {
	test, ok := expr.(*syntax.BinaryTest)
	if !ok || test.Op != syntax.TsGtr {
		return false
	}

	left := p.text[test.X.Pos().Offset():test.X.End().Offset()]
	right := p.text[test.Y.Pos().Offset():test.Y.End().Offset()]

	return (left == "$#" || left == "${#}" || left == `"$#"` || left == `"${#}"`) && right == "0"
}

func (p *declarationProjection) nonemptyParameterTest(expr syntax.TestExpr) string {
	test, ok := expr.(*syntax.UnaryTest)
	if !ok || test.Op != syntax.TsNempStr {
		return ""
	}

	raw := p.text[test.X.Pos().Offset():test.X.End().Offset()]
	parameter, ok := strings.CutPrefix(raw, `"$`)
	name, quoted := strings.CutSuffix(parameter, `"`)

	if !ok || !quoted {
		return ""
	}

	if inner, braced := strings.CutPrefix(name, "{"); braced {
		var closed bool

		name, closed = strings.CutSuffix(inner, "}")
		if !closed {
			return ""
		}
	}

	if !shellIdentifier(name) {
		return ""
	}

	return name
}

func projectControlOperand(c *Command, word *Word) bool {
	if len(word.Parts) == 1 && word.Parts[0].Kind == PartParameterIndirect {
		c.IndirectTest = append(c.IndirectTest, word.Parts[0].Text)
		return true
	}

	hasSubstitution, safe := readOnlyExpansion(word, false)
	if safe && hasSubstitution {
		c.ExpansionWords = append(c.ExpansionWords, word)
	}

	return safe
}

func readOnlyExpansion(word *Word, allowArray bool) (hasSubstitution, safe bool) {
	if word.Writes {
		return false, false
	}

	for _, part := range word.Parts {
		if part.Tree != nil || part.Operand != nil {
			hasSubstitution = true
			continue
		}

		if !sideEffectFreePart(part.Kind) && !(allowArray && (part.Kind == PartParameterArrayAll || part.Kind == PartParameterArrayAllDefaultEmpty)) {
			return false, false
		}
	}

	return hasSubstitution, true
}

func sideEffectFreeWord(word *Word) bool {
	if word.Writes {
		return false
	}

	for _, part := range word.Parts {
		if !sideEffectFreePart(part.Kind) {
			return false
		}
	}

	return true
}

func sideEffectFreePart(kind string) bool {
	switch kind {
	case PartLiteral, PartParameter, PartParameterDefaultDot, PartParameterDefaultEmpty, PartParameterTrimNewline,
		PartParameterScriptDir, PartParameterReplaceAll, PartParameterBashSource, PartParameterValue, PartParameterLength, partParameterArrayJoin:
		return true
	default:
		return false
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
		word := p.text[int(r.Word.Pos().Offset()):int(r.Word.End().Offset())]
		if delim, quoted, ok := literalDelimiter(word); ok {
			red.QuotedDelimiter = quoted

			red.Target = &Word{
				Span:   raw.Span,
				Quoted: quoted,
				Parts: []Part{{
					Kind:   PartLiteral,
					Text:   delim,
					Span:   raw.Span,
					Quoted: quoted,
				}},
			}
			p.verifyHeredocBody(red, delim, word)
		}
	}

	return red
}

func (p *declarationProjection) verifyHeredocBody(red *Redirect, delimiter, word string) {
	start, end := red.Body.Span.Start, red.Body.Span.End
	if start > end || end > len(p.text) || strings.Contains(word, "$\"") {
		return
	}
	// The broader grammar may omit leading tabs from the first literal.
	line := strings.LastIndexByte(p.text[:start], '\n') + 1
	if strings.Trim(p.text[line:start], "\t") != "" {
		return
	}
	// The raw search is confined to the declaration parser's own body and
	// closing line, so many rejected redirects cannot rescan the file.
	_, bound := shellLine(p.text, end, len(p.text))

	scan := parser{text: p.text, at: line, end: bound, budget: &budget{ctx: p.ctx}}
	if end, ok, _ := scan.heredocEnd(red.Op, delimiter, red.QuotedDelimiter); ok {
		red.Body.Span = source.Span{Start: line, End: end}
		red.BodyVerified = true
	}
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
		part.Kind = PartLiteral
		part.Text = declarationLiteral(n.Value, quoted, out)
	case *syntax.SglQuoted:
		out.Quoted = true
		part.Quoted = true
		part.Kind = PartLiteral

		part.Text = n.Value
		if n.Dollar {
			out.Expands = true
		}
	case *syntax.DblQuoted:
		out.Quoted = true
		p.wordParts(out, n.Parts, true, depth+1)

		return nil
	case *syntax.ParamExp:
		if p.projectIndirectParameter(n, &part, depth) {
			out.Writes = true // Requires a proof of the referent at runtime.
			break
		}

		if p.projectReadOnlyReplacement(n, &part) {
			break
		}

		p.parameterPart(out, n, &part)

		if !p.readOnlyParameter(n, &part, depth) {
			out.Writes = true
			p.omittedExecution = true
		}

		out.Writes = out.Writes || part.ArrayIndex != nil
	case *syntax.ArithmExp:
		out.Expands, out.Writes = true, true

		cmd := Command{NumericTest: []*Word{}}
		if !n.Unsigned && p.arithmeticPredicate(&cmd, n.X, depth+1) {
			part.Kind, part.ArithmeticOperands = PartArithmetic, cmd.NumericTest
		} else {
			p.omittedExecution = true
		}

	case *syntax.ProcSubst:
		out.Expands = true
		part.Kind = PartProcessSubstitution
		part.Tree = p.list(n.Stmts, depth+1)
	case *syntax.CmdSubst:
		if n.TempFile || n.ReplyVar {
			out.Expands, out.Writes = true, true
			p.omittedExecution = true

			break
		}

		part.Kind = PartSubstitution
		part.Tree = p.list(n.Stmts, depth+1)
	default:
		out.Expands = true
		p.omittedExecution = true
	}

	return &part
}

// These replacements read shell data without evaluating arithmetic or commands.
// Their values still depend on runtime data or locale.
func (p *declarationProjection) projectReadOnlyReplacement(n *syntax.ParamExp, part *Part) bool {
	if !part.Quoted || n.Param == nil || !shellIdentifier(n.Param.Value) || n.Repl == nil || n.Index != nil || n.Excl {
		return false
	}

	raw := p.text[part.Span.Start:part.Span.End]
	if raw == "${"+n.Param.Value+"//[[:space:]]/}" {
		part.Kind, part.Text, part.SingleField = PartParameterValue, n.Param.Value, true
		return true
	}

	tail, prefix := strings.CutPrefix(raw, "${"+n.Param.Value+`/#\~/$`)

	replacement, closed := strings.CutSuffix(tail, "}")
	if !prefix || !closed || !shellIdentifier(replacement) {
		return false
	}

	part.Kind, part.Text, part.SingleField = PartParameterValue, n.Param.Value, true

	return true
}

func (p *declarationProjection) readOnlyParameter(n *syntax.ParamExp, part *Part, depth int) bool {
	if n.Excl {
		return false
	}

	if n.Index != nil {
		if !p.readOnlyArrayParameter(n, *part) {
			if !plainIndexedParameter(n) {
				return false
			}

			part.ArrayIndex = p.simpleArithmeticIndex(n.Index, depth+1)
			part.Kind = partParameterIndex

			return part.ArrayIndex != nil
		}
	}

	if n.Repl != nil {
		return part.Replacement != nil
	}

	if n.Slice != nil {
		return p.literalSliceIndex(n.Slice.Offset) && p.literalSliceIndex(n.Slice.Length)
	}

	if n.Exp == nil || part.Kind != PartParameter {
		return true
	}

	switch n.Exp.Op {
	case syntax.DefaultUnset, syntax.DefaultUnsetOrNull, syntax.AlternateUnset, syntax.AlternateUnsetOrNull,
		syntax.RemSmallSuffix, syntax.RemLargeSuffix, syntax.RemSmallPrefix, syntax.RemLargePrefix:
		operand := p.word(n.Exp.Word, depth+1)

		hasSubstitution, safe := readOnlyExpansion(operand, false)
		if !safe {
			return false
		}

		part.Kind = PartParameterValue
		part.TrimPrefix = literalParameterPrefix(n.Exp.Op, operand)
		part.SingleField = singleFieldParameterOperand(n, operand)

		part.DefaultIfUnset = n.Index == nil && (n.Exp.Op == syntax.DefaultUnset || n.Exp.Op == syntax.DefaultUnsetOrNull)
		if hasSubstitution {
			part.Operand = operand
		}

		return true
	case syntax.UpperAll, syntax.LowerAll:
		return n.Exp.Word == nil || len(n.Exp.Word.Parts) == 0
	default:
		return false
	}
}

func literalParameterPrefix(op syntax.ParExpOperator, word *Word) string {
	if op != syntax.RemSmallPrefix {
		return ""
	}

	prefix, known := word.Literal()
	if !known || strings.Trim(prefix, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._=-/") != "" {
		return ""
	}

	return prefix
}

func singleFieldParameterOperand(n *syntax.ParamExp, operand *Word) bool {
	if n.Index != nil || n.Param == nil || n.Param.Value == "@" || n.Param.Value == "*" {
		return false
	}

	for _, part := range operand.Parts {
		switch part.Kind {
		case PartLiteral, PartSubstitution, PartParameterDefaultDot, PartParameterDefaultEmpty, PartParameterScriptDir, PartParameterBashSource:
		case PartParameter:
			if part.Text == "@" || part.Text == "*" || operand.Expands {
				return false
			}
		case PartParameterValue:
			if !part.SingleField {
				return false
			}
		default:
			return false
		}
	}

	return true
}

func (p *declarationProjection) readOnlyArrayParameter(n *syntax.ParamExp, part Part) bool {
	index, ok := n.Index.(*syntax.Word)
	if !ok || n.Param == nil || n.Repl != nil || n.Slice != nil {
		return false
	}

	if part.Kind == PartParameterArrayAll || part.Kind == PartParameterArrayAllDefaultEmpty ||
		part.Kind == partParameterArrayJoin || part.Kind == PartParameterLength || part.Kind == PartParameterBashSource {
		return true
	}

	if !digits(p.text[index.Pos().Offset():index.End().Offset()]) {
		return false
	}

	return n.Param.Value == "BASH_REMATCH" && n.Exp == nil ||
		n.Param.Value == "BASH_VERSINFO" && (n.Exp == nil || n.Exp.Op == syntax.DefaultUnsetOrNull && p.literalSliceIndex(n.Exp.Word))
}

func (p *declarationProjection) literalSliceIndex(expr syntax.ArithmExpr) bool {
	if expr == nil {
		return true
	}

	word, ok := expr.(*syntax.Word)

	return ok && (word == nil || digits(p.text[word.Pos().Offset():word.End().Offset()]))
}

func (p *declarationProjection) parameterPart(out *Word, n *syntax.ParamExp, part *Part) {
	part.Kind = PartParameter
	if n.Param != nil {
		part.Text = n.Param.Value

		raw := p.text[part.Span.Start:part.Span.End]

		if shellIdentifier(part.Text) && (raw == "${#"+part.Text+"}" || raw == "${#"+part.Text+"[@]}" || raw == "${#"+part.Text+"[*]}") {
			part.Kind, out.Expands = PartParameterLength, true
			return
		}

		if replacement := literalReplacement(n, raw); replacement != nil {
			part.Kind, part.Replacement = PartParameterReplaceAll, replacement
			out.Expands = out.Expands || !part.Quoted

			return
		}

		if part.Quoted {
			switch {
			case raw == "${BASH_SOURCE[0]}" || raw == "${BASH_SOURCE[0]:-$0}":
				part.Kind = PartParameterBashSource
				return
			case raw == "${"+part.Text+"[@]}" && shellIdentifier(part.Text):
				part.Kind, out.Expands = PartParameterArrayAll, true
				return
			case raw == "${"+part.Text+"[@]:-}" && shellIdentifier(part.Text):
				part.Kind, out.Expands = PartParameterArrayAllDefaultEmpty, true
				return
			case raw == "${"+part.Text+"[*]}" && shellIdentifier(part.Text):
				part.Kind, part.SingleField = partParameterArrayJoin, true
				return
			case raw == "${"+part.Text+":-.}":
				part.Kind = PartParameterDefaultDot
				return
			case raw == "${"+part.Text+":-}":
				part.Kind = PartParameterDefaultEmpty
				return
			case raw == "${"+part.Text+`%$'\n'}`:
				part.Kind = PartParameterTrimNewline
				return
			}

			if suffix, ok := strings.CutPrefix(raw, "${0"); ok && suffix != "" && scriptDirectorySuffix(suffix) == suffix {
				part.Kind = PartParameterScriptDir
				return
			}
		}

		part.PlainParameter = raw == "$"+part.Text || raw == "${"+part.Text+"}"
		out.Expands = out.Expands || !part.PlainParameter
	} else {
		out.Expands = true
	}
}

// Project the shape, not the effect. The referenced parameter name may
// contain an arithmetic index until the hook walk proves a plain identifier.
func (p *declarationProjection) projectIndirectParameter(n *syntax.ParamExp, part *Part, depth int) bool {
	if !part.Quoted || !n.Excl || n.Param == nil || !shellIdentifier(n.Param.Value) || n.Index != nil || n.Slice != nil ||
		n.Repl != nil || n.Length || n.NestedParam != nil {
		return false
	}

	var fallback *Word

	if n.Exp != nil {
		if n.Exp.Op != syntax.DefaultUnsetOrNull {
			return false
		}

		fallback = p.word(n.Exp.Word, depth+1)
		if !sideEffectFreeWord(fallback) {
			return false
		}
	}

	part.Kind, part.Text, part.Operand = PartParameterIndirect, n.Param.Value, fallback

	return true
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
	if b.Op == syntax.Pipe || b.Op == syntax.PipeAll {
		if len(x) == 1 && len(y) == 1 {
			x[0].Commands = append(x[0].Commands, y[0].Commands...)
			x[0].Pipes = append(append(x[0].Pipes, b.Op.String()), y[0].Pipes...)
			x[0].Span = declarationSpan(s)

			x[0].Negated = x[0].Negated || s.Negated
			if s.Background {
				x[0].Background, x[0].Next = true, Background
			}

			return x
		}
	} else if len(x) > 0 {
		x[len(x)-1].Next = b.Op.String()
	}

	x = append(x, y...)
	if s.Background {
		for _, stmt := range x {
			stmt.Background = true
		}

		if len(x) > 0 {
			x[len(x)-1].Next = Background
		}
	}

	return x
}

func (p *declarationProjection) projectAssignments(c *Command, assignments []*syntax.Assign, depth int) {
	for _, a := range assignments {
		if a.Name == nil {
			continue
		}

		c.Assignments = append(c.Assignments, Assignment{Name: a.Name.Value, Value: p.assignmentWord(a, depth), Span: declarationSpan(a)})
	}
}

func (p *declarationProjection) assignmentWord(a *syntax.Assign, depth int) *Word {
	if a.Array != nil && a.Index == nil {
		value := p.arrayAssignmentWord(a.Array, depth)
		value.IndexedArray = !a.Append && !value.Writes
		value.ArrayAppend = a.Append && !value.Writes

		return value
	}

	value := p.word(a.Value, depth+1)
	if a.Append || a.Index != nil || a.Array != nil {
		p.omittedExecution = p.omittedExecution || a.Index != nil || a.Array != nil
		value.Expands = true
		value.Writes = a.Index != nil || a.Array != nil || value.Writes

		for i := range value.Parts {
			value.Parts[i].ArithmeticOperands = nil
		}
	}

	return value
}

func (p *declarationProjection) arrayAssignmentWord(arr *syntax.ArrayExpr, depth int) *Word {
	value := &Word{Span: declarationSpan(arr), Expands: true, DecimalElements: true, FixedArraySize: len(arr.Elems) + 1}
	for _, element := range arr.Elems {
		if !p.step(depth) || element.Index != nil || element.Value == nil {
			value.Writes, p.omittedExecution = true, true
			break
		}

		part := p.word(element.Value, depth+1)
		if len(arr.Elems) <= maxProjectedArrayItems {
			value.ArrayWords = append(value.ArrayWords, part)
		}

		literal, known := part.Literal()
		value.DecimalElements = value.DecimalElements && known && digits(literal)

		if !known && !fixedArrayElement(part) {
			value.FixedArraySize = 0
		}

		for i := range part.Parts {
			part.Parts[i].ArithmeticOperands = nil
		}

		value.Writes = value.Writes || part.Writes
		value.Parts = append(value.Parts, part.Parts...)
	}

	p.omittedExecution = p.omittedExecution || value.Writes

	return value
}

func fixedArrayElement(word *Word) bool {
	if word.Writes || word.Expands || len(word.Parts) == 0 {
		return false
	}

	for _, part := range word.Parts {
		if part.Kind != PartLiteral && (part.Kind != PartParameter || !part.Quoted || !shellIdentifier(part.Text)) {
			return false
		}
	}

	return true
}

func (p *declarationProjection) projectConditional(c *Command, n *syntax.IfClause, depth int) {
	c.ExclusiveBranches = true
	c.Prelude = p.list(n.Cond, depth+1)

	other := &File{}

	switch {
	case n.Else == nil:
	case !n.Else.ThenPos.IsValid():
		other = p.list(n.Else.Then, depth+1)
	default:
		other = &File{Statements: p.statement(&syntax.Stmt{Position: n.Else.Pos(), Cmd: n.Else}, depth+1)}
	}

	c.Alternatives = []*File{p.list(n.Then, depth+1), other}
}
