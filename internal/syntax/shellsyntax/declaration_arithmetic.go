package shellsyntax

import "mvdan.cc/sh/v3/syntax"

func plainIndexedParameter(n *syntax.ParamExp) bool {
	return n.Param != nil && shellIdentifier(n.Param.Value) && !n.Excl && !n.Length &&
		n.Exp == nil && n.Repl == nil && n.Slice == nil && n.NestedParam == nil
}

func arithmeticUpdate(expr syntax.ArithmExpr) string {
	update, ok := expr.(*syntax.UnaryArithm)
	if !ok || (update.Op != syntax.Inc && update.Op != syntax.Dec) {
		return ""
	}

	target, ok := update.X.(*syntax.Word)
	if !ok || len(target.Parts) != 1 {
		return ""
	}

	name, ok := target.Parts[0].(*syntax.Lit)
	if !ok || !shellIdentifier(name.Value) {
		return ""
	}

	return name.Value
}

func (p *declarationProjection) simpleArithmeticIndex(expr syntax.ArithmExpr, depth int) *ArithmeticIndex {
	word, ok := expr.(*syntax.Word)
	if !ok || len(word.Parts) != 1 || !p.step(depth) {
		return nil
	}

	switch part := word.Parts[0].(type) {
	case *syntax.Lit:
		if digits(part.Value) {
			return &ArithmeticIndex{Decimal: true}
		}

		if shellIdentifier(part.Value) {
			return &ArithmeticIndex{Name: part.Value}
		}
	case *syntax.ParamExp:
		if plainIndexedParameter(part) {
			if part.Index == nil {
				return &ArithmeticIndex{Name: part.Param.Value}
			}

			if inner := p.simpleArithmeticIndex(part.Index, depth+1); inner != nil {
				return &ArithmeticIndex{Name: part.Param.Value, Inner: inner}
			}
		}
	}

	return nil
}

func (p *declarationProjection) decimalGuard(expr syntax.TestExpr, depth int) *DecimalGuard {
	negated := false
	if unary, ok := expr.(*syntax.UnaryTest); ok && unary.Op == syntax.TsNot {
		expr, negated = unary.X, true
	}

	match, ok := expr.(*syntax.BinaryTest)
	if !ok || match.Op != syntax.TsReMatch {
		return nil
	}

	input, ok := match.X.(*syntax.Word)
	if !ok {
		return nil
	}

	pattern := p.text[match.Y.Pos().Offset():match.Y.End().Offset()]
	requiresC := pattern == "^[0-9]+$" || pattern == "^-?[0-9]+$"

	if !requiresC && pattern != "^[0123456789]+$" && pattern != "^-?[0123456789]+$" {
		return nil
	}

	if raw := p.text[input.Pos().Offset():input.End().Offset()]; raw == "${1:-}" || raw == `"${1:-}"` {
		return &DecimalGuard{Name: "1", RequiresC: requiresC, MatchOnFailure: negated}
	}

	word := p.word(input, depth)
	if word.Expands || word.Writes || len(word.Parts) != 1 {
		return nil
	}

	part := word.Parts[0]
	if part.Kind != PartParameter || !shellIdentifier(part.Text) {
		return nil
	}

	return &DecimalGuard{Name: part.Text, RequiresC: requiresC, MatchOnFailure: negated}
}

// arithmeticPredicate projects only scalar expressions without assignments,
// subscript evaluation, or substitutions. The tracer checks operand values.
func (p *declarationProjection) arithmeticPredicate(c *Command, expr syntax.ArithmExpr, depth int) bool {
	if !p.step(depth) {
		return false
	}

	switch n := expr.(type) {
	case *syntax.BinaryArithm:
		switch n.Op {
		case syntax.Add, syntax.Sub, syntax.Mul, syntax.Quo, syntax.Rem, syntax.Lss, syntax.Leq, syntax.Gtr, syntax.Geq, syntax.Eql, syntax.Neq, syntax.AndArit, syntax.OrArit:
			return p.arithmeticPredicate(c, n.X, depth+1) && p.arithmeticPredicate(c, n.Y, depth+1)
		case syntax.TernQuest:
			arms, ok := n.Y.(*syntax.BinaryArithm)

			return ok && arms.Op == syntax.TernColon && p.arithmeticPredicate(c, n.X, depth+1) &&
				p.arithmeticPredicate(c, arms.X, depth+1) && p.arithmeticPredicate(c, arms.Y, depth+1)
		}
	case *syntax.UnaryArithm:
		switch n.Op {
		case syntax.Plus, syntax.Minus, syntax.Not:
			return p.arithmeticPredicate(c, n.X, depth+1)
		}
	case *syntax.ParenArithm:
		return p.arithmeticPredicate(c, n.X, depth+1)
	case *syntax.Word:
		return p.arithmeticOperand(c, n, depth+1)
	}

	return false
}

func (p *declarationProjection) arithmeticOperand(c *Command, n *syntax.Word, depth int) bool {
	if name := p.decimalArithmeticDefault(n); name != "" {
		c.NumericTest = append(c.NumericTest, &Word{
			Span: declarationSpan(n), Parts: []Part{{Kind: PartParameter, Text: name}},
		})

		return true
	}

	value := p.word(n, depth)
	if text, literal := value.Literal(); literal && digits(text) {
		return true
	}

	if len(value.Parts) == 1 && !value.Writes && value.Parts[0].Kind == PartParameterLength &&
		p.text[value.Span.Start:value.Span.End] == "${#"+value.Parts[0].Text+"[@]}" {
		c.NumericTest = append(c.NumericTest, value)
		return true
	}

	if !value.Writes && len(value.Parts) == 2 && value.Parts[0].Kind == PartLiteral && value.Parts[0].Text == "10#" &&
		value.Parts[1].Kind == PartSubstitution && value.Parts[1].Tree != nil {
		c.NumericTest = append(c.NumericTest, value)
		return true
	}

	if value.Expands || value.Writes || len(value.Parts) != 1 {
		return false
	}

	part := &value.Parts[0]
	if part.Kind == PartSubstitution && part.Tree != nil {
		c.NumericTest = append(c.NumericTest, value)
		return true
	}

	if (part.Kind != PartLiteral && part.Kind != PartParameter) || !shellIdentifier(part.Text) {
		return false
	}

	if part.Kind == PartLiteral {
		part.Kind = PartArithmeticVariable
	}

	c.NumericTest = append(c.NumericTest, value)

	return true
}

func (p *declarationProjection) decimalArithmeticDefault(word *syntax.Word) string {
	if len(word.Parts) != 1 {
		return ""
	}

	param, ok := word.Parts[0].(*syntax.ParamExp)
	if !ok || param.Param == nil || !shellIdentifier(param.Param.Value) || param.Excl || param.Length || param.Index != nil ||
		param.Repl != nil || param.Slice != nil || param.NestedParam != nil || param.Exp == nil || param.Exp.Op != syntax.DefaultUnsetOrNull {
		return ""
	}

	fallback := param.Exp.Word
	if fallback == nil || !digits(p.text[fallback.Pos().Offset():fallback.End().Offset()]) {
		return ""
	}

	return param.Param.Value
}
