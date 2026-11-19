package shellsyntax

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	maxForArgumentItems = 8
)

func (p *declarationProjection) projectForList(c *Command, loop *syntax.WordIter, depth int) {
	if len(loop.Items) == 1 {
		c.ForArraySlice = p.forArraySlice(loop.Items[0], depth+1)
		if c.ForArraySlice != nil {
			c.ForArguments = loop.Name.Value
			return
		}
	}

	c.ForFileGlob = p.forFileGlob(loop, depth)
	if c.ForFileGlob == nil {
		c.ForArguments = p.forArguments(c, loop, depth)
	}
}

func (p *declarationProjection) forArguments(c *Command, loop *syntax.WordIter, depth int) string {
	var (
		expansions []*Word
		list       []*Word
	)

	for _, item := range loop.Items {
		word := p.word(item, depth+1)

		hasSubstitution, safe := readOnlyExpansion(word, true)
		if !safe {
			return ""
		}

		if len(loop.Items) <= maxForArgumentItems {
			list = append(list, word)
		}

		if hasSubstitution {
			expansions = append(expansions, word)
		}

		if len(loop.Items) == 1 && len(word.Parts) == 1 &&
			word.Parts[0].Kind == PartParameterArrayAll && word.Parts[0].Quoted {
			c.ForArray = word.Parts[0].Text
		}
	}

	c.ExpansionWords = expansions

	c.ForPositional = p.positionalIteration(loop)
	if !c.ForPositional && c.ForArray == "" {
		c.ForWords = list
	}

	return loop.Name.Value
}

func (p *declarationProjection) forArraySlice(item *syntax.Word, depth int) *ForArraySlice {
	if len(item.Parts) != 1 {
		return nil
	}

	quoted, ok := item.Parts[0].(*syntax.DblQuoted)
	if !ok || quoted.Dollar || len(quoted.Parts) != 1 {
		return nil
	}

	param, ok := quoted.Parts[0].(*syntax.ParamExp)
	if !ok || param.Param == nil || !shellIdentifier(param.Param.Value) || param.Excl || param.Length ||
		param.Repl != nil || param.Exp != nil || param.NestedParam != nil || param.Slice == nil || param.Slice.Length != nil {
		return nil
	}

	index, ok := param.Index.(*syntax.Word)
	if !ok || p.text[index.Pos().Offset():index.End().Offset()] != "@" {
		return nil
	}

	offset := p.simpleArithmeticIndex(param.Slice.Offset, depth)
	if offset == nil || offset.Inner != nil {
		return nil
	}

	return &ForArraySlice{Name: param.Param.Value, OffsetVariable: offset.Name}
}

func (p *declarationProjection) positionalIteration(loop *syntax.WordIter) bool {
	if !loop.InPos.IsValid() {
		return true
	}

	if len(loop.Items) != 1 {
		return false
	}

	item := loop.Items[0]

	raw := p.text[item.Pos().Offset():item.End().Offset()]

	return raw == `"$@"` || raw == `"${@}"`
}

func (p *declarationProjection) forFileGlob(loop *syntax.WordIter, depth int) *ForFileGlob {
	if len(loop.Items) != 1 {
		return nil
	}

	word := p.word(loop.Items[0], depth+1)
	if len(word.Parts) != 2 || word.Writes {
		return nil
	}

	root, suffix := word.Parts[0], word.Parts[1]
	if root.Kind != PartParameter || !root.Quoted || suffix.Kind != PartLiteral || suffix.Quoted {
		return nil
	}

	parameter := p.text[root.Span.Start:root.Span.End]
	if parameter != "$"+root.Text && parameter != "${"+root.Text+"}" {
		return nil
	}

	raw := p.text[suffix.Span.Start:suffix.Span.End]
	if raw != suffix.Text || !strings.HasPrefix(raw, "/") || !strings.HasSuffix(raw, "/*") {
		return nil
	}

	dir := strings.TrimSuffix(raw[1:], "/*")
	if dir == "" || dir == "." || strings.HasPrefix(dir, "/") || dir == ".." || strings.HasPrefix(dir, "../") || path.Clean(dir) != dir || strings.ContainsAny(dir, "*?[]{}~") {
		return nil
	}

	return &ForFileGlob{Name: loop.Name.Value, Root: root.Text, Directory: dir}
}
