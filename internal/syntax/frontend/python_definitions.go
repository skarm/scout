package frontend

type pythonParameters struct {
	args, defaults, kwonly, kwdefaults, posonly []*Node
	keyword                                     bool
}

func (b *pythonNormalizer) nodeFunctionDefinition(n *pythonSyntax, depth int, typ NodeKind) *Node {
	out := b.make(n, typ)
	b.set(out, FieldName, StringValue(b.textOf(n.field("name"))))
	b.set(out, Body, nodesValue(b.list(n.field("body"), depth)))
	b.set(out, DecoratorList, nodesValue([]*Node{}))

	if typ == FunctionDef {
		b.set(out, Args, childValue(b.parameters(n.field("parameters"), depth+1)))
		b.set(out, Returns, childValue(b.node(n.field("return_type"), depth+1)))
	} else {
		var (
			bases    []*Node
			keywords []*Node
		)

		for _, x := range n.field("superclasses").named() {
			if x.Kind == "keyword_argument" || x.Kind == "dictionary_splat" {
				k := b.make(x, Keyword)
				if x.Kind == "keyword_argument" {
					b.set(k, FieldArg, StringValue(b.textOf(x.field("name"))))
					b.set(k, FieldValue, childValue(b.node(x.field("value"), depth+1)))
				} else {
					b.set(k, FieldArg, NullValue())
					b.set(k, FieldValue, childValue(b.node(x.first(), depth+1)))
				}

				keywords = append(keywords, k)
			} else {
				bases = append(bases, b.node(x, depth+1))
			}
		}

		b.set(out, Bases, nodesValue(bases))
		b.set(out, Keywords, nodesValue(keywords))
	}
	// PEP-695 type parameters require scope semantics not implemented here.
	// Retain expressions for independent observations; never silently omit them.
	if n.field("type_parameters") != nil {
		b.partial = true
		b.set(out, TypeParams, nodesValue(b.list(n.field("type_parameters"), depth+1)))
	}

	return out
}

func (b *pythonNormalizer) parameters(n *pythonSyntax, depth int) *Node {
	if n == nil {
		return nil
	}

	out := b.make(n, Arguments)

	params := pythonParameters{
		args:       []*Node{},
		defaults:   []*Node{},
		kwonly:     []*Node{},
		kwdefaults: []*Node{},
		posonly:    []*Node{},
	}
	for _, x := range n.named() {
		params.append(b, out, x, depth)
	}

	b.set(out, Args, nodesValue(params.args))
	b.set(out, Posonlyargs, nodesValue(params.posonly))
	b.set(out, KWOnlyargs, nodesValue(params.kwonly))
	b.set(out, Defaults, nodesValue(params.defaults))
	b.set(out, KWDefaults, nodesValue(params.kwdefaults))

	return out
}

func (b *pythonNormalizer) parameterName(item *pythonSyntax) string {
	switch item.Kind {
	case "default_parameter", "typed_default_parameter":
		return b.textOf(item.field("name"))
	case "list_splat_pattern", "dictionary_splat_pattern":
		return b.textOf(item.first())
	default:
		return b.textOf(item)
	}
}

func (p *pythonParameters) append(b *pythonNormalizer, out *Node, x *pythonSyntax, depth int) {
	switch x.Kind {
	case "positional_separator":
		p.posonly, p.args = p.args, []*Node{}
		return
	case "keyword_separator":
		p.keyword = true
		return
	}

	item := x
	if item.Kind == "typed_parameter" {
		item = item.first()
	}

	if item == nil {
		return
	}

	a := b.make(x, Arg)
	b.set(a, FieldArg, StringValue(b.parameterName(item)))
	b.set(a, Annotation, childValue(b.node(x.field("type"), depth+1)))

	switch item.Kind {
	case "list_splat_pattern":
		b.set(out, Vararg, childValue(a))

		p.keyword = true
	case "dictionary_splat_pattern":
		b.set(out, Kwarg, childValue(a))
	case "identifier", "default_parameter", "typed_default_parameter":
		p.regular(a, b.node(item.field("value"), depth+1))
	default:
		b.partial = true
	}
}

func (p *pythonParameters) regular(arg, def *Node) {
	if p.keyword {
		p.kwonly = append(p.kwonly, arg)
		p.kwdefaults = append(p.kwdefaults, def)

		return
	}

	p.args = append(p.args, arg)
	if def != nil {
		p.defaults = append(p.defaults, def)
	}
}
