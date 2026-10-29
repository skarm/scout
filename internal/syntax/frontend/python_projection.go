package frontend

//nolint:gochecknoglobals // Read-only IR schema and Python grammar tables are shared by scans.
var pythonProjections map[string]pythonProjection

// The registry is the single CST-kind dispatch. Simple projections describe
// field shape; builders own forms requiring ordering, aliases or syntax tests.
type pythonProjection struct {
	kind   NodeKind
	fields []pythonProjectedField
	build  func(*pythonNormalizer, *pythonSyntax, int, NodeKind) *Node
}

type pythonProjectedField struct {
	kind   FieldKind
	form   pythonFieldForm
	source string // Empty selects the whole CST node.
}

type pythonFieldForm uint8

const (
	pythonText pythonFieldForm = iota
	pythonChild
	pythonFirst
	pythonChildren
)

//nolint:gochecknoinits // Registered methods recurse through this table; a variable initializer creates an initialization cycle.
func init() {
	pythonProjections = map[string]pythonProjection{
		"module": {
			kind: Module,
			fields: []pythonProjectedField{{
				kind:   Body,
				form:   pythonChildren,
				source: "",
			}},
		},
		"block": {
			kind: Module,
			fields: []pythonProjectedField{{
				kind:   Body,
				form:   pythonChildren,
				source: "",
			}},
		},
		"identifier": {
			kind:   Name,
			fields: []pythonProjectedField{{kind: ID, form: pythonText, source: ""}},
		},
		"attribute": {
			kind: Attribute,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonChild,
				source: "object",
			}, {
				kind:   Attr,
				form:   pythonText,
				source: "attribute",
			}},
		},
		"subscript": {
			kind: Subscript,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonChild,
				source: "value",
			}, {
				kind:   Slice,
				form:   pythonChild,
				source: "subscript",
			}},
		},
		"augmented_assignment": {
			kind: AugAssign,
			fields: []pythonProjectedField{{
				kind:   Target,
				form:   pythonChild,
				source: "left",
			}, {
				kind:   FieldValue,
				form:   pythonChild,
				source: "right",
			}},
		},
		"named_expression": {
			kind: NamedExpr,
			fields: []pythonProjectedField{{
				kind:   Target,
				form:   pythonChild,
				source: "name",
			}, {
				kind:   FieldValue,
				form:   pythonChild,
				source: "value",
			}},
		},
		"interpolation": {
			kind: formattedValue,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonChild,
				source: "expression",
			}, {
				kind:   formatSpec,
				form:   pythonChild,
				source: "format_specifier",
			}},
		},
		"list": {
			kind: List,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		"list_pattern": {
			kind: List,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		"tuple": {
			kind: Tuple,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		"tuple_pattern": {
			kind: Tuple,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		"pattern_list": {
			kind: Tuple,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		"expression_list": {
			kind: Tuple,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		"set": {
			kind: Set,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		"binary_operator": {
			kind: BinOp,
			fields: []pythonProjectedField{{
				kind:   Left,
				form:   pythonChild,
				source: "left",
			}, {
				kind:   Right,
				form:   pythonChild,
				source: "right",
			}},
		},
		"list_splat": {
			kind: Starred,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonFirst,
				source: "",
			}},
		},
		"dictionary_splat": {
			kind: Starred,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonFirst,
				source: "",
			}},
		},
		"return_statement": {
			kind: Return,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonFirst,
				source: "",
			}, {
				kind:   Targets,
				form:   pythonChildren,
				source: "",
			}},
		},
		"raise_statement": {
			kind: raise,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonFirst,
				source: "",
			}, {
				kind:   Targets,
				form:   pythonChildren,
				source: "",
			}},
		},
		"assert_statement": {
			kind: assert,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonFirst,
				source: "",
			}, {
				kind:   Targets,
				form:   pythonChildren,
				source: "",
			}},
		},
		"delete_statement": {
			kind: Delete,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonFirst,
				source: "",
			}, {
				kind:   Targets,
				form:   pythonChildren,
				source: "",
			}},
		},
		"pass_statement":           {kind: pass},
		"break_statement":          {kind: breakNode},
		"continue_statement":       {kind: continueNode},
		"expression_statement":     {kind: Expr, build: (*pythonNormalizer).expressionStatement},
		"import_statement":         {kind: Import, build: (*pythonNormalizer).importNode},
		"import_from_statement":    {kind: ImportFrom, build: (*pythonNormalizer).importNode},
		"future_import_statement":  {kind: ImportFrom, build: (*pythonNormalizer).importNode},
		"call":                     {kind: Call, build: (*pythonNormalizer).callNode},
		"assignment":               {kind: Assign, build: (*pythonNormalizer).assignmentNode},
		"parenthesized_expression": {build: (*pythonNormalizer).unwrapNode},
		"as_pattern_target":        {build: (*pythonNormalizer).unwrapNode},
		"type":                     {build: (*pythonNormalizer).typeNode},
		"integer":                  {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		"float":                    {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		"true":                     {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		"false":                    {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		"none":                     {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		"ellipsis":                 {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		"string":                   {build: (*pythonNormalizer).stringNode},
		"concatenated_string":      {build: (*pythonNormalizer).concatenatedStringNode},
		"dictionary":               {kind: Dict, build: (*pythonNormalizer).dictionaryNode},
		"list_comprehension":       {kind: ListComp, build: (*pythonNormalizer).comprehensionNode},
		"set_comprehension":        {kind: SetComp, build: (*pythonNormalizer).comprehensionNode},
		"dictionary_comprehension": {kind: DictComp, build: (*pythonNormalizer).comprehensionNode},
		"generator_expression":     {kind: GeneratorExp, build: (*pythonNormalizer).comprehensionNode},
		"boolean_operator":         {kind: BoolOp, build: (*pythonNormalizer).booleanNode},
		"conditional_expression":   {kind: IfExp, build: (*pythonNormalizer).conditionalNode},
		"unary_operator":           {kind: UnaryOp, build: (*pythonNormalizer).unaryNode},
		"not_operator":             {kind: UnaryOp, build: (*pythonNormalizer).unaryNode},
		"function_definition":      {kind: FunctionDef, build: (*pythonNormalizer).nodeFunctionDefinition},
		"class_definition":         {kind: ClassDef, build: (*pythonNormalizer).nodeFunctionDefinition},
		"decorated_definition":     {build: (*pythonNormalizer).decoratedNode},
		"lambda":                   {kind: Lambda, build: (*pythonNormalizer).lambdaNode},
		"if_statement":             {kind: If, build: (*pythonNormalizer).ifNode},
		"elif_clause":              {kind: If, build: (*pythonNormalizer).ifNode},
		"for_statement":            {kind: For, build: (*pythonNormalizer).loopNode},
		"while_statement":          {kind: While, build: (*pythonNormalizer).loopNode},
		"with_statement":           {kind: With, build: (*pythonNormalizer).withNode},
		"global_statement":         {kind: Global, build: (*pythonNormalizer).nameDeclarationNode},
		"nonlocal_statement":       {kind: Nonlocal, build: (*pythonNormalizer).nameDeclarationNode},
	}
}

func (b *pythonNormalizer) projectFields(n *pythonSyntax, depth int, projection pythonProjection) *Node {
	out := b.make(n, projection.kind)
	for _, field := range projection.fields {
		input := n
		if field.source != "" {
			input = n.field(field.source)
		}

		var value Value

		switch field.form {
		case pythonText:
			value = StringValue(b.textOf(input))
		case pythonChild:
			value = childValue(b.node(input, depth+1))
		case pythonFirst:
			value = childValue(b.node(input.first(), depth+1))
		case pythonChildren:
			value = nodesValue(b.list(input, depth))
		}

		b.set(out, field.kind, value)
	}

	return out
}

func (b *pythonNormalizer) unwrapNode(n *pythonSyntax, depth int, _ NodeKind) *Node {
	return b.node(n.first(), depth+1)
}
