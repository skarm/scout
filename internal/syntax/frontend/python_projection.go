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
		pyKindModule: {
			kind: Module,
			fields: []pythonProjectedField{{
				kind:   Body,
				form:   pythonChildren,
				source: "",
			}},
		},
		pyKindBlock: {
			kind: Module,
			fields: []pythonProjectedField{{
				kind:   Body,
				form:   pythonChildren,
				source: "",
			}},
		},
		pyKindIdentifier: {
			kind:   Name,
			fields: []pythonProjectedField{{kind: ID, form: pythonText, source: ""}},
		},
		pyKindAttribute: {
			kind: Attribute,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonChild,
				source: pyFieldObject,
			}, {
				kind:   Attr,
				form:   pythonText,
				source: pyFieldAttribute,
			}},
		},
		pyKindSubscript: {kind: Subscript, build: (*pythonNormalizer).subscriptNode},
		pyKindAugmentedAssignment: {
			kind: AugAssign,
			fields: []pythonProjectedField{{
				kind:   Target,
				form:   pythonChild,
				source: pyFieldLeft,
			}, {
				kind:   FieldValue,
				form:   pythonChild,
				source: pyFieldRight,
			}},
		},
		pyKindNamedExpression: {
			kind: NamedExpr,
			fields: []pythonProjectedField{{
				kind:   Target,
				form:   pythonChild,
				source: pyFieldName,
			}, {
				kind:   FieldValue,
				form:   pythonChild,
				source: pyFieldValue,
			}},
		},
		pyKindInterpolation: {
			kind: formattedValue,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonChild,
				source: pyFieldExpression,
			}, {
				kind:   formatSpec,
				form:   pythonChild,
				source: pyFieldFormatSpecifier,
			}},
		},
		pyKindList: {
			kind: List,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		pyKindListPattern: {
			kind: List,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		pyKindTuple: {
			kind: Tuple,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		pyKindTuplePattern: {
			kind: Tuple,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		pyKindPatternList: {
			kind: Tuple,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		pyKindExpressionList: {
			kind: Tuple,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		pyKindSet: {
			kind: Set,
			fields: []pythonProjectedField{{
				kind:   Elts,
				form:   pythonChildren,
				source: "",
			}},
		},
		pyKindBinaryOperator: {
			kind: BinOp,
			fields: []pythonProjectedField{{
				kind:   Left,
				form:   pythonChild,
				source: pyFieldLeft,
			}, {
				kind:   Right,
				form:   pythonChild,
				source: pyFieldRight,
			}, {
				kind:   Op,
				form:   pythonText,
				source: pyFieldOperator,
			}},
		},
		pyKindComparisonOperator: {kind: Compare, build: (*pythonNormalizer).comparisonNode},
		pyKindListSplat: {
			kind: Starred,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonFirst,
				source: "",
			}},
		},
		pyKindListSplatPattern: {
			kind: Starred,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonFirst,
				source: "",
			}},
		},
		pyKindDictionarySplat: {
			kind: Starred,
			fields: []pythonProjectedField{{
				kind:   FieldValue,
				form:   pythonFirst,
				source: "",
			}},
		},
		pyKindReturnStatement: {
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
		pyKindRaiseStatement: {
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
		pyKindAssertStatement: {
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
		pyKindDeleteStatement: {
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
		pyKindPassStatement:           {kind: Pass},
		pyKindBreakStatement:          {kind: breakNode},
		pyKindContinueStatement:       {kind: Continue},
		pyKindExpressionStatement:     {kind: Expr, build: (*pythonNormalizer).expressionStatement},
		pyKindImportStatement:         {kind: Import, build: (*pythonNormalizer).importNode},
		pyKindImportFromStatement:     {kind: ImportFrom, build: (*pythonNormalizer).importNode},
		pyKindFutureImportStatement:   {kind: ImportFrom, build: (*pythonNormalizer).importNode},
		pyKindCall:                    {kind: Call, build: (*pythonNormalizer).callNode},
		pyKindAssignment:              {kind: Assign, build: (*pythonNormalizer).assignmentNode},
		pyKindParenthesizedExpression: {build: (*pythonNormalizer).unwrapNode},
		pyKindAsPatternTarget:         {build: (*pythonNormalizer).unwrapNode},
		pyKindType:                    {build: (*pythonNormalizer).typeNode},
		pyKindInteger:                 {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		pyKindFloat:                   {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		pyKindTrue:                    {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		pyKindFalse:                   {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		pyKindNone:                    {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		pyKindEllipsis:                {kind: Constant, build: (*pythonNormalizer).nodeInteger},
		pyKindString:                  {build: (*pythonNormalizer).stringNode},
		pyKindConcatenatedString:      {build: (*pythonNormalizer).concatenatedStringNode},
		pyKindDictionary:              {kind: Dict, build: (*pythonNormalizer).dictionaryNode},
		pyKindListComprehension:       {kind: ListComp, build: (*pythonNormalizer).comprehensionNode},
		pyKindSetComprehension:        {kind: SetComp, build: (*pythonNormalizer).comprehensionNode},
		pyKindDictionaryComprehension: {kind: DictComp, build: (*pythonNormalizer).comprehensionNode},
		pyKindGeneratorExpression:     {kind: GeneratorExp, build: (*pythonNormalizer).comprehensionNode},
		pyKindBooleanOperator:         {kind: BoolOp, build: (*pythonNormalizer).booleanNode},
		pyKindConditionalExpression:   {kind: IfExp, build: (*pythonNormalizer).conditionalNode},
		pyKindUnaryOperator:           {kind: UnaryOp, build: (*pythonNormalizer).unaryNode},
		pyKindNotOperator:             {kind: UnaryOp, build: (*pythonNormalizer).unaryNode},
		pyKindFunctionDefinition:      {kind: FunctionDef, build: (*pythonNormalizer).nodeFunctionDefinition},
		pyKindClassDefinition:         {kind: ClassDef, build: (*pythonNormalizer).nodeFunctionDefinition},
		pyKindDecoratedDefinition:     {build: (*pythonNormalizer).decoratedNode},
		pyKindLambda:                  {kind: Lambda, build: (*pythonNormalizer).lambdaNode},
		pyKindIfStatement:             {kind: If, build: (*pythonNormalizer).ifNode},
		pyKindElifClause:              {kind: If, build: (*pythonNormalizer).ifNode},
		pyKindForStatement:            {kind: For, build: (*pythonNormalizer).loopNode},
		pyKindWhileStatement:          {kind: While, build: (*pythonNormalizer).loopNode},
		pyKindWithStatement:           {kind: With, build: (*pythonNormalizer).withNode},
		pyKindTryStatement:            {kind: Try, build: (*pythonNormalizer).tryNode},
		pyKindGlobalStatement:         {kind: Global, build: (*pythonNormalizer).nameDeclarationNode},
		pyKindNonlocalStatement:       {kind: Nonlocal, build: (*pythonNormalizer).nameDeclarationNode},
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
