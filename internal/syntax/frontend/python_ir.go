package frontend

import (
	"context"
)

// Named child fields in the Python CST.
const (
	pyFieldAlias           = "alias"
	pyFieldAlternative     = "alternative"
	pyFieldArgument        = "argument"
	pyFieldArguments       = "arguments"
	pyFieldAttribute       = "attribute"
	pyFieldBody            = "body"
	pyFieldCondition       = "condition"
	pyFieldConsequence     = "consequence"
	pyFieldDefinition      = "definition"
	pyFieldExpression      = "expression"
	pyFieldFormatSpecifier = "format_specifier"
	pyFieldFunction        = "function"
	pyFieldKey             = "key"
	pyFieldLeft            = "left"
	pyFieldModuleName      = "module_name"
	pyFieldName            = "name"
	pyFieldObject          = "object"
	pyFieldOperator        = "operator"
	pyFieldOperators       = "operators"
	pyFieldParameters      = "parameters"
	pyFieldReturnType      = "return_type"
	pyFieldRight           = "right"
	pyFieldSubscript       = "subscript"
	pyFieldSuperclasses    = "superclasses"
	pyFieldType            = "type"
	pyFieldTypeParameters  = "type_parameters"
	pyFieldValue           = "value"
)

// Internal Tree-sitter Python node kinds.
const (
	pyKindAliasedImport           = "aliased_import"
	pyKindAsPattern               = "as_pattern"
	pyKindAsPatternTarget         = "as_pattern_target"
	pyKindAssertStatement         = "assert_statement"
	pyKindAssignment              = "assignment"
	pyKindAsterisk                = "*"
	pyKindAttribute               = "attribute"
	pyKindAugmentedAssignment     = "augmented_assignment"
	pyKindBinaryOperator          = "binary_operator"
	pyKindBlock                   = "block"
	pyKindBooleanOperator         = "boolean_operator"
	pyKindBreakStatement          = "break_statement"
	pyKindCall                    = "call"
	pyKindClassDefinition         = "class_definition"
	pyKindComment                 = "comment"
	pyKindComparisonOperator      = "comparison_operator"
	pyKindConcatenatedString      = "concatenated_string"
	pyKindConditionalExpression   = "conditional_expression"
	pyKindContinueStatement       = "continue_statement"
	pyKindDecoratedDefinition     = "decorated_definition"
	pyKindDecorator               = "decorator"
	pyKindDefaultParameter        = "default_parameter"
	pyKindDeleteStatement         = "delete_statement"
	pyKindDictionary              = "dictionary"
	pyKindDictionaryComprehension = "dictionary_comprehension"
	pyKindDictionarySplat         = "dictionary_splat"
	pyKindDictionarySplatPattern  = "dictionary_splat_pattern"
	pyKindDottedName              = "dotted_name"
	pyKindElifClause              = "elif_clause"
	pyKindEllipsis                = "ellipsis"
	pyKindElseClause              = "else_clause"
	pyKindExceptClause            = "except_clause"
	pyKindExpressionList          = "expression_list"
	pyKindExpressionStatement     = "expression_statement"
	pyKindFalse                   = "false"
	pyKindFinallyClause           = "finally_clause"
	pyKindFloat                   = "float"
	pyKindForInClause             = "for_in_clause"
	pyKindForStatement            = "for_statement"
	pyKindFunctionDefinition      = "function_definition"
	pyKindFutureImportStatement   = "future_import_statement"
	pyKindGeneratorExpression     = "generator_expression"
	pyKindGlobalStatement         = "global_statement"
	pyKindIdentifier              = "identifier"
	pyKindIfClause                = "if_clause"
	pyKindIfStatement             = "if_statement"
	pyKindImportFromStatement     = "import_from_statement"
	pyKindImportStatement         = "import_statement"
	pyKindInteger                 = "integer"
	pyKindInterpolation           = "interpolation"
	pyKindKeywordArgument         = "keyword_argument"
	pyKindKeywordSeparator        = "keyword_separator"
	pyKindLambda                  = "lambda"
	pyKindList                    = "list"
	pyKindListComprehension       = "list_comprehension"
	pyKindListPattern             = "list_pattern"
	pyKindListSplat               = "list_splat"
	pyKindListSplatPattern        = "list_splat_pattern"
	pyKindMatchStatement          = "match_statement"
	pyKindModule                  = "module"
	pyKindNamedExpression         = "named_expression"
	pyKindNone                    = "none"
	pyKindNonlocalStatement       = "nonlocal_statement"
	pyKindNotOperator             = "not_operator"
	pyKindPair                    = "pair"
	pyKindParenthesizedExpression = "parenthesized_expression"
	pyKindPassStatement           = "pass_statement"
	pyKindPatternList             = "pattern_list"
	pyKindPositionalSeparator     = "positional_separator"
	pyKindRaiseStatement          = "raise_statement"
	pyKindReturnStatement         = "return_statement"
	pyKindSet                     = "set"
	pyKindSetComprehension        = "set_comprehension"
	pyKindString                  = "string"
	pyKindSubscript               = "subscript"
	pyKindTrue                    = "true"
	pyKindTryStatement            = "try_statement"
	pyKindTuple                   = "tuple"
	pyKindTuplePattern            = "tuple_pattern"
	pyKindType                    = "type"
	pyKindTypedDefaultParameter   = "typed_default_parameter"
	pyKindTypedParameter          = "typed_parameter"
	pyKindUnaryOperator           = "unary_operator"
	pyKindWhileStatement          = "while_statement"
	pyKindWildcardImport          = "wildcard_import"
	pyKindWithClause              = "with_clause"
	pyKindWithStatement           = "with_statement"
)

// pythonSyntax is a bounded, byte-addressed copy of Tree-sitter's CST. This is
// only a normalizer input, NOT a hand-written parser or a CPython AST claim.
type pythonSyntax struct {
	Kind, Field string
	Start, End  int
	Named       bool
	Children    []*pythonSyntax
}

type pythonNormalizer struct {
	ctx            context.Context
	text           string
	nodes, encoded int
	partial        bool
	err            error
}

func normalizePython(ctx context.Context, text string, root *pythonSyntax) (*Node, error) {
	n := &pythonNormalizer{ctx: ctx, text: text}

	if root == nil || root.Kind != pyKindModule {
		return nil, &Failure{Category: "invalid_tree"}
	}

	ast := n.node(root, 0)
	if n.err != nil {
		return nil, n.err
	}

	if n.partial {
		return ast, &Failure{Category: "unsupported_projection"}
	}

	return ast, nil
}

func (n *pythonSyntax) field(key string) *pythonSyntax {
	if n != nil {
		for _, x := range n.Children {
			if x.Field == key {
				return x
			}
		}
	}

	return nil
}

func (n *pythonSyntax) named() []*pythonSyntax {
	var out []*pythonSyntax

	if n != nil {
		for _, x := range n.Children {
			if x.Named && x.Kind != pyKindComment {
				out = append(out, x)
			}
		}
	}

	return out
}

func (n *pythonSyntax) first() *pythonSyntax {
	for _, x := range n.named() {
		return x
	}

	return nil
}

func (b *pythonNormalizer) textOf(n *pythonSyntax) string {
	if n == nil || n.Start < 0 || n.End < n.Start || n.End > len(b.text) {
		return ""
	}

	return b.text[n.Start:n.End]
}

func (b *pythonNormalizer) make(n *pythonSyntax, typ NodeKind) *Node {
	b.nodes++
	if b.nodes > maxNodes {
		b.err = &Failure{Category: "limit"}
	}

	return newNode(typ, n.Start, n.End)
}

func (b *pythonNormalizer) set(n *Node, key FieldKind, value Value) {
	if b.err != nil || n == nil {
		return
	}

	size := value.encodedSize()

	b.encoded += size
	if b.encoded > maxOutput {
		b.err = &Failure{Category: "output_limit"}
		return
	}

	if err := n.set(Field{kind: key, value: value}); err != nil {
		b.err = &Failure{Category: "invalid_tree"}
	}
}

func (b *pythonNormalizer) list(n *pythonSyntax, depth int) []*Node {
	out := make([]*Node, 0)

	for _, x := range n.named() {
		if v := b.node(x, depth+1); v != nil {
			out = append(out, v)
		}
	}

	return out
}

func (b *pythonNormalizer) alias(n *pythonSyntax) *Node {
	out := b.make(n, Alias)

	name, asname := b.textOf(n), ""
	if n.Kind == pyKindAliasedImport {
		name = b.textOf(n.field(pyFieldName))
		asname = b.textOf(n.field(pyFieldAlias))
	}

	if n.Kind == pyKindWildcardImport {
		name = "*"
	}

	b.set(out, FieldName, StringValue(name))
	b.set(out, Asname, StringValue(asname))

	return out
}

func (b *pythonNormalizer) node(n *pythonSyntax, depth int) *Node {
	if n == nil || !b.accept(n, depth) {
		return nil
	}

	projection, supported := pythonProjections[n.Kind]
	if !supported {
		return b.unsupportedNode(n, depth)
	}

	if projection.build != nil {
		return projection.build(b, n, depth, projection.kind)
	}

	return b.projectFields(n, depth, projection)
}

func (b *pythonNormalizer) accept(n *pythonSyntax, depth int) bool {
	if b.err != nil {
		return false
	}

	if depth > MaxDepth || n.Start < 0 || n.End < n.Start || n.End > len(b.text) {
		b.err = &Failure{Category: "limit"}
		return false
	}

	if b.ctx.Err() != nil {
		b.err = &Failure{Category: "deadline"}
		return false
	}

	return n.Kind != pyKindComment
}
