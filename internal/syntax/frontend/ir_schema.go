package frontend

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

//nolint:gochecknoglobals // Read-only IR schema and Python grammar tables are shared by scans.
var fieldNames = [...]string{
	invalidField:   "",
	Body:           "body",
	Orelse:         "orelse",
	Finalbody:      "finalbody",
	Handlers:       "handlers",
	FieldValue:     "value",
	Values:         "values",
	Targets:        "targets",
	Target:         "target",
	Test:           "test",
	Func:           "func",
	Args:           "args",
	Keywords:       "keywords",
	Elts:           "elts",
	Keys:           "keys",
	Left:           "left",
	Right:          "right",
	Operand:        "operand",
	Iter:           "iter",
	Generators:     "generators",
	Slice:          "slice",
	Items:          "items",
	ContextExpr:    "context_expr",
	OptionalVars:   "optional_vars",
	DecoratorList:  "decorator_list",
	Bases:          "bases",
	Returns:        "returns",
	formatSpec:     "format_spec",
	Elt:            "elt",
	Key:            "key",
	Defaults:       "defaults",
	KWDefaults:     "kw_defaults",
	Names:          "names",
	Ifs:            "ifs",
	exc:            "exc",
	cause:          "cause",
	Annotation:     "annotation",
	Posonlyargs:    "posonlyargs",
	KWOnlyargs:     "kwonlyargs",
	Vararg:         "vararg",
	Kwarg:          "kwarg",
	TypeParams:     "type_params",
	ID:             "id",
	Attr:           "attr",
	FieldName:      "name",
	Asname:         "asname",
	FieldArg:       "arg",
	FieldModule:    "module",
	Level:          "level",
	Op:             "op",
	NumericTruth:   "numeric_truth",
	NumericUnknown: "numeric_unknown",
}

// Variant-local schemas replace the old global Children field-name whitelist.
// Scalar and child shapes cannot be interchanged even where Python reuses a name
// (Constant.value vs Expr.value, Lambda.body vs FunctionDef.body).
//
//nolint:gochecknoglobals // Read-only IR schema and Python grammar tables are shared by scans.
var nodeSchemas = [...]nodeSchema{
	Module:    {name: "Module", fields: []fieldSpec{listField(Body)}},
	Name:      {name: "Name", fields: []fieldSpec{textField(ID)}},
	Attribute: {name: "Attribute", fields: []fieldSpec{childField(FieldValue), textField(Attr)}},
	Call:      {name: "Call", fields: []fieldSpec{childField(Func), listField(Args), listField(Keywords)}},
	Subscript: {name: "Subscript", fields: []fieldSpec{childField(FieldValue), childField(Slice)}},
	Assign:    {name: "Assign", fields: []fieldSpec{childField(FieldValue), listField(Targets)}},
	AnnAssign: {
		name:   "AnnAssign",
		fields: []fieldSpec{childField(FieldValue), childField(Target), childField(Annotation)},
	},
	AugAssign: {name: "AugAssign", fields: []fieldSpec{childField(FieldValue), childField(Target)}},
	NamedExpr: {name: "NamedExpr", fields: []fieldSpec{childField(FieldValue), childField(Target)}},
	Expr:      {name: "Expr", fields: []fieldSpec{childField(FieldValue)}},
	Constant: {
		name: "Constant",
		fields: []fieldSpec{{
			kind:   FieldValue,
			shapes: shape(ValueNull, ValueString, ValueBool, ValueInteger, ValueNumber, valueBytes),
		}, {
			kind:   NumericTruth,
			shapes: shape(ValueBool),
		}, {
			kind:   NumericUnknown,
			shapes: shape(ValueBool),
		}},
	},
	JoinedStr:      {name: "JoinedStr", fields: []fieldSpec{listField(Values)}},
	formattedValue: {name: "FormattedValue", fields: []fieldSpec{childField(FieldValue), childField(formatSpec)}},
	List:           {name: "List", fields: []fieldSpec{listField(Elts)}},
	Tuple:          {name: "Tuple", fields: []fieldSpec{listField(Elts)}},
	Set:            {name: "Set", fields: []fieldSpec{listField(Elts)}},
	Dict:           {name: "Dict", fields: []fieldSpec{listField(Values), listField(Keys)}},
	ListComp:       {name: "ListComp", fields: []fieldSpec{listField(Generators), childField(Elt)}},
	SetComp:        {name: "SetComp", fields: []fieldSpec{listField(Generators), childField(Elt)}},
	DictComp: {
		name:   "DictComp",
		fields: []fieldSpec{childField(FieldValue), listField(Generators), childField(Key)},
	},
	GeneratorExp: {name: "GeneratorExp", fields: []fieldSpec{listField(Generators), childField(Elt)}},
	comprehension: {
		name:   "comprehension",
		fields: []fieldSpec{childField(Target), childField(Iter), listField(Ifs)},
	},
	BoolOp:  {name: "BoolOp", fields: []fieldSpec{listField(Values), textField(Op)}},
	IfExp:   {name: "IfExp", fields: []fieldSpec{childField(Body), childField(Orelse), childField(Test)}},
	BinOp:   {name: "BinOp", fields: []fieldSpec{childField(Left), childField(Right)}},
	UnaryOp: {name: "UnaryOp", fields: []fieldSpec{childField(Operand), textField(Op)}},
	Starred: {name: "Starred", fields: []fieldSpec{childField(FieldValue)}},
	FunctionDef: {
		name:   "FunctionDef",
		fields: []fieldSpec{listField(Body), childField(Args), listField(DecoratorList), childField(Returns), listField(TypeParams), textField(FieldName)},
	},
	AsyncFunctionDef: {
		name:   "AsyncFunctionDef",
		fields: []fieldSpec{listField(Body), childField(Args), listField(DecoratorList), childField(Returns), listField(TypeParams), textField(FieldName)},
	},
	ClassDef: {
		name:   "ClassDef",
		fields: []fieldSpec{listField(Body), listField(Keywords), listField(DecoratorList), listField(Bases), listField(TypeParams), textField(FieldName)},
	},
	Lambda: {name: "Lambda", fields: []fieldSpec{childField(Body), childField(Args)}},
	If:     {name: "If", fields: []fieldSpec{listField(Body), listField(Orelse), childField(Test)}},
	For: {
		name:   "For",
		fields: []fieldSpec{listField(Body), listField(Orelse), childField(Target), childField(Test), childField(Iter)},
	},
	AsyncFor: {
		name:   "AsyncFor",
		fields: []fieldSpec{listField(Body), listField(Orelse), childField(Target), childField(Test), childField(Iter)},
	},
	While: {
		name:   "While",
		fields: []fieldSpec{listField(Body), listField(Orelse), childField(Target), childField(Test), childField(Iter)},
	},
	With:      {name: "With", fields: []fieldSpec{listField(Body), listField(Items)}},
	AsyncWith: {name: "AsyncWith", fields: []fieldSpec{listField(Body), listField(Items)}},
	WithItem:  {name: "withitem", fields: []fieldSpec{childField(ContextExpr), childField(OptionalVars)}},
	Return:    {name: "Return", fields: []fieldSpec{childField(FieldValue), listField(Targets)}},
	raise: {
		name:   "Raise",
		fields: []fieldSpec{childField(FieldValue), listField(Targets), childField(exc), childField(cause)},
	},
	assert:       {name: "Assert", fields: []fieldSpec{childField(FieldValue), listField(Targets)}},
	Delete:       {name: "Delete", fields: []fieldSpec{childField(FieldValue), listField(Targets)}},
	pass:         {name: "Pass"},
	breakNode:    {name: "Break"},
	continueNode: {name: "Continue"},
	Global:       {name: "Global", fields: []fieldSpec{{kind: Names, shapes: shape(valueStrings)}}},
	Nonlocal:     {name: "Nonlocal", fields: []fieldSpec{{kind: Names, shapes: shape(valueStrings)}}},
	Import:       {name: "Import", fields: []fieldSpec{listField(Names)}},
	ImportFrom: {
		name: "ImportFrom",
		fields: []fieldSpec{listField(Names), textField(FieldModule), {
			kind:   Level,
			shapes: shape(ValueInteger),
		}},
	},
	Alias: {name: "alias", fields: []fieldSpec{textField(FieldName), textField(Asname)}},
	Arguments: {
		name:   "arguments",
		fields: []fieldSpec{listField(Args), listField(Defaults), listField(KWDefaults), listField(Posonlyargs), listField(KWOnlyargs), childField(Vararg), childField(Kwarg)},
	},
	Arg: {name: "arg", fields: []fieldSpec{childField(Annotation), textField(FieldArg)}},
	Keyword: {
		name: "keyword",
		fields: []fieldSpec{childField(FieldValue), {
			kind:   FieldArg,
			shapes: shape(ValueString, ValueNull),
		}},
	},
	Try: {
		name:   "Try",
		fields: []fieldSpec{listField(Body), listField(Orelse), listField(Finalbody), listField(Handlers)},
	},
	TryStar: {
		name:   "TryStar",
		fields: []fieldSpec{listField(Body), listField(Orelse), listField(Finalbody), listField(Handlers)},
	},
	ExceptHandler: {
		name:   "ExceptHandler",
		fields: []fieldSpec{listField(Body), childField(Test), textField(FieldName)},
	},
	UnsupportedExpression: {name: "UnsupportedExpression", fields: []fieldSpec{listField(Body), listField(Values)}},
	UnsupportedStatement:  {name: "UnsupportedStatement", fields: []fieldSpec{listField(Body)}},
}

// NodeKind is the closed projection vocabulary, independent of Tree-sitter's CST.
// A Node's kind and fields are established together at the preparation boundary.
type NodeKind uint8

const (
	invalidNode NodeKind = iota
	Module
	Name
	Attribute
	Call
	Subscript
	Assign
	AnnAssign
	AugAssign
	NamedExpr
	Expr
	Constant
	JoinedStr
	formattedValue
	List
	Tuple
	Set
	Dict
	ListComp
	SetComp
	DictComp
	GeneratorExp
	comprehension
	BoolOp
	IfExp
	BinOp
	UnaryOp
	Starred
	FunctionDef
	AsyncFunctionDef
	ClassDef
	Lambda
	If
	For
	AsyncFor
	While
	With
	AsyncWith
	WithItem
	Return
	raise
	assert
	Delete
	pass
	breakNode
	continueNode
	Global
	Nonlocal
	Import
	ImportFrom
	Alias
	Arguments
	Arg
	Keyword
	Try
	TryStar
	ExceptHandler
	UnsupportedExpression
	UnsupportedStatement
)

// FieldKind is a structural selector, not an arbitrary property name. The schema
// below determines its permitted value shape separately for each node variant.
type FieldKind uint8

const (
	invalidField FieldKind = iota
	Body
	Orelse
	Finalbody
	Handlers
	FieldValue
	Values
	Targets
	Target
	Test
	Func
	Args
	Keywords
	Elts
	Keys
	Left
	Right
	Operand
	Iter
	Generators
	Slice
	Items
	ContextExpr
	OptionalVars
	DecoratorList
	Bases
	Returns
	formatSpec
	Elt
	Key
	Defaults
	KWDefaults
	Names
	Ifs
	exc
	cause
	Annotation
	Posonlyargs
	KWOnlyargs
	Vararg
	Kwarg
	TypeParams
	ID
	Attr
	FieldName
	Asname
	FieldArg
	FieldModule
	Level
	Op
	NumericTruth
	NumericUnknown
)

type fieldSpec struct {
	kind   FieldKind
	shapes uint16
}

type nodeSchema struct {
	name   string
	fields []fieldSpec // AST traversal order; every stored edge belongs to this schema.
}

// Field values are created with typed constructors. The containing node checks
// the pair against its variant's schema before accepting it.
type Field struct {
	kind  FieldKind
	value Value
}

// Node holds only schema-validated fields in a stable AST order. The kind and
// fields cannot be independently mutated by a consumer. Nodes are read-only
// after preparation; spans remain exported for source-location projections.
type Node struct {
	Start, End int
	kind       NodeKind
	fields     []Field
	encoded    int
}

func parseNodeKind(name string) (NodeKind, error) {
	for kind, schema := range nodeSchemas {
		if kind != 0 && schema.name == name {
			return NodeKind(kind), nil
		}
	}

	return invalidNode, errors.New("unknown Python IR node kind")
}

func parseFieldKind(name string) (FieldKind, error) {
	for kind, field := range fieldNames {
		if kind != 0 && field == name {
			return FieldKind(kind), nil
		}
	}

	return invalidField, errors.New("unknown Python IR field kind")
}

func NewNode(kind NodeKind, start, end int, fields ...Field) (*Node, error) {
	if kind.String() == "" || start < 0 || end < start {
		return nil, errors.New("invalid Python IR node kind or span")
	}

	node := newNode(kind, start, end)
	for _, field := range fields {
		if _, exists := node.Value(field.kind); exists {
			return nil, errors.New("duplicate Python IR field")
		}

		if err := node.set(field); err != nil {
			return nil, err
		}
	}

	return node, nil
}

func TextField(kind FieldKind, value string) Field {
	return Field{kind: kind, value: StringValue(value)}
}

func ChildField(kind FieldKind, value *Node) Field {
	return Field{kind: kind, value: childValue(value)}
}

func NodesField(kind FieldKind, value []*Node) Field {
	return Field{kind: kind, value: nodesValue(value)}
}

func StringsField(kind FieldKind, value []string) Field {
	return Field{kind: kind, value: stringsValue(value)}
}

func LiteralField(value Value) Field { return Field{kind: FieldValue, value: value} }

func newNode(kind NodeKind, start, end int) *Node {
	return &Node{kind: kind, Start: start, End: end, encoded: nodeHeaderSize(kind.String(), start, end)}
}

func shape(kinds ...valueKind) uint16 {
	var mask uint16
	for _, kind := range kinds {
		mask |= 1 << kind
	}

	return mask
}

func textField(kind FieldKind) fieldSpec { return fieldSpec{kind: kind, shapes: shape(ValueString)} }

func childField(kind FieldKind) fieldSpec {
	return fieldSpec{kind: kind, shapes: shape(valueNode, ValueNull)}
}

func listField(kind FieldKind) fieldSpec { return fieldSpec{kind: kind, shapes: shape(valueNodes)} }

func (kind NodeKind) String() string {
	if kind > invalidNode && int(kind) < len(nodeSchemas) {
		return nodeSchemas[kind].name
	}

	return ""
}

func (kind FieldKind) String() string {
	if int(kind) < len(fieldNames) {
		return fieldNames[kind]
	}

	return ""
}

func (n *Node) Kind() NodeKind {
	if n == nil {
		return invalidNode
	}

	return n.kind
}

func (n *Node) Value(kind FieldKind) (Value, bool) {
	if n != nil {
		for _, field := range n.fields {
			if field.kind == kind {
				return field.value, true
			}
		}
	}

	return Value{}, false
}

func (n *Node) Field(kind FieldKind) Value  { value, _ := n.Value(kind); return value }
func (n *Node) Child(kind FieldKind) *Node  { value, _ := n.Value(kind); return value.node() }
func (n *Node) List(kind FieldKind) []*Node { value, _ := n.Value(kind); return value.nodeSlice() }

func (n *Node) String(kind FieldKind) string {
	value, _ := n.Value(kind)
	text, _ := value.Text()

	return text
}

func (n *Node) Children() []*Node {
	if n == nil {
		return nil
	}

	var children []*Node

	for _, field := range n.fields {
		if child := field.value.node(); child != nil {
			children = append(children, child)
		} else {
			for _, child := range field.value.nodeSlice() {
				if child != nil {
					children = append(children, child)
				}
			}
		}
	}

	return children
}

// MarshalJSON is an explicit transport boundary. Unknown variants, unknown fields,
// duplicate keys and mismatched shapes fail here, before interpretation.
func (n *Node) MarshalJSON() ([]byte, error) {
	if n == nil || n.kind.String() == "" {
		return nil, errors.New("invalid Python IR node kind")
	}

	fields := make(map[string]Value, len(n.fields))
	for _, field := range n.fields {
		fields[field.kind.String()] = field.value
	}

	return json.Marshal(struct {
		Type   string           `json:"type"`
		Start  int              `json:"start"`
		End    int              `json:"end"`
		Fields map[string]Value `json:"fields,omitempty"`
	}{
		Type:   n.kind.String(),
		Start:  n.Start,
		End:    n.End,
		Fields: fields,
	})
}

func (n *Node) UnmarshalJSON(data []byte) error {
	if n == nil || len(data) > maxOutput || !json.Valid(data) {
		return errors.New("invalid Python IR node input")
	}

	object, err := valueObjectFields(data)
	if err != nil {
		return err
	}

	decoded, err := decodeNodeObject(object)
	if err != nil {
		return err
	}

	*n = *decoded

	return nil
}

func (n *Node) fieldIndex(kind FieldKind, value Value) (int, error) {
	if n == nil || n.kind.String() == "" {
		return 0, errors.New("invalid Python IR node")
	}

	for i, spec := range nodeSchemas[n.kind].fields {
		if spec.kind == kind && spec.shapes&(1<<value.kind) != 0 {
			return i, nil
		}
	}

	return 0, fmt.Errorf("invalid Python IR %s.%s field shape", n.kind, kind)
}

func (n *Node) set(field Field) error {
	index, err := n.fieldIndex(field.kind, field.value)
	if err != nil {
		return err
	}

	if err := validateFieldChildren(field.value); err != nil {
		return err
	}

	for i, previous := range n.fields {
		if previous.kind == field.kind {
			n.encoded += field.value.encodedSize() - previous.value.encodedSize()
			n.fields[i] = field

			return nil
		}

		previousIndex, _ := n.fieldIndex(previous.kind, previous.value)
		if previousIndex > index {
			n.fields = slices.Insert(n.fields, i, field)
			n.addFieldSize(field)

			return nil
		}
	}

	n.fields = append(n.fields, field)
	n.addFieldSize(field)

	return nil
}

func (n *Node) addFieldSize(field Field) {
	if len(n.fields) == 1 {
		n.encoded += len(`,"fields":{}`)
	} else {
		n.encoded++
	}

	n.encoded += quotedSize(field.kind.String()) + 1 + field.value.encodedSize()
}

func validateFieldChildren(value Value) error {
	valid := func(node *Node) bool {
		return node == nil || node.kind.String() != "" && node.Start >= 0 && node.End >= node.Start
	}
	if !valid(value.node()) {
		return errors.New("invalid Python IR child")
	}

	for _, child := range value.nodeSlice() {
		if !valid(child) {
			return errors.New("invalid Python IR child in list")
		}
	}

	return nil
}

func decodeNodeObject(object map[string]json.RawMessage) (*Node, error) {
	kind, start, end, err := decodeNodeHeader(object)
	if err != nil {
		return nil, err
	}

	fields, err := decodeNodeFields(kind, object["fields"])
	if err != nil {
		return nil, err
	}

	return NewNode(kind, start, end, fields...)
}

func validateNodeProperties(object map[string]json.RawMessage) error {
	for key := range object {
		if key != "type" && key != "start" && key != "end" && key != "fields" {
			return errors.New("unknown Python IR node property")
		}
	}

	return nil
}

func decodeNodeHeader(object map[string]json.RawMessage) (NodeKind, int, int, error) {
	if err := validateNodeProperties(object); err != nil {
		return invalidNode, 0, 0, err
	}

	var name string
	if err := json.Unmarshal(object["type"], &name); err != nil {
		return invalidNode, 0, 0, errors.New("invalid Python IR node header")
	}

	start, err := decodeNodePosition(object["start"])
	if err != nil {
		return invalidNode, 0, 0, err
	}

	end, err := decodeNodePosition(object["end"])
	if err != nil {
		return invalidNode, 0, 0, err
	}

	kind, err := parseNodeKind(name)

	return kind, start, end, err
}

func decodeNodePosition(raw json.RawMessage) (int, error) {
	var position *int
	if err := json.Unmarshal(raw, &position); err != nil || position == nil {
		return 0, errors.New("invalid Python IR source coordinate")
	}

	return *position, nil
}

func decodeNodeFields(kind NodeKind, raw json.RawMessage) ([]Field, error) {
	var fields []Field

	if raw != nil {
		decoded, err := valueObjectFields(raw)
		if err != nil {
			return nil, err
		}

		for key, rawValue := range decoded {
			field, err := decodeNodeField(kind, key, rawValue)
			if err != nil {
				return nil, err
			}

			fields = append(fields, field)
		}
	}

	return fields, nil
}

func decodeNodeField(kind NodeKind, key string, raw json.RawMessage) (Field, error) {
	fieldKind, err := parseFieldKind(key)
	if err != nil {
		return Field{}, err
	}

	value, err := decodeValue(raw)
	if err != nil {
		return Field{}, err
	}
	// Only the transport's untyped empty array needs schema-guided resolution.
	if (kind == Global || kind == Nonlocal) && fieldKind == Names && value.kind == valueNodes && len(value.children) == 0 {
		value = stringsValue(nil)
	}

	return Field{kind: fieldKind, value: value}, nil
}
