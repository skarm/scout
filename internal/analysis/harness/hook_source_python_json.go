package harness

import (
	"slices"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

// The caller has already proved that a standard Python interpreter received
// -I and -S. Each accepted form evaluates only known standard-library values.
func knownIsolatedPythonProgram(units []document.Unit, span source.Span, argc int) bool {
	for _, unit := range units {
		if unit.Origin != document.OriginHookInlineRuntime || unit.Span != span || unit.Status != report.UnitParsedLimited {
			continue
		}

		if tree, ok := unit.Tree.(parse.PythonTree); ok && knownIsolatedPythonTree(tree.Root, unit.View.Text(), argc) {
			return true
		}
	}

	return false
}

func knownIsolatedPythonTree(root *frontend.Node, program string, argc int) bool {
	return pythonJSONProgram(root, program, argc) || argc == 0 && pythonUTCProgram(root, program)
}

func pythonJSONProgram(root *frontend.Node, program string, argc int) bool {
	if root.Kind() != frontend.Module {
		return false
	}

	body := root.List(frontend.Body)
	if len(body) < 2 || len(body) > 5 {
		return false
	}

	var jsonModule, sysModule bool

	for len(body) > 0 && body[0].Kind() == frontend.Import {
		for _, alias := range body[0].List(frontend.Names) {
			name := alias.String(frontend.FieldName)
			if alias.String(frontend.Asname) != "" || name != "json" && name != "sys" {
				return false
			}

			jsonModule = jsonModule || name == "json"
			sysModule = sysModule || name == "sys"
		}

		body = body[1:]
	}

	if !jsonModule || !sysModule {
		return false
	}

	if argc > 0 {
		return len(body) == 1 && pythonJSONDump(pythonPrintValue(body[0]), func(value *frontend.Node) bool {
			return pythonJSONArgument(value, program, argc)
		}) || pythonFileJSONFilter(body, program, argc) || pythonCountJSONLines(body, program, argc)
	}

	return pythonJSONFilter(body)
}

func pythonJSONDump(call *frontend.Node, acceptsLeaf func(*frontend.Node) bool) bool {
	args := call.List(frontend.Args)

	return pythonPositionalCall(call) && len(args) == 1 &&
		pythonAttribute(call.Child(frontend.Func), "json", "dumps") &&
		pythonJSONObject(args[0], acceptsLeaf, 0)
}

func pythonJSONObject(node *frontend.Node, acceptsLeaf func(*frontend.Node) bool, depth int) bool {
	if depth >= 8 {
		return false
	}

	if node.Kind() != frontend.Dict {
		return pythonJSONString(node) || acceptsLeaf(node)
	}

	keys := node.List(frontend.Keys)
	values := node.List(frontend.Values)

	if len(keys) != len(values) {
		return false
	}

	for i, key := range keys {
		if !pythonJSONString(key) || !pythonJSONObject(values[i], acceptsLeaf, depth+1) {
			return false
		}
	}

	return true
}

func pythonJSONArgument(node *frontend.Node, program string, argc int) bool {
	if node.Kind() != frontend.Subscript || !pythonAttribute(node.Child(frontend.FieldValue), "sys", "argv") {
		return false
	}

	text, decimal := pythonDecimalLiteral(node.Child(frontend.Slice), program)
	index, err := strconv.Atoi(text)

	return decimal && err == nil && index > 0 && index <= argc
}

func pythonDecimalLiteral(node *frontend.Node, program string) (string, bool) {
	if node.Kind() != frontend.Constant || node.Start < 0 || node.End > len(program) || node.End <= node.Start {
		return "", false
	}

	_, numeric := node.Field(frontend.NumericTruth).Boolean()
	text := program[node.Start:node.End]

	return text, numeric && decimalDigits(text)
}

func pythonPrintValue(stmt *frontend.Node) *frontend.Node {
	call := stmt.Child(frontend.FieldValue)
	args := call.List(frontend.Args)

	if stmt.Kind() == frontend.Expr && pythonPositionalCall(call) && len(args) == 1 &&
		pythonName(call.Child(frontend.Func), "print") {
		return args[0]
	}

	return nil
}

func pythonJSONFilter(body []*frontend.Node) bool {
	if len(body) == 1 && body[0].Kind() == frontend.Try {
		body = pythonJSONTryBody(body[0])
	}

	if len(body) == 0 || len(body) > 3 {
		return false
	}

	var bindings []string

	for _, stmt := range body[:len(body)-1] {
		name := pythonJSONBinding(stmt, bindings)
		if name == "" || slices.Contains(bindings, name) {
			return false
		}

		bindings = append(bindings, name)
	}

	value := pythonPrintValue(body[len(body)-1])

	return pythonJSONField(value, bindings, 0) || pythonJSONDictChoice(value, bindings)
}

func pythonJSONTryBody(stmt *frontend.Node) []*frontend.Node {
	handlers := stmt.List(frontend.Handlers)
	if len(handlers) != 1 || len(stmt.List(frontend.Orelse)) != 0 || len(stmt.List(frontend.Finalbody)) != 0 {
		return nil
	}

	handler := handlers[0]
	body := handler.List(frontend.Body)

	if handler.Kind() != frontend.ExceptHandler || handler.String(frontend.FieldName) != "" ||
		len(body) != 1 || body[0].Kind() != frontend.Pass || !pythonJSONExceptions(handler.Child(frontend.Test)) {
		return nil
	}

	return stmt.List(frontend.Body)
}

func pythonJSONExceptions(node *frontend.Node) bool {
	if node.Kind() != frontend.Tuple {
		return pythonJSONException(node)
	}

	members := node.List(frontend.Elts)

	return len(members) > 0 && len(members) <= 4 && !slices.ContainsFunc(members, func(member *frontend.Node) bool {
		return !pythonJSONException(member)
	})
}

func pythonJSONException(node *frontend.Node) bool {
	if pythonAttribute(node, "json", "JSONDecodeError") {
		return true
	}

	return node.Kind() == frontend.Name && slices.Contains(
		[]string{"Exception", "AttributeError", "KeyError", "TypeError", "ValueError"}, node.String(frontend.ID))
}

func pythonJSONBinding(stmt *frontend.Node, bindings []string) string {
	targets := stmt.List(frontend.Targets)
	if stmt.Kind() != frontend.Assign || len(targets) != 1 || targets[0].Kind() != frontend.Name ||
		!pythonJSONField(stmt.Child(frontend.FieldValue), bindings, 0) {
		return ""
	}

	name := targets[0].String(frontend.ID)
	if !hookVariableName(name) || strings.HasPrefix(name, "__") ||
		slices.Contains([]string{"json", "sys", "print", "isinstance", "dict"}, name) || pythonJSONException(targets[0]) {
		return ""
	}

	return name
}

func pythonJSONDictChoice(node *frontend.Node, bindings []string) bool {
	test := node.Child(frontend.Test)
	args := test.List(frontend.Args)

	return node.Kind() == frontend.IfExp && pythonPositionalCall(test) && len(args) == 2 &&
		pythonName(test.Child(frontend.Func), "isinstance") && pythonName(args[1], "dict") &&
		pythonJSONLocal(args[0], bindings) && pythonJSONField(node.Child(frontend.Body), bindings, 0) &&
		pythonJSONDefault(node.Child(frontend.Orelse))
}

func pythonJSONLocal(node *frontend.Node, bindings []string) bool {
	return node.Kind() == frontend.Name && slices.Contains(bindings, node.String(frontend.ID))
}

func pythonJSONField(node *frontend.Node, bindings []string, depth int) bool {
	if depth >= 8 {
		return false
	}

	if pythonJSONLocal(node, bindings) || pythonJSONInput(node) {
		return true
	}

	method := node.Child(frontend.Func)
	args := node.List(frontend.Args)

	if !pythonPositionalCall(node) || method.Kind() != frontend.Attribute || method.String(frontend.Attr) != "get" ||
		len(args) < 1 || len(args) > 2 || !pythonJSONString(args[0]) {
		return false
	}

	if len(args) == 2 && !pythonJSONDefault(args[1]) {
		return false
	}

	return pythonJSONField(method.Child(frontend.FieldValue), bindings, depth+1)
}

func pythonJSONDefault(n *frontend.Node) bool {
	if n.Kind() == frontend.Dict {
		return len(n.List(frontend.Keys)) == 0 && len(n.List(frontend.Values)) == 0
	}

	value, ok := n.Value(frontend.FieldValue)

	return n.Kind() == frontend.Constant && ok &&
		(value.Kind() == frontend.ValueString || value.Kind() == frontend.ValueNull || value.Kind() == frontend.ValueBool || value.Kind() == frontend.ValueInteger)
}

func pythonJSONString(n *frontend.Node) bool {
	value, ok := n.Value(frontend.FieldValue)

	return n.Kind() == frontend.Constant && ok && value.Kind() == frontend.ValueString
}

func pythonJSONInput(node *frontend.Node) bool {
	args := node.List(frontend.Args)

	return pythonPositionalCall(node) && len(args) == 1 &&
		pythonAttribute(node.Child(frontend.Func), "json", "load") && pythonAttribute(args[0], "sys", "stdin")
}

func pythonPositionalCall(node *frontend.Node) bool {
	return node.Kind() == frontend.Call && len(node.List(frontend.Keywords)) == 0
}

func pythonAttribute(node *frontend.Node, name, attr string) bool {
	return node.Kind() == frontend.Attribute && node.String(frontend.Attr) == attr && pythonName(node.Child(frontend.FieldValue), name)
}

func pythonName(node *frontend.Node, name string) bool {
	return node.Kind() == frontend.Name && node.String(frontend.ID) == name
}
