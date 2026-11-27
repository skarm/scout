package python

import (
	"maps"
	"slices"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const maxEnvironmentProofBytes = 8192

// ChildEnvironmentCopy identifies an environment copy passed exclusively to a
// Python subprocess as its environment, in original file coordinates.
func ChildEnvironmentCopy(unit document.Unit) (source.Span, bool) {
	tree, ok := unit.Tree.(parse.PythonTree)
	if !ok || unit.Status != report.UnitParsedLimited || len(unit.View.Text()) > maxEnvironmentProofBytes {
		return source.Span{}, false
	}

	copyNode := provenChildEnvironment(tree.Root.List(frontend.Body))
	if copyNode == nil {
		return source.Span{}, false
	}

	at, err := unit.View.Original(source.Span{Start: copyNode.Start, End: copyNode.End})

	return at, err == nil
}

// Only a resolved, local hand-off is downgraded. The proof accepts an inline
// copy or a single local binding with one consumer in an isolated body.
// Unknown setup, rebinding, extra arguments and other uses keep E2 unchanged.
func provenChildEnvironment(body []*frontend.Node) *frontend.Node {
	imports := map[string]string{}

	body, ok := environmentImports(body, imports)
	if !ok || len(body) == 0 {
		return nil
	}

	first := body[0]
	// Later statements cannot use the anonymous copy.
	if candidate := childEnvironmentArgument(first, imports); environmentCopy(candidate, imports) {
		return candidate
	}

	if len(body) != 1 {
		return nil
	}

	switch first.Kind() {
	case frontend.FunctionDef:
		if len(first.Child(frontend.Args).Children()) != 0 || len(first.List(frontend.DecoratorList)) != 0 ||
			first.Child(frontend.Returns) != nil || len(first.List(frontend.TypeParams)) != 0 ||
			imports[first.String(frontend.FieldName)] != "" || first.String(frontend.FieldName) == "dict" {
			return nil
		}
	case frontend.If:
		if imports["__name__"] != "" || !pythonMainGuard(first) {
			return nil
		}
	default:
		return nil
	}

	return isolatedEnvironmentBody(first.List(frontend.Body), imports)
}

func environmentImports(body []*frontend.Node, bindings map[string]string) ([]*frontend.Node, bool) {
	if len(body) > 0 && body[0].Kind() == frontend.Expr && body[0].Child(frontend.FieldValue).Kind() == frontend.Constant {
		if _, ok := body[0].Child(frontend.FieldValue).Field(frontend.FieldValue).Text(); ok {
			body = body[1:]
		}
	}

	for len(body) > 0 && body[0].Kind() == frontend.Import {
		for _, item := range body[0].List(frontend.Names) {
			name := item.String(frontend.FieldName)
			if name != "os" && name != "subprocess" {
				return nil, false
			}

			binding := item.String(frontend.Asname)
			if binding == "" {
				binding = name
			}

			if old := bindings[binding]; old != "" && old != name {
				return nil, false
			}

			bindings[binding] = name
		}

		body = body[1:]
	}

	return body, true
}

func pythonMainGuard(node *frontend.Node) bool {
	test := node.Child(frontend.Test)
	if len(node.List(frontend.Orelse)) != 0 || test.Kind() != frontend.Compare || test.String(frontend.Op) != "==" {
		return false
	}

	left, right := test.Child(frontend.Left), test.Child(frontend.Right)

	return left.Kind() == frontend.Name && left.String(frontend.ID) == "__name__" &&
		right.Kind() == frontend.Constant && right.String(frontend.FieldValue) == "__main__"
}

func isolatedEnvironmentBody(body []*frontend.Node, inherited map[string]string) *frontend.Node {
	imports := maps.Clone(inherited)

	body, ok := environmentImports(body, imports)
	if !ok || len(body) == 0 {
		return nil
	}

	if len(body) == 1 {
		if candidate := childEnvironmentArgument(body[0], imports); environmentCopy(candidate, imports) {
			return candidate
		}

		return nil
	}

	if len(body) != 2 || body[0].Kind() != frontend.Assign {
		return nil
	}

	targets := body[0].List(frontend.Targets)

	consumer := childEnvironmentArgument(body[1], imports)
	if len(targets) != 1 || targets[0].Kind() != frontend.Name || consumer.Kind() != frontend.Name {
		return nil
	}

	binding := targets[0].String(frontend.ID)

	copyNode := body[0].Child(frontend.FieldValue)
	if binding == "" || binding == "dict" || imports[binding] != "" || consumer.String(frontend.ID) != binding || !environmentCopy(copyNode, imports) {
		return nil
	}

	return copyNode
}

func childEnvironmentArgument(statement *frontend.Node, imports map[string]string) *frontend.Node {
	if statement.Kind() != frontend.Expr {
		return nil
	}

	call := statement.Child(frontend.FieldValue)

	method := call.Child(frontend.Func)
	if call.Kind() != frontend.Call || method.Kind() != frontend.Attribute ||
		!boundPythonName(method.Child(frontend.FieldValue), imports, "subprocess") ||
		!slices.Contains([]string{"run", "Popen", "call", "check_call", "check_output"}, method.String(frontend.Attr)) {
		return nil
	}

	args, keywords := call.List(frontend.Args), call.List(frontend.Keywords)
	if len(args) != 1 || len(keywords) != 1 || keywords[0].String(frontend.FieldArg) != "env" ||
		!literalChildArgv(args[0]) {
		return nil
	}

	return keywords[0].Child(frontend.FieldValue)
}

func literalChildArgv(arg *frontend.Node) bool {
	if arg.Kind() != frontend.List && arg.Kind() != frontend.Tuple {
		return false
	}

	items := arg.List(frontend.Elts)
	if len(items) == 0 {
		return false
	}

	for _, item := range items {
		if _, ok := item.Field(frontend.FieldValue).Text(); item.Kind() != frontend.Constant || !ok {
			return false
		}
	}

	return true
}

func environmentCopy(node *frontend.Node, imports map[string]string) bool {
	if node.Kind() != frontend.Call || len(node.List(frontend.Keywords)) != 0 {
		return false
	}

	callee, args := node.Child(frontend.Func), node.List(frontend.Args)

	var mapping *frontend.Node

	switch {
	case callee.Kind() == frontend.Attribute && callee.String(frontend.Attr) == "copy" && len(args) == 0:
		mapping = callee.Child(frontend.FieldValue)
	case callee.Kind() == frontend.Name && callee.String(frontend.ID) == "dict" && imports["dict"] == "" && len(args) == 1:
		mapping = args[0]
	default:
		return false
	}

	return mapping.Kind() == frontend.Attribute && mapping.String(frontend.Attr) == "environ" &&
		boundPythonName(mapping.Child(frontend.FieldValue), imports, "os")
}

func boundPythonName(node *frontend.Node, imports map[string]string, module string) bool {
	return node.Kind() == frontend.Name && imports[node.String(frontend.ID)] == module
}
