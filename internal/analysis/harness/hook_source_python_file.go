package harness

import (
	"slices"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/syntax/frontend"
)

// Track a read-only text file through a bounded read, an optional truncation
// suffix, and JSON output. File contents and paths stay data in this model.
func pythonFileJSONFilter(body []*frontend.Node, program string, argc int) bool {
	if len(body) != 2 || body[0].Kind() != frontend.With {
		return false
	}

	items := body[0].List(frontend.Items)
	if len(items) != 1 || !pythonReadOnlyFile(items[0].Child(frontend.ContextExpr), program, argc) {
		return false
	}

	stream := pythonFileBinding(items[0].Child(frontend.OptionalVars))
	text := pythonFileTextBinding(body[0].List(frontend.Body), stream, program)

	return text != "" && pythonJSONDump(pythonPrintValue(body[1]), func(value *frontend.Node) bool {
		return pythonFileText(value, text, 0)
	})
}

func pythonReadOnlyFile(open *frontend.Node, program string, argc int) bool {
	args := open.List(frontend.Args)
	if open.Kind() != frontend.Call || !pythonName(open.Child(frontend.Func), "open") || len(args) != 1 ||
		!pythonJSONArgument(args[0], program, argc) {
		return false
	}

	// No positional mode, custom opener, or user-chosen codec.
	var encoding, errorHandling bool

	for _, keyword := range open.List(frontend.Keywords) {
		value := keyword.Child(frontend.FieldValue)
		if !pythonJSONString(value) {
			return false
		}

		text := value.String(frontend.FieldValue)

		switch keyword.String(frontend.FieldArg) {
		case "encoding":
			if encoding || text != "utf-8" {
				return false
			}

			encoding = true
		case "errors":
			if errorHandling || !slices.Contains([]string{"strict", "ignore", "replace"}, text) {
				return false
			}

			errorHandling = true
		default:
			return false
		}
	}

	return encoding
}

func pythonFileTextBinding(body []*frontend.Node, stream, program string) string {
	if stream == "" || len(body) == 0 || len(body) > 2 {
		return ""
	}

	first := body[0]
	targets := first.List(frontend.Targets)

	if first.Kind() != frontend.Assign || len(targets) != 1 || !pythonBoundedRead(first.Child(frontend.FieldValue), stream, program) {
		return ""
	}

	text := pythonFileBinding(targets[0])
	if text == "" || text == stream || len(body) == 2 && !pythonFileTruncation(body[1], stream, text, program) {
		return ""
	}

	return text
}

func pythonFileBinding(n *frontend.Node) string {
	name := n.String(frontend.ID)
	if n.Kind() != frontend.Name || !hookVariableName(name) || strings.HasPrefix(name, "__") ||
		slices.Contains([]string{"json", "sys", "open", "print"}, name) {
		return ""
	}

	return name
}

func pythonBoundedRead(call *frontend.Node, stream, program string) bool {
	args := call.List(frontend.Args)
	if !pythonPositionalCall(call) || len(args) != 1 || !pythonAttribute(call.Child(frontend.Func), stream, "read") {
		return false
	}

	literal, decimal := pythonDecimalLiteral(args[0], program)
	count, err := strconv.Atoi(literal)

	return decimal && err == nil && count > 0 && count <= 1<<20
}

func pythonFileTruncation(stmt *frontend.Node, stream, text, program string) bool {
	body := stmt.List(frontend.Body)
	if stmt.Kind() != frontend.If || len(body) != 1 || len(stmt.List(frontend.Orelse)) != 0 ||
		!pythonBoundedRead(stmt.Child(frontend.Test), stream, program) {
		return false
	}

	appendText := body[0]

	return appendText.Kind() == frontend.AugAssign && pythonName(appendText.Child(frontend.Target), text) &&
		pythonJSONString(appendText.Child(frontend.FieldValue))
}

func pythonFileText(value *frontend.Node, text string, depth int) bool {
	if depth >= 8 {
		return false
	}

	if pythonName(value, text) || pythonJSONString(value) {
		return true
	}

	return value.Kind() == frontend.BinOp && pythonFileText(value.Child(frontend.Left), text, depth+1) &&
		pythonFileText(value.Child(frontend.Right), text, depth+1)
}
