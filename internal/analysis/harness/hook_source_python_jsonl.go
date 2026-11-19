package harness

import (
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/frontend"
)

// The isolated program reads lines as text, decodes JSON as built-in data,
// and counts records that pass constant field and type tests.
func pythonCountJSONLines(body []*frontend.Node, program string, argc int) bool {
	if len(body) != 3 || body[1].Kind() != frontend.With {
		return false
	}

	initial, counter := pythonAssignment(body[0])
	number, numeric := pythonDecimalLiteral(initial, program)

	if !numeric || number != "0" || !pythonName(pythonPrintValue(body[2]), counter) {
		return false
	}

	items := body[1].List(frontend.Items)
	loops := body[1].List(frontend.Body)

	if len(items) != 1 || len(loops) != 1 || !pythonJSONLineFile(items[0].Child(frontend.ContextExpr), program, argc) {
		return false
	}

	stream := pythonFileBinding(items[0].Child(frontend.OptionalVars))
	line := pythonFileBinding(loops[0].Child(frontend.Target))

	return pythonDistinctNames(counter, stream, line) && loops[0].Kind() == frontend.For &&
		pythonName(loops[0].Child(frontend.Iter), stream) && len(loops[0].List(frontend.Orelse)) == 0 &&
		pythonJSONLineLoop(loops[0].List(frontend.Body), program, counter, stream, line)
}

func pythonJSONLineFile(call *frontend.Node, program string, argc int) bool {
	if pythonReadOnlyFile(call, program, argc) {
		return true
	}

	args := call.List(frontend.Args)

	return pythonPositionalCall(call) && pythonName(call.Child(frontend.Func), "open") && len(args) == 2 &&
		pythonJSONArgument(args[0], program, argc) && pythonJSONString(args[1]) && args[1].String(frontend.FieldValue) == "r"
}

func pythonJSONLineLoop(body []*frontend.Node, program, counter, stream, line string) bool {
	if len(body) == 3 {
		expr, target := pythonAssignment(body[0])
		if target != line || !pythonPositionalCall(expr) || len(expr.List(frontend.Args)) != 0 ||
			!pythonAttribute(expr.Child(frontend.Func), line, "strip") || !pythonSkipEmptyLine(body[1], line) {
			return false
		}

		body = body[2:]
	}

	if len(body) != 1 || body[0].Kind() != frontend.Try {
		return false
	}

	rows := pythonJSONTryBody(body[0])
	if len(rows) != 4 {
		return false
	}

	decode, record := pythonAssignment(rows[0])
	extract, value := pythonAssignment(rows[2])

	return pythonDistinctNames(counter, stream, line, record, value) &&
		pythonJSONDecodeLine(decode, line) && pythonJSONLineSkip(rows[1], record) &&
		pythonJSONField(extract, []string{record}, 0) && pythonJSONLineIncrement(rows[3], value, counter, program)
}

func pythonAssignment(stmt *frontend.Node) (*frontend.Node, string) {
	targets := stmt.List(frontend.Targets)
	if stmt.Kind() != frontend.Assign || len(targets) != 1 {
		return nil, ""
	}

	return stmt.Child(frontend.FieldValue), pythonFileBinding(targets[0])
}

func pythonDistinctNames(names ...string) bool {
	for i, name := range names {
		if name == "" || name == "isinstance" || name == "str" || slices.Contains(names[:i], name) {
			return false
		}
	}

	return true
}

func pythonSkipEmptyLine(stmt *frontend.Node, line string) bool {
	test := stmt.Child(frontend.Test)

	return pythonOnlyContinue(stmt) && test.Kind() == frontend.UnaryOp && test.String(frontend.Op) == "Not" &&
		pythonName(test.Child(frontend.Operand), line)
}

func pythonOnlyContinue(stmt *frontend.Node) bool {
	body := stmt.List(frontend.Body)

	return stmt.Kind() == frontend.If && len(stmt.List(frontend.Orelse)) == 0 &&
		len(body) == 1 && body[0].Kind() == frontend.Continue
}

func pythonJSONDecodeLine(call *frontend.Node, line string) bool {
	args := call.List(frontend.Args)

	return pythonPositionalCall(call) && pythonAttribute(call.Child(frontend.Func), "json", "loads") &&
		len(args) == 1 && pythonName(args[0], line)
}

func pythonJSONLineSkip(stmt *frontend.Node, record string) bool {
	test := stmt.Child(frontend.Test)

	return pythonOnlyContinue(stmt) && test.Kind() == frontend.Compare && test.String(frontend.Op) == "!=" &&
		pythonJSONField(test.Child(frontend.Left), []string{record}, 0) && pythonJSONString(test.Child(frontend.Right))
}

func pythonJSONLineIncrement(stmt *frontend.Node, value, counter, program string) bool {
	test := stmt.Child(frontend.Test)
	args := test.List(frontend.Args)
	body := stmt.List(frontend.Body)

	return stmt.Kind() == frontend.If && len(stmt.List(frontend.Orelse)) == 0 && len(body) == 1 &&
		pythonPositionalCall(test) && pythonName(test.Child(frontend.Func), "isinstance") &&
		len(args) == 2 && pythonName(args[0], value) && pythonName(args[1], "str") &&
		pythonIncrementByOne(body[0], counter, program)
}

func pythonIncrementByOne(stmt *frontend.Node, name, program string) bool {
	target := stmt.Child(frontend.Target)
	operand := stmt.Child(frontend.FieldValue)
	number, numeric := pythonDecimalLiteral(operand, program)

	return stmt.Kind() == frontend.AugAssign && pythonName(target, name) && numeric && number == "1" &&
		target.End >= 0 && target.End <= operand.Start && strings.TrimSpace(program[target.End:operand.Start]) == "+="
}
