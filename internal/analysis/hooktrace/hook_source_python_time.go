package hooktrace

import "github.com/skarm/scout/internal/syntax/frontend"

// An isolated calendar formatter can use UTC time and a fixed day offset.
// All calls are on known datetime types, and the format is a literal string.
func pythonUTCProgram(root *frontend.Node, program string) bool {
	body := root.List(frontend.Body)
	if root.Kind() != frontend.Module || len(body) != 2 {
		return false
	}

	valid, offset := pythonUTCImports(body[0])
	value := pythonPrintValue(body[1])
	method := value.Child(frontend.Func)
	args := value.List(frontend.Args)

	return valid && pythonPositionalCall(value) && method.Kind() == frontend.Attribute &&
		method.String(frontend.Attr) == "strftime" && len(args) == 1 && pythonJSONString(args[0]) &&
		pythonUTCDate(method.Child(frontend.FieldValue), offset, program)
}

func pythonUTCImports(stmt *frontend.Node) (valid, offset bool) {
	level, atRoot := stmt.Field(frontend.Level).Integer()
	if stmt.Kind() != frontend.ImportFrom || !atRoot || level != 0 || stmt.String(frontend.FieldModule) != "datetime" {
		return false, false
	}

	names := stmt.List(frontend.Names)
	if len(names) == 0 || len(names) > 2 || !pythonUnaliasedImport(names[0], "datetime") {
		return false, false
	}

	if len(names) == 2 && !pythonUnaliasedImport(names[1], "timedelta") {
		return false, false
	}

	return true, len(names) == 2
}

func pythonUnaliasedImport(n *frontend.Node, name string) bool {
	return n.Kind() == frontend.Alias && n.String(frontend.FieldName) == name && n.String(frontend.Asname) == ""
}

func pythonUTCDate(node *frontend.Node, offset bool, program string) bool {
	if offset && node.Kind() == frontend.BinOp {
		// Only built-in operands can participate in the operation.
		return pythonUTCNow(node.Child(frontend.Left)) && pythonUTCDayOffset(node.Child(frontend.Right), program)
	}

	return pythonUTCNow(node)
}

func pythonUTCNow(node *frontend.Node) bool {
	return pythonPositionalCall(node) && len(node.List(frontend.Args)) == 0 &&
		pythonAttribute(node.Child(frontend.Func), "datetime", "utcnow")
}

func pythonUTCDayOffset(node *frontend.Node, program string) bool {
	kw := node.List(frontend.Keywords)
	if node.Kind() != frontend.Call || !pythonName(node.Child(frontend.Func), "timedelta") ||
		len(node.List(frontend.Args)) != 0 || len(kw) != 1 || kw[0].String(frontend.FieldArg) != "days" {
		return false
	}

	value := kw[0].Child(frontend.FieldValue)
	_, numeric := pythonDecimalLiteral(value, program)

	return numeric
}
