package frontend

import "context"

// Test-only access to pure conversion contracts. These helpers do not emulate
// Tree-sitter parsing and are not present in the application binary.
type TestPythonSyntax = pythonSyntax

func NormalizePythonForTest(ctx context.Context, text string, root *TestPythonSyntax) (*Node, error) {
	return normalizePython(ctx, text, root)
}

func PythonLiteralForTest(s string) (string, bool, bool) { return pythonLiteral(s) }

func ValidateTreeForTest(r Result, size int) error { return validateTree(r, size) }
