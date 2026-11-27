package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/format"
	"go/parser"
	"go/token"
	"path"
	"strconv"
	"strings"
	"unicode"
)

func (i inventory) readGoTests(name string, data []byte) error {
	base := path.Base(name)
	if strings.HasPrefix(base, "_") || strings.HasPrefix(base, ".") {
		return nil
	}

	fset := token.NewFileSet()

	file, err := parser.ParseFile(fset, name, data, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return fmt.Errorf("parse Go tests: %w", err)
	}

	prefix := path.Dir(name) + "/" + file.Name.Name + "\x00"
	tags := goBuildTags(fset, name, file)
	assertions := goAssertionParser{imports: assertionImports(file.Imports), guards: map[assertionGuard]bool{}}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isGoTest(fn) {
			continue
		}

		test := fn.Name.Name
		key := prefix + test
		i.addTest(key, test, location{name, fset.Position(fn.Pos()).Line})
		i.buildTags[key] = append(i.buildTags[key], tags)
		assertions.receiver = assertions.testReceiver(fn.Type)
		i.readTestBody(fset, fn.Body, prefix, test, name, assertions)
	}

	return nil
}

func isGoTest(fn *ast.FuncDecl) bool {
	suffix, ok := strings.CutPrefix(fn.Name.Name, "Test")
	if !ok || fn.Body == nil || fn.Recv != nil || fn.Type.Results != nil || fn.Type.Params.NumFields() != 1 {
		return false
	}

	for _, r := range suffix {
		return !unicode.IsLower(r)
	}

	return true
}

func (i inventory) addTest(key, name string, loc location) {
	if i.negativeName(name) {
		i.controls[key] = append(i.controls[key], loc)
	} else {
		i.tests[key] = append(i.tests[key], loc)
	}
}

func (i inventory) negativeName(name string) bool {
	name = strings.ToLower(i.testNameSeparators.Replace(name))
	return strings.Contains(name, "negative") || strings.Contains(name, "benign") || strings.Contains(name, "falsepositive")
}

func (i inventory) readTestBody(fset *token.FileSet, body *ast.BlockStmt, prefix, test, name string, parser goAssertionParser) {
	ast.PreorderStack(body, nil, func(node ast.Node, ancestors []ast.Node) bool {
		loc := location{name, fset.PositionFor(node.Pos(), false).Line}
		switch n := node.(type) {
		case *ast.CallExpr:
			i.readTestCall(fset, n, ancestors, prefix, test, loc)

			if checks := parser.readCall(n, ancestors, loc); len(checks) != 0 {
				key := prefix + testPath(test, ancestors)
				i.assertions[key] = append(i.assertions[key], checks...)
			}
		case *ast.KeyValueExpr:
			field, ok := n.Key.(*ast.Ident)
			if ok && strings.EqualFold(field.Name, "name") {
				if value := goString(n.Value); i.negativeName(value) {
					key := prefix + test + "/" + value
					i.controls[key] = append(i.controls[key], loc)
				}
			}
		}

		return true
	})
}

func (i inventory) readTestCall(fset *token.FileSet, call *ast.CallExpr, ancestors []ast.Node, prefix, test string, loc location) {
	method := methodName(call)
	switch method {
	case "Run":
		if name := literalSubtest(call); name != "" {
			i.addTest(prefix+testPath(test, ancestors)+"/"+name, name, loc)
		}
	case "Skip", "Skipf", "SkipNow":
		var guard strings.Builder

		for _, node := range ancestors {
			if condition, ok := node.(*ast.IfStmt); ok {
				var text bytes.Buffer

				_ = format.Node(&text, fset, condition.Cond)
				if call.Pos() > condition.Body.End() {
					guard.WriteString("else:")
				}

				guard.WriteString(text.String() + "\x01")
			}
		}

		key := testSkip{subject: prefix + testPath(test, ancestors), condition: guard.String()}
		i.skips[key] = append(i.skips[key], loc)
	}
}

func testPath(test string, ancestors []ast.Node) string {
	parts := []string{test}

	for _, node := range ancestors {
		if call, ok := node.(*ast.CallExpr); ok && methodName(call) == "Run" {
			if child := literalSubtest(call); child != "" {
				parts = append(parts, child)
			}
		}
	}

	return strings.Join(parts, "/")
}

func methodName(call *ast.CallExpr) string {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		return selector.Sel.Name
	}

	return ""
}

func literalSubtest(call *ast.CallExpr) string {
	if len(call.Args) == 2 {
		if _, ok := call.Args[1].(*ast.FuncLit); ok {
			return goString(call.Args[0])
		}
	}

	return ""
}

func goString(expr ast.Expr) string {
	if value, ok := expr.(*ast.BasicLit); ok && value.Kind == token.STRING {
		text, _ := strconv.Unquote(value.Value)
		return text
	}

	return ""
}

func goBuildTags(fset *token.FileSet, name string, file *ast.File) taggedTests {
	tags := taggedTests{expression: filenameBuildTags(name), location: location{name, 1}}

	for _, group := range file.Comments {
		if group.Pos() > file.Package {
			break
		}

		for _, comment := range group.List {
			if constraint.IsGoBuild(comment.Text) {
				explicit := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//go:build"))
				if expr, err := constraint.Parse(comment.Text); err == nil {
					explicit = expr.String()
				}

				tags.expression = strings.TrimSpace(tags.expression + " " + explicit)
				tags.line = fset.Position(comment.Pos()).Line

				return tags
			}

			if constraint.IsPlusBuild(comment.Text) {
				tags.expression += strings.TrimSpace(comment.Text) + "\n"
				tags.line = fset.Position(comment.Pos()).Line
			}
		}
	}

	return tags
}

func filenameBuildTags(name string) string {
	base := strings.TrimSuffix(path.Base(name), "_test.go")

	prefix, last, ok := splitSuffix(base)
	if !ok {
		return ""
	}

	if goOS(last) {
		return "GOOS=" + last
	}

	if goArch(last) {
		if _, previous, hasOS := splitSuffix(prefix); hasOS && goOS(previous) {
			return "GOOS=" + previous + " GOARCH=" + last
		}

		return "GOARCH=" + last
	}

	return ""
}

func splitSuffix(name string) (string, string, bool) {
	index := strings.LastIndexByte(name, '_')
	if index < 1 {
		return "", "", false
	}

	return name[:index], name[index+1:], true
}

func goOS(name string) bool {
	switch name {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "js", "linux",
		"nacl", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows", "zos":
		return true
	default:
		return false
	}
}

func goArch(name string) bool {
	switch name {
	case "386", "amd64", "amd64p32", "arm", "arm64", "arm64be", "armbe", "loong64", "mips",
		"mips64", "mips64le", "mips64p32", "mips64p32le", "mipsle", "ppc", "ppc64", "ppc64le",
		"riscv", "riscv64", "s390", "s390x", "sparc", "sparc64", "wasm":
		return true
	default:
		return false
	}
}
