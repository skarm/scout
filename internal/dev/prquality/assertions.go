package main

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"path"
	"slices"
	"strconv"
	"strings"
)

type assertionStrength uint8

const (
	assertionOther assertionStrength = iota
	assertionCoarse
	assertionShape
	assertionExact
)

type testAssertion struct {
	location
	identity, subject string
	strength          assertionStrength
}

type goAssertionParser struct {
	imports  map[string]string
	receiver string
	guards   map[assertionGuard]bool
}

type assertionGuard struct {
	node     *ast.IfStmt
	inverted bool
}

func assertionImports(specs []*ast.ImportSpec) map[string]string {
	imports := make(map[string]string, len(specs))
	for _, spec := range specs {
		value := goString(spec.Path)

		name := path.Base(value)
		if spec.Name != nil {
			name = spec.Name.Name
		}

		imports[name] = value
	}

	return imports
}

func (p goAssertionParser) testReceiver(fn *ast.FuncType) string {
	if fn.Params.NumFields() != 1 {
		return ""
	}

	param := fn.Params.List[0]
	if pointer, ok := param.Type.(*ast.StarExpr); ok && len(param.Names) == 1 && p.packageMember(pointer.X) == "testing.T" {
		return param.Names[0].Name
	}

	return ""
}

func (p goAssertionParser) packageMember(expr ast.Expr) string {
	if member, ok := expr.(*ast.SelectorExpr); ok {
		if qualifier, ok := member.X.(*ast.Ident); ok && p.imports[qualifier.Name] != "" {
			return p.imports[qualifier.Name] + "." + member.Sel.Name
		}
	}

	return ""
}

func (p goAssertionParser) readCall(call *ast.CallExpr, ancestors []ast.Node, loc location) []testAssertion {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	if p.testifyCall(selector, call, ancestors) {
		if check, ok := testifyAssertion(call, selector.Sel.Name, loc); ok {
			return []testAssertion{check}
		}
	}

	switch selector.Sel.Name {
	case "Error", "Errorf", "Fatal", "Fatalf", "Fail", "FailNow":
	default:
		return nil
	}

	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !p.testingReceiver(receiver.Name, ancestors) {
		return nil
	}

	for index := len(ancestors) - 1; index >= 0; index-- {
		switch node := ancestors[index].(type) {
		case *ast.IfStmt:
			guard := assertionGuard{node, call.Pos() > node.Body.End()}
			if p.guards[guard] {
				return nil
			}

			p.guards[guard] = true

			return p.guardAssertions(nil, node.Cond, guard.inverted, goSyntax(node.Init), loc)
		case *ast.FuncLit:
			return nil
		}
	}

	return nil
}

func (p goAssertionParser) testifyCall(selector *ast.SelectorExpr, call *ast.CallExpr, ancestors []ast.Node) bool {
	qualifier, ok := selector.X.(*ast.Ident)
	if !ok || len(call.Args) == 0 {
		return false
	}

	library := p.imports[qualifier.Name]
	if library != "github.com/stretchr/testify/assert" && library != "github.com/stretchr/testify/require" {
		return false
	}

	receiver, ok := ast.Unparen(call.Args[0]).(*ast.Ident)

	return ok && p.testingReceiver(receiver.Name, ancestors)
}

func (p goAssertionParser) testingReceiver(name string, ancestors []ast.Node) bool {
	if name == p.receiver {
		return true
	}

	for _, node := range ancestors {
		if fn, ok := node.(*ast.FuncLit); ok && name == p.testReceiver(fn.Type) {
			return true
		}
	}

	return false
}

func testifyAssertion(call *ast.CallExpr, method string, loc location) (testAssertion, bool) {
	method = strings.TrimSuffix(method, "f")
	actual, required := 1, 2
	strength := assertionExact

	switch method {
	case "Equal", "EqualValues", "Exactly", "ElementsMatch", "JSONEq", "YAMLEq", "Same":
		actual, required = 2, 3
	case "NotEqual", "NotSame":
		actual, required, strength = 2, 3, assertionCoarse
	case "Len":
		strength, required = assertionShape, 3
	case "ErrorIs", "ErrorAs", "EqualError":
		required = 3
	case "Empty", "Nil", "Zero", "NoError", "True", "False":
	case "Contains", "NotContains", "Subset", "Greater", "GreaterOrEqual", "Less", "LessOrEqual", "ErrorContains":
		strength, required = assertionCoarse, 3
	case "NotEmpty", "NotNil", "NotZero", "Positive", "Negative", "Error":
		strength = assertionCoarse
	default:
		return testAssertion{}, false
	}

	if len(call.Args) < required {
		return testAssertion{}, false
	}

	var identity strings.Builder
	identity.WriteString(method)

	for _, arg := range call.Args[1:required] {
		identity.WriteByte('\x00')
		identity.WriteString(goSyntax(arg))
	}

	subject, length := lengthSubject(call.Args[actual])
	if length && strength == assertionExact {
		strength = assertionShape
	}

	return testAssertion{loc, identity.String(), goSyntax(subject), strength}, true
}

func (p goAssertionParser) guardAssertions(out []testAssertion, expr ast.Expr, inverted bool, setup string, loc location) []testAssertion {
	expr = ast.Unparen(expr)
	if negation, ok := expr.(*ast.UnaryExpr); ok && negation.Op == token.NOT {
		return p.guardAssertions(out, negation.X, !inverted, setup, loc)
	}

	if pair, ok := expr.(*ast.BinaryExpr); ok && (pair.Op == token.LOR && !inverted || pair.Op == token.LAND && inverted) {
		out = p.guardAssertions(out, pair.X, inverted, setup, loc)
		return p.guardAssertions(out, pair.Y, inverted, setup, loc)
	}

	subject, strength := p.guardStrength(expr, inverted)
	if setup != "" && subject != "" {
		subject = setup + "\x00" + subject
	}

	identity := "guard\x00" + setup + "\x00" + strconv.FormatBool(inverted) + "\x00" + goSyntax(expr)

	return append(out, testAssertion{loc, identity, subject, strength})
}

func (p goAssertionParser) guardStrength(expr ast.Expr, inverted bool) (string, assertionStrength) {
	switch check := expr.(type) {
	case *ast.Ident:
		return check.Name, assertionExact
	case *ast.BinaryExpr:
		return comparisonStrength(check, inverted)
	case *ast.CallExpr:
		if len(check.Args) >= 2 && inverted {
			switch p.packageMember(check.Fun) {
			case "bytes.Equal", "slices.Equal", "maps.Equal", "reflect.DeepEqual", "github.com/google/go-cmp/cmp.Equal":
				return goSyntax(check.Args[0]), assertionExact
			case "bytes.Contains", "strings.Contains", "strings.HasPrefix", "strings.HasSuffix", "slices.Contains":
				return goSyntax(check.Args[0]), assertionCoarse
			}
		}
	}

	return "", assertionOther
}

func comparisonStrength(pair *ast.BinaryExpr, inverted bool) (string, assertionStrength) {
	left, right := ast.Unparen(pair.X), ast.Unparen(pair.Y)
	if isLiteral(left) && !isLiteral(right) {
		left, right = right, left
	}

	left, length := lengthSubject(left)

	switch pair.Op {
	case token.EQL, token.NEQ:
		if (pair.Op == token.EQL) == inverted {
			if length {
				return goSyntax(left), assertionShape
			}

			return goSyntax(left), assertionExact
		}

		if literal := goSyntax(right); literal == "nil" || literal == "0" || literal == `""` {
			return goSyntax(left), assertionCoarse
		}
	case token.LSS, token.LEQ, token.GTR, token.GEQ:
		return goSyntax(left), assertionCoarse
	}

	return "", assertionOther
}

func lengthSubject(expr ast.Expr) (ast.Expr, bool) {
	expr = ast.Unparen(expr)
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 1 {
		if builtin, ok := call.Fun.(*ast.Ident); ok && builtin.Name == "len" {
			return ast.Unparen(call.Args[0]), true
		}
	}

	return expr, false
}

func isLiteral(expr ast.Expr) bool {
	switch value := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return value.Name == "nil" || value.Name == "false" || value.Name == "true"
	default:
		return false
	}
}

func goSyntax(node ast.Node) string {
	if node == nil {
		return ""
	}

	var text strings.Builder

	_ = format.Node(&text, token.NewFileSet(), node)

	return text.String()
}

type assertionSubject struct {
	name     string
	strength assertionStrength
}

func changedAssertions(before, after inventory) []warning {
	var warnings []warning

	for key, checks := range before.assertions {
		if len(after.tests[key]) != 0 || len(after.controls[key]) != 0 {
			warnings = append(warnings, compareAssertions(subjectName(key), checks, after.assertions[key])...)
		}
	}

	return warnings
}

func compareAssertions(test string, before, after []testAssertion) []warning {
	remaining := make(map[string]int, len(after))
	for _, check := range after {
		remaining[check.identity]++
	}

	var missing []testAssertion

	for _, check := range before {
		if remaining[check.identity] == 0 {
			missing = append(missing, check)
		} else {
			remaining[check.identity]--
		}
	}

	if len(missing) == 0 {
		return nil
	}

	replacements := make(map[assertionSubject][]testAssertion)

	for _, check := range after {
		if remaining[check.identity] > 0 {
			remaining[check.identity]--
			if check.subject != "" {
				key := assertionSubject{check.subject, check.strength}
				replacements[key] = append(replacements[key], check)
			}
		}
	}

	// Match equally strict checks first. This avoids treating a remaining
	// exact check as a replacement for a relaxed check on the same value.
	unmatched := missing[:0]
	for _, check := range missing {
		if _, found := takeAssertion(replacements, check.subject, check.strength); !found {
			unmatched = append(unmatched, check)
		}
	}

	return assertionWarnings(test, unmatched, replacements)
}

func assertionWarnings(test string, missing []testAssertion, replacements map[assertionSubject][]testAssertion) []warning {
	var warnings []warning

	slices.SortStableFunc(missing, func(a, b testAssertion) int { return int(b.strength) - int(a.strength) })

	for _, check := range missing {
		next, found := replacementAssertion(replacements, check.subject)
		if found {
			if next.strength < check.strength {
				warnings = append(warnings, warning{
					next.location, false, "Test assertion weakened",
					fmt.Sprintf("%q replaced an assertion with a looser check on %q.", test, assertionValue(check.subject)),
				})
			}

			continue
		}

		detail := fmt.Sprintf("%q lost an assertion at this line.", test)
		if check.subject != "" {
			detail = fmt.Sprintf("%q lost a check on %q at this line.", test, assertionValue(check.subject))
		}

		warnings = append(warnings, warning{check.location, true, "Test assertion removed", detail})
	}

	return warnings
}

func replacementAssertion(available map[assertionSubject][]testAssertion, subject string) (testAssertion, bool) {
	if subject != "" {
		for strength := assertionExact; strength > assertionOther; strength-- {
			if next, found := takeAssertion(available, subject, strength); found {
				return next, true
			}
		}
	}

	return testAssertion{}, false
}

func takeAssertion(available map[assertionSubject][]testAssertion, subject string, strength assertionStrength) (testAssertion, bool) {
	key := assertionSubject{subject, strength}

	checks := available[key]
	if len(checks) == 0 {
		return testAssertion{}, false
	}

	available[key] = checks[1:]

	return checks[0], true
}

func assertionValue(subject string) string {
	return subject[strings.LastIndexByte(subject, '\x00')+1:]
}
