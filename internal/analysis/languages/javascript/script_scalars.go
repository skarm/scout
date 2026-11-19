package javascript

import (
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/syntax/scriptsyntax"
)

func (w *scriptWalk) scalarExpression(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	switch n.Kind {
	case scriptsyntax.KindUpdateExpression:
		return w.update(n, s, depth)
	case scriptsyntax.KindUnaryExpression:
		return w.unary(n, s, depth)
	default:
		return w.assignment(n, s, depth)
	}
}

func (w *scriptWalk) update(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	argument := n.Child(scriptsyntax.FieldArgument)

	value := scriptNumeric(w.expr(argument, s, depth+1))
	argument = w.scalarTarget(argument, depth)

	if argument != nil && argument.Kind == scriptsyntax.KindIdentifier {
		w.bind(argument, value, s, false)
	} else {
		w.limited = true
	}

	// Both prefix and postfix return numeric values. Their exact numbers differ,
	// but neither retains the operand's callable identity or string contents.
	return value
}

func (w *scriptWalk) scalarTarget(n *scriptsyntax.Node, depth int) *scriptsyntax.Node {
	for n != nil {
		switch n.Kind {
		case scriptsyntax.KindParenthesizedExpression, scriptsyntax.KindAsExpression, scriptsyntax.KindSatisfiesExpression, scriptsyntax.KindNonNullExpression:
			if !w.charge(depth) {
				return nil
			}

			n = scriptInnerExpression(n)
			depth++
		default:
			return n
		}
	}

	return nil
}

func scriptInnerExpression(n *scriptsyntax.Node) *scriptsyntax.Node {
	for _, child := range n.Children {
		if child.Kind != scriptsyntax.KindOpenParen && child.Kind != scriptsyntax.KindCloseParen && child.Kind != scriptsyntax.KindComment && child.Kind != scriptsyntax.KindAwait {
			return child
		}
	}

	return nil
}

func (w *scriptWalk) unary(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	value := w.expr(n.Child(scriptsyntax.FieldArgument), s, depth+1)
	switch w.text(n.Child(scriptsyntax.FieldOperator)) {
	case scriptsyntax.OpAdd, scriptsyntax.OpSubtract, scriptsyntax.OpBitwiseNot, scriptsyntax.OpNot:
		return scriptNumeric(value)
	case scriptsyntax.OpVoid:
		return scriptValue{text: "undefined", known: true, valueType: scriptNonString, primitive: true}
	case scriptsyntax.OpTypeof:
		return scriptValue{stringValue: true}
	case scriptsyntax.OpDelete:
		w.limited = true
		return scriptValue{valueType: scriptNonString, primitive: true}
	}

	w.limited = true

	return scriptValue{secret: value.secret, dynamic: value.dynamic}
}

func scriptNumeric(value scriptValue) scriptValue {
	return scriptValue{secret: value.secret, dynamic: value.dynamic, valueType: scriptNonString, primitive: true}
}

func scriptCompound(left, right scriptValue, operator string) scriptValue {
	return scriptBinary(left, right, strings.TrimSuffix(operator, "="))
}

func scriptBinary(left, right scriptValue, operator string) scriptValue {
	switch operator {
	case scriptsyntax.OpSubtract, scriptsyntax.OpMultiply, scriptsyntax.OpDivide, scriptsyntax.OpRemainder, scriptsyntax.OpPower, scriptsyntax.OpLeftShift, scriptsyntax.OpRightShift, scriptsyntax.OpUnsignedRightShift, scriptsyntax.OpBitwiseAnd, scriptsyntax.OpBitwiseOr, scriptsyntax.OpBitwiseXor, scriptsyntax.OpEqual, scriptsyntax.OpNotEqual, scriptsyntax.OpStrictEqual, scriptsyntax.OpStrictNotEqual, scriptsyntax.OpLess, scriptsyntax.OpLessEqual, scriptsyntax.OpGreater, scriptsyntax.OpGreaterEqual, scriptsyntax.OpIn, scriptsyntax.OpInstanceof:
		return scriptNumeric(combineScript(left, right, false))
	case scriptsyntax.OpAdd:
		if left.primitive && right.primitive {
			return scriptNumeric(combineScript(left, right, false))
		}

		return combineScript(left, right, true)
	default:
		return combineScript(left, right, false)
	}
}

func (w *scriptWalk) binary(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	left := w.expr(n.Child(scriptsyntax.FieldLeft), s, depth+1)

	operator := w.text(n.Child(scriptsyntax.FieldOperator))
	if operator != scriptsyntax.OpOr && operator != scriptsyntax.OpAnd && operator != scriptsyntax.OpNullish {
		return scriptBinary(left, w.expr(n.Child(scriptsyntax.FieldRight), s, depth+1), operator)
	}

	evaluate, known := scriptAssignmentCondition(left, operator+"=")
	if !known {
		return w.conditionalRight(n, s, left, depth, false)
	}

	if !evaluate {
		return left
	}

	return w.expr(n.Child(scriptsyntax.FieldRight), s, depth+1)
}

func scriptAssignmentCondition(value scriptValue, operator string) (assign, known bool) {
	if value.known {
		if operator == scriptsyntax.OpNullishAssign {
			return !value.stringValue && (value.text == "null" || value.text == "undefined"), true
		}

		truthy, fixed := scriptTruthiness(value)

		return truthy == (operator == scriptsyntax.OpAndAssign), fixed
	}

	// Selected API models already treat these names as callable; their values
	// and modeled response objects are non-null and truthy.
	if scriptNetwork(value.name) || scriptShellCall(value.name, nil) || value.valueType == scriptPromiseResponse ||
		value.valueType == scriptResponse || value.valueType == scriptPromiseText {
		return operator == scriptsyntax.OpAndAssign, true
	}

	return false, false
}

func scriptTruthiness(value scriptValue) (bool, bool) {
	if value.stringValue {
		return value.text != "", true
	}

	switch value.text {
	case "true":
		return true, true
	case "false", "null", "undefined":
		return false, true
	}

	text := strings.ReplaceAll(value.text, "_", "")
	if number, err := strconv.ParseFloat(text, 64); err == nil {
		return number != 0, true
	}

	if number, err := strconv.ParseUint(strings.TrimSuffix(text, "n"), 0, 64); err == nil {
		return number != 0, true
	}

	return false, false
}

func (w *scriptWalk) conditionalAssignment(n *scriptsyntax.Node, s *scriptScope, previous scriptValue, depth int) scriptValue {
	return w.conditionalRight(n, s, previous, depth, true)
}

func (w *scriptWalk) conditionalRight(n *scriptsyntax.Node, s *scriptScope, previous scriptValue, depth int, assign bool) scriptValue {
	w.limited = true

	unchanged, assigned := w.cloneScope(s), w.cloneScope(s)
	if w.err != nil {
		return scriptValue{}
	}

	value := w.expr(n.Child(scriptsyntax.FieldRight), assigned, depth+1)
	if assign {
		w.bind(w.scalarTarget(n.Child(scriptsyntax.FieldLeft), depth), value, assigned, false)
	}

	w.joinScopes(s, unchanged, assigned)

	return joinScriptValues(previous, value)
}
