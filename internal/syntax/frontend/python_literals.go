package frontend

import (
	"math"
	"strconv"
	"strings"
)

func (b *pythonNormalizer) nodeInteger(n *pythonSyntax, _ int, kind NodeKind) *Node {
	out := b.make(n, kind)
	b.set(out, FieldValue, NullValue())

	if n.Kind == pyKindInteger || n.Kind == pyKindFloat {
		b.setNumericTruth(out, n.Kind, b.textOf(n))
	}

	if n.Kind == pyKindEllipsis {
		b.set(out, NumericTruth, BoolValue(true))
	}

	if n.Kind == pyKindTrue {
		b.set(out, FieldValue, BoolValue(true))
	}

	if n.Kind == pyKindFalse {
		b.set(out, FieldValue, BoolValue(false))
	}

	return out
}

func (b *pythonNormalizer) setNumericTruth(out *Node, kind, text string) {
	// An imaginary literal has a floating-point coefficient, even when
	// the CST classifies its spelling as an integer.
	coefficient := strings.TrimRight(text, "jJ")
	if kind == pyKindInteger && coefficient == text {
		b.set(out, NumericTruth, BoolValue(pythonIntegerTruth(text)))
		return
	}

	v, err := strconv.ParseFloat(strings.ReplaceAll(coefficient, "_", ""), 64)
	if err == nil || math.IsInf(v, 0) {
		b.set(out, NumericTruth, BoolValue(v != 0))
	} else {
		b.set(out, NumericUnknown, BoolValue(true))
	}
}

func pythonIntegerTruth(text string) bool {
	digits := strings.ReplaceAll(text, "_", "")
	if len(digits) > 2 && digits[0] == '0' && strings.ContainsRune("xXoObB", rune(digits[1])) {
		digits = digits[2:]
	}

	return strings.Trim(digits, "0") != ""
}
