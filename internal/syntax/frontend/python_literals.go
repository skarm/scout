package frontend

import (
	"math"
	"strconv"
	"strings"
)

func (b *pythonNormalizer) nodeInteger(n *pythonSyntax, _ int, kind NodeKind) *Node {
	out := b.make(n, kind)
	b.set(out, FieldValue, NullValue())

	if n.Kind == "integer" {
		b.set(out, NumericTruth, BoolValue(pythonIntegerTruth(b.textOf(n))))
	}

	if n.Kind == "float" {
		v, err := strconv.ParseFloat(strings.ReplaceAll(b.textOf(n), "_", ""), 64)
		if err == nil || math.IsInf(v, 0) {
			b.set(out, NumericTruth, BoolValue(v != 0))
		} else {
			b.set(out, NumericUnknown, BoolValue(true))
		}
	}

	if n.Kind == "ellipsis" {
		b.set(out, NumericTruth, BoolValue(true))
	}

	if n.Kind == "true" {
		b.set(out, FieldValue, BoolValue(true))
	}

	if n.Kind == "false" {
		b.set(out, FieldValue, BoolValue(false))
	}

	return out
}

func pythonIntegerTruth(text string) bool {
	digits := strings.ReplaceAll(text, "_", "")
	if len(digits) > 2 && digits[0] == '0' && strings.ContainsRune("xXoObB", rune(digits[1])) {
		digits = digits[2:]
	}

	return strings.Trim(digits, "0") != ""
}
