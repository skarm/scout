package python

import (
	"maps"
	"slices"

	"github.com/skarm/scout/internal/syntax/frontend"
)

// 0 unknown, 1 definitely false, 2 definitely true. No Python code is evaluated.
func pyTruth(n *frontend.Node, s *pyState, depth int) uint8 {
	if n == nil || depth > 32 {
		return 0
	}

	switch n.Kind() {
	case frontend.Name:
		v, _ := s.lookup(n.String(frontend.ID))
		return v.truth
	case frontend.Constant:
		return pyConstantTruth(n)
	case frontend.List, frontend.Tuple, frontend.Set:
		return pyContainerTruth(n.List(frontend.Elts), false)
	case frontend.Dict:
		return pyContainerTruth(n.List(frontend.Keys), true)
	case frontend.UnaryOp:
		return pyUnaryTruth(n, s, depth)
	default:
		return 0
	}
}

func pyContainerTruth(nodes []*frontend.Node, dictionary bool) uint8 {
	for _, n := range nodes {
		if dictionary && n == nil {
			return 0
		}

		if !dictionary && n.Kind() == frontend.Starred {
			return 0
		}
	}

	return knownTruth(len(nodes) > 0)
}

func pyUnaryTruth(n *frontend.Node, s *pyState, depth int) uint8 {
	v := pyTruth(n.Child(frontend.Operand), s, depth+1)
	switch n.String(frontend.Op) {
	case "Not":
		return map[uint8]uint8{0: 0, 1: 2, 2: 1}[v]
	case "USub", "UAdd":
		return v
	default:
		return 0
	}
}

func knownTruth(yes bool) uint8 {
	if yes {
		return 2
	}

	return 1
}

func pyConstantTruth(n *frontend.Node) uint8 {
	if numeric, ok := n.Field(frontend.NumericTruth).Boolean(); ok {
		return knownTruth(numeric)
	}

	if unknown, ok := n.Field(frontend.NumericUnknown).Boolean(); ok && unknown {
		return 0
	}

	v, exists := n.Value(frontend.FieldValue)
	if !exists {
		return 0
	}

	return pyScalarTruth(v)
}

func pyScalarTruth(v frontend.Value) uint8 {
	switch v.Kind() {
	case frontend.ValueNull:
		return 1
	case frontend.ValueBool:
		x, _ := v.Boolean()
		return knownTruth(x)
	case frontend.ValueString:
		x, _ := v.Text()
		return knownTruth(x != "")
	case frontend.ValueInteger:
		x, _ := v.Integer()
		return knownTruth(x != 0)
	case frontend.ValueNumber:
		x, _ := v.Number()

		n, err := x.Float64()
		if err != nil {
			return 0
		}

		return knownTruth(n != 0)
	default:
		return 0
	}
}

func pyHandlerOrigins(v pyValue, depth int, seen map[*pyInstance]bool) pyValue {
	out := joinPy(v)
	if depth > 8 || v.instance() == nil || seen[v.instance()] {
		return out
	}

	seen[v.instance()] = true

	keys := slices.Sorted(maps.Keys(v.instance().fields))

	for _, key := range keys {
		out = joinPy(out, pyHandlerOrigins(v.instance().fields[key], depth+1, seen))
	}

	return out
}
