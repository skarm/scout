package document

import "iter"

// TypedUnit retains the preparation metadata and source view alongside the
// matching backend tree. Querying one backend never reparses or coerces units.
type TypedUnit[T any] struct {
	Unit
	Tree T
}

// ParsedUnits iterates the prepared units with the requested tree type.
func ParsedUnits[T any](doc File) iter.Seq[TypedUnit[T]] {
	return func(yield func(TypedUnit[T]) bool) {
		for _, unit := range doc.Units() {
			if tree, ok := unit.Tree.(T); ok && !yield(TypedUnit[T]{Unit: unit, Tree: tree}) {
				return
			}
		}
	}
}

// HasParsedUnit reports whether a prepared unit has the requested tree type.
func HasParsedUnit[T any](doc File) bool {
	for range ParsedUnits[T](doc) {
		return true
	}

	return false
}
