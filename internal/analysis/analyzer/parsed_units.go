package analyzer

import (
	"iter"

	"github.com/skarm/scout/internal/analysis/document"
)

// typedUnit retains the preparation metadata and source view alongside the
// matching backend tree. Querying one backend never reparses or coerces units.
type typedUnit[T any] struct {
	document.Unit
	tree T
}

func parsedUnits[T any](doc document.File) iter.Seq[typedUnit[T]] {
	return func(yield func(typedUnit[T]) bool) {
		for _, unit := range doc.Units() {
			if tree, ok := unit.Tree.(T); ok && !yield(typedUnit[T]{Unit: unit, tree: tree}) {
				return
			}
		}
	}
}

func hasParsedUnit[T any](doc document.File) bool {
	for range parsedUnits[T](doc) {
		return true
	}

	return false
}
