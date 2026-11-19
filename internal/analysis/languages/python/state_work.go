package python

// State traversal shares the walker's existing quota. It charges entries as
// they are visited, independently of the AST nodes that initiated exploration.
// A nil work counter is used by the standalone, in-package value helpers.
type pyStateWork struct {
	next    func() bool
	stopped bool
}

func (work *pyStateWork) step() bool {
	if work == nil {
		return true
	}

	if work.stopped || !work.next() {
		work.stopped = true
		return false
	}

	return true
}

func (work *pyStateWork) failed() bool { return work != nil && work.stopped }

func copyPyEntries[K comparable, V any](destination, original map[K]V, work *pyStateWork) {
	for key, value := range original {
		if !work.step() {
			return
		}

		destination[key] = value
	}
}

func (w *pyWalker) stateReady() bool {
	if err := w.ctx.Err(); err != nil {
		w.err = err
	}

	return w.err == nil && !w.truncated && !w.facts.exhausted()
}

func (w *pyWalker) stateWork() *pyStateWork {
	return &pyStateWork{next: func() bool { return w.charge(0) }}
}

func (w *pyWalker) contents(value pyValue) pyValue {
	if !w.stateReady() {
		return pyValue{}
	}

	if value.mapping() == nil {
		return value
	}

	return pyContentsWithin(value, w.stateWork())
}

func (w *pyWalker) handlerOrigins(value pyValue) pyValue {
	if !w.stateReady() {
		return pyValue{}
	}

	return pyHandlerOriginsWithin(value, 0, map[*pyInstance]bool{}, w.stateWork())
}

// These callers own a new call/definition scope and do not evaluate or publish
// it unless all selected defaults have been copied. Values intentionally retain
// their aliases in that scope's object store.
func (w *pyWalker) copyDefaults(state *pyState, defaults map[string]pyValue) bool {
	if !w.stateReady() {
		return false
	}

	work := w.stateWork()
	copyPyEntries(state.names, defaults, work)

	return !work.failed()
}

func (w *pyWalker) forkState(original *pyState) *pyState {
	if !w.stateReady() {
		return newPyState()
	}

	work := w.stateWork()

	state := original.forkWithin(work)
	if work.failed() {
		// Callers may still bind parameters before their next AST admission.
		// Give them an empty isolated state, never a partial fork or its parent.
		return newPyState()
	}

	return state
}

type pyMerge struct {
	values map[pyValuePair]pyValue
	work   *pyStateWork
}

func (w *pyWalker) mergeStates(a, b *pyState) *pyState {
	if !w.stateReady() {
		return newPyState()
	}

	work := w.stateWork()

	merged := mergePyWithin(a, b, &pyMerge{values: map[pyValuePair]pyValue{}, work: work})
	if work.failed() {
		return newPyState()
	}

	return merged
}

func (w *pyWalker) mergeBranches(s, a, b *pyState) {
	if w.stateReady() {
		mergePyBranchesWithin(s, a, b, &pyMerge{values: map[pyValuePair]pyValue{}, work: w.stateWork()})
	}
}

func (w *pyWalker) mergeValues(a, b pyValue) pyValue {
	if !w.stateReady() {
		return pyValue{}
	}

	work := w.stateWork()

	merged := mergePyValueMemo(a, b, 0, &pyMerge{values: map[pyValuePair]pyValue{}, work: work})
	if work.failed() {
		return pyValue{}
	}

	return merged
}
