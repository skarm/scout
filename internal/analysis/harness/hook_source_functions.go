package harness

import (
	"reflect"
	"slices"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

type hookSourceFunction struct {
	entry  *entry
	view   source.View
	body   *shellsyntax.File
	scope  source.Span
	path   string
	chains [][]report.SourceRef
}

func (f hookSourceFunction) same(other hookSourceFunction) bool {
	return f.entry == other.entry && f.scope == other.scope
}

func (f hookSourceFunction) merge(other hookSourceFunction) (hookSourceFunction, bool) {
	chains := f.chains
	for _, candidate := range other.chains {
		if slices.ContainsFunc(chains, func(chain []report.SourceRef) bool { return slices.Equal(chain, candidate) }) {
			continue
		}

		if len(chains) == maxHookFunctionOrigins {
			return f, false
		}

		chains = append(chains[:len(chains):len(chains)], candidate)
	}

	f.chains = chains

	return f, true
}

const (
	maxHookFunctionOrigins = 8
	maxHookFunctionChoices = 4
	maxHookFunctionChain   = 2 * maxHookSourceDepth
)

func joinHookFunctionChoices(first, second []hookSourceFunction) []hookSourceFunction {
	if len(first) == 0 || len(second) == 0 {
		return nil
	}

	merged := slices.Clone(first)
	for _, other := range second {
		index := slices.IndexFunc(merged, other.same)
		if index >= 0 {
			definition, ok := merged[index].merge(other)
			if !ok {
				return nil
			}

			merged[index] = definition

			continue
		}

		if len(merged) == maxHookFunctionChoices {
			return nil
		}

		merged = append(merged, other)
	}

	return merged
}

func (w *hookSourceWalk) defineFunction(e *entry, view source.View, cmd *shellsyntax.Command, chain []report.SourceRef, state *hookSourceState) {
	scope, err := view.Original(cmd.Span)
	if err != nil {
		return
	}

	if state.functions == nil {
		state.functions = make(map[string][]hookSourceFunction)
	}

	state.functions[cmd.FunctionName] = []hookSourceFunction{{entry: e, view: view, body: cmd.FunctionBody, scope: scope, path: state.sourcePath, chains: [][]report.SourceRef{chain}}}
}

func (w *hookSourceWalk) callFunctions(e *entry, view source.View, cmd *shellsyntax.Command, name string, chain []report.SourceRef, state *hookSourceState) bool {
	definitions := state.functions[name]

	switch len(definitions) {
	case 0:
		w.commandGap(e, view, cmd.Span, "hook_source_function_unverified", "Shell branches leave the function called here ambiguous.")

		*state = state.blockTrace()

		return false
	case 1:
		return w.callFunction(e, view, cmd, definitions[0], chain, state)
	}

	var merged *hookSourceState

	for _, definition := range definitions {
		next := state.clone()
		if next.traceBlocked {
			*state = next
			return false
		}

		next.functions[name] = []hookSourceFunction{definition}
		w.callFunction(e, view, cmd, definition, chain, &next)
		merged = mergeHookPath(merged, next)
	}

	*state = *merged

	return !state.exited && !state.traceBlocked
}

func (w *hookSourceWalk) callFunction(e *entry, view source.View, cmd *shellsyntax.Command, fn hookSourceFunction, chain []report.SourceRef, state *hookSourceState) bool {
	if fn.body == nil {
		w.commandGap(e, view, cmd.Span, "hook_source_function_unverified", "The shell function call could not be resolved statically.")

		*state = state.blockTrace()

		return false
	}

	span, err := view.Original(cmd.Span)
	if err != nil {
		*state = state.blockTrace()
		return false
	}

	at := ref(e, span)
	if at == nil {
		*state = state.blockTrace()
		return false
	}

	args := w.arguments(cmd.Words[1:], *state)
	key := fn.scopeKey(args)

	if w.activeFunctions[key] {
		w.gap(*at, "hook_source_cycle", "A cycle was found in local shell function calls.")

		*state = state.blockTrace()

		return false
	}

	var merged *hookSourceState

	for _, definition := range fn.chains {
		steps := hookFunctionChain(definition, chain, *at)
		// The source chain includes the imports that established each
		// definition, which may be longer than the active call stack.
		if len(w.activeFunctions) >= maxHookSourceDepth || len(steps) > maxHookFunctionChain ||
			len(w.plugin.b.hookSourcePaths) >= w.plugin.b.r.Limits.References {
			w.gap(*at, "hook_source_limit", "The shell source path budget was exhausted.")

			merged = mergeHookPath(merged, state.blockTrace())

			break
		}

		next := w.followFunction(fn, *state, steps, args, key)
		merged = mergeHookPath(merged, next)
	}

	if merged != nil {
		*state = *merged
		return !state.exited && !state.traceBlocked
	}

	*state = state.blockTrace()

	return false
}

func (w *hookSourceWalk) applyReadCallbackLoop(e *entry, view source.View, cmd *shellsyntax.Command, readNames []string, state *hookSourceState, chain []report.SourceRef) bool {
	body := cmd.Alternatives[0]
	name := hookReadCallbackName(body)

	if _, known := state.singleFunction(name); name == "" || !known {
		return false
	}

	return w.traceLoopInvariant(e, view, cmd, body, readNames, state, chain)
}

func (w *hookSourceWalk) traceLoopInvariant(e *entry, view source.View, cmd *shellsyntax.Command, body *shellsyntax.File, names []string, state *hookSourceState, chain []report.SourceRef, fixedBuiltins ...string) bool {
	if !state.explicitBash || w.tracingLoop {
		return false
	}

	w.tracingLoop = true
	defer func() { w.tracingLoop = false }()

	w.traceSubstitutions(e, view, cmd, *state, chain)

	invariant := state.clone()
	invariant.forgetIterationValues(names)

	// Join the zero-iteration state with successive body effects.
	// Accept the summary only when another iteration can no longer
	// change its bindings, including the values read by the next test.
	for range 4 {
		if invariant.lookupUnknown || cmd.Prelude != nil && invariant.hasFunction("read") {
			return false
		}

		if cmd.Prelude != nil {
			w.traceReadLoopBody(e, view, cmd.Prelude, invariant, chain)
		}

		next := w.commands(e, view, body, invariant.clone(), chain, false)
		if next.traceBlocked || slices.ContainsFunc(fixedBuiltins, next.hasFunction) {
			return false
		}

		next = invariant.clone().join(next)
		next.forgetIterationValues(names)

		if reflect.DeepEqual(next, invariant) {
			*state = next
			return true
		}

		invariant = next
	}

	return false
}

func (s *hookSourceState) forgetIterationValues(names []string) {
	for _, name := range names {
		s.bindValue(name, "", false)
	}
}

func hookReadCallbackName(body *shellsyntax.File) string {
	if len(body.Statements) != 1 {
		return ""
	}

	stmt := body.Statements[0]
	if stmt.Background || stmt.Negated || hookAndOrLink(stmt.Next) || len(stmt.Commands) != 1 {
		return ""
	}

	cmd := stmt.Commands[0]
	if len(cmd.Words) == 0 || len(cmd.Assignments) != 0 || len(cmd.Redirects) != 0 || hookCommandWritesDuringExpansion(cmd) {
		return ""
	}

	name, _ := cmd.Words[0].Literal()

	return name
}

type hookFunctionKey struct {
	path, firstArgument string
	scope               source.Span
}

func (f hookSourceFunction) scopeKey(args hookSourceArguments) hookFunctionKey {
	key := hookFunctionKey{path: f.entry.meta.Path, scope: f.scope}

	// A constant first argument can select a different action in a recursive
	// dispatcher. A repeated argument still counts as a cycle, and changing
	// arguments still use the same call-depth and reference budgets.
	if len(args.values) > 0 && args.values[0].known {
		key.firstArgument = args.values[0].value
	}

	return key
}

func (w *hookSourceWalk) followFunction(fn hookSourceFunction, state hookSourceState, steps []report.SourceRef, arguments hookSourceArguments, key hookFunctionKey) hookSourceState {
	b := w.plugin.b

	b.hookSourcePaths = append(b.hookSourcePaths, HookSourcePath{
		Target: fn.entry.meta.Path, Event: w.event, HostOutput: state.hookOutput,
		Steps: steps, Scope: fn.scope, Exclude: hookFunctionSpans(fn.view, fn.body),
	})
	if w.activeFunctions == nil {
		w.activeFunctions = make(map[hookFunctionKey]bool)
	}

	w.activeFunctions[key] = true

	body := fn.body
	if len(body.Statements) == 1 {
		stmt := body.Statements[0]
		if !stmt.Negated && len(stmt.Commands) == 1 && stmt.Commands[0].Group != nil && len(stmt.Commands[0].Redirects) == 0 {
			body = stmt.Commands[0].Group
		}
	}

	child := state.child()
	child.canReturn, child.positional = true, arguments
	child.sourcePath = fn.path
	child.locals = make(map[string]hookSourceLocal)
	next := w.commands(fn.entry, fn.view, body, child, steps, false).resume(state)
	next.restoreLocals(state.locals)
	next.canReturn, next.positional = state.canReturn, state.positional
	next.sourcePath = state.sourcePath

	delete(w.activeFunctions, key)

	return next
}

// Preserve both the definition's import path and the caller's path. They may
// share a prefix or the definition may have been imported from another file.
func hookFunctionChain(definition, caller []report.SourceRef, at report.SourceRef) []report.SourceRef {
	common := 0
	for common < min(len(definition), len(caller)) && definition[common] == caller[common] {
		common++
	}

	steps := make([]report.SourceRef, 0, len(definition)+len(caller)-common+1)
	steps = append(steps, definition...)
	steps = append(steps, caller[common:]...)

	return append(steps, at)
}

func hookFunctionSpans(view source.View, tree *shellsyntax.File) []source.Span {
	var (
		spans []source.Span
		walk  func(*shellsyntax.File)
	)

	walk = func(file *shellsyntax.File) {
		if file == nil {
			return
		}

		for _, stmt := range file.Statements {
			for _, cmd := range stmt.Commands {
				if cmd.FunctionBody != nil {
					if span, err := view.Original(cmd.Span); err == nil {
						spans = append(spans, span)
					}

					continue
				}

				walk(cmd.Group)
				walk(cmd.Prelude)
				walk(cmd.Subshell)

				for _, alt := range cmd.Alternatives {
					walk(alt)
				}
			}
		}
	}
	walk(tree)
	slices.SortFunc(spans, func(a, b source.Span) int { return a.Start - b.Start })

	return spans
}
