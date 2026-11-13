package harness

import (
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

const maxHookFunctionOrigins = 8

func (w *hookSourceWalk) defineFunction(e *entry, view source.View, cmd *shellsyntax.Command, chain []report.SourceRef, state *hookSourceState) {
	scope, err := view.Original(cmd.Span)
	if err != nil {
		return
	}

	if state.functions == nil {
		state.functions = make(map[string]hookSourceFunction)
	}

	delete(state.ambiguousFunctions, cmd.FunctionName)
	state.functions[cmd.FunctionName] = hookSourceFunction{entry: e, view: view, body: cmd.FunctionBody, scope: scope, chains: [][]report.SourceRef{chain}}
}

func (w *hookSourceWalk) callFunction(e *entry, view source.View, cmd *shellsyntax.Command, fn hookSourceFunction, chain []report.SourceRef, state *hookSourceState) bool {
	if fn.body == nil || hookSourceHasRuntimeExpansion(cmd) {
		w.commandGap(e, view, cmd.Span, "hook_source_function_unverified", "The shell function call could not be resolved statically.")

		*state = state.opaque()

		return false
	}

	span, err := view.Original(cmd.Span)
	if err != nil {
		*state = state.opaque()
		return false
	}

	at := ref(e, span)
	if at == nil {
		*state = state.opaque()
		return false
	}

	if w.activeFunctions[fn.scopeKey()] {
		w.gap(*at, "hook_source_cycle", "A cycle was found in local shell function calls.")

		*state = state.opaque()

		return false
	}

	var merged *hookSourceState

	for _, definition := range fn.chains {
		steps := hookFunctionChain(definition, chain, *at)
		if len(steps) > maxHookSourceDepth || len(w.plugin.b.hookSourcePaths) >= w.plugin.b.r.Limits.References {
			w.gap(*at, "hook_source_limit", "The shell source path budget was exhausted.")

			merged = mergeHookPath(merged, state.opaque())

			break
		}

		next := w.followFunction(fn, *state, steps, w.arguments(cmd.Words[1:], *state))
		merged = mergeHookPath(merged, next)
	}

	if merged != nil {
		*state = *merged
		return !state.exited
	}

	*state = state.opaque()

	return false
}

type hookFunctionKey struct {
	path  string
	scope source.Span
}

func (f hookSourceFunction) scopeKey() hookFunctionKey {
	return hookFunctionKey{path: f.entry.meta.Path, scope: f.scope}
}

func (w *hookSourceWalk) followFunction(fn hookSourceFunction, state hookSourceState, steps []report.SourceRef, arguments []hookSourceArgument) hookSourceState {
	b := w.plugin.b

	b.hookSourcePaths = append(b.hookSourcePaths, HookSourcePath{
		Target: fn.entry.meta.Path, Event: w.event, Steps: steps, Scope: fn.scope, Exclude: hookFunctionSpans(fn.view, fn.body),
	})
	if w.activeFunctions == nil {
		w.activeFunctions = make(map[hookFunctionKey]bool)
	}

	key := fn.scopeKey()
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
	next := w.commands(fn.entry, fn.view, body, child, steps, false).resume(state)
	next.canReturn, next.positional = state.canReturn, state.positional

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
