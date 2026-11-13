package harness

import (
	"maps"
	"slices"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func (s hookSourceState) clone() hookSourceState {
	s.vars = maps.Clone(s.vars)
	s.functions = maps.Clone(s.functions)
	s.ambiguousFunctions = maps.Clone(s.ambiguousFunctions)

	return s
}

func (s hookSourceState) child() hookSourceState {
	s = s.clone()
	s.returned, s.returns = false, nil

	return s
}

func (s hookSourceState) resume(caller hookSourceState) hookSourceState {
	if s.returns != nil {
		if s.exited {
			s = s.returns.clone()
		} else {
			s = s.joinBindings(*s.returns)
		}
	}

	s.returned, s.returns = false, caller.returns

	return s
}

func (s hookSourceState) join(other hookSourceState) hookSourceState {
	returns := s.returns
	if other.returns != nil && other.returns != returns {
		returns = mergeHookReturn(returns, other.returns.clone())
	}

	s.returns, other.returns = returns, returns
	switch {
	case s.exited != other.exited:
		if s.exited {
			return other
		}

		return s
	case s.returned != other.returned:
		if s.returned {
			s, other = other, s
		}

		s.returns = mergeHookReturn(returns, other)

		return s
	default:
		return s.joinBindings(other)
	}
}

func mergeHookReturn(previous *hookSourceState, next hookSourceState) *hookSourceState {
	next.returns = nil
	if previous != nil {
		next = next.joinBindings(*previous)
	}

	return &next
}

func (s hookSourceState) joinBindings(other hookSourceState) hookSourceState {
	if s.cwd != other.cwd {
		s.cwd = ""
	}

	if !slices.Equal(s.positional, other.positional) {
		s.positional = nil
	}

	s.lookupUnknown = s.lookupUnknown || other.lookupUnknown

	s.rootUnknown = s.rootUnknown || other.rootUnknown
	for key, value := range s.vars {
		if next, ok := other.vars[key]; !ok || next != value {
			delete(s.vars, key)
		}
	}

	s.joinFunctions(other)

	return s
}

func (s *hookSourceState) joinFunctions(other hookSourceState) {
	for name := range other.ambiguousFunctions {
		s.markAmbiguousFunction(name)
	}

	for name, fn := range s.functions {
		next := other.functions[name]
		if fn.same(next) {
			if merged, ok := fn.merge(next); ok {
				s.functions[name] = merged
				continue
			}
		}

		s.markAmbiguousFunction(name)
	}

	for name := range other.functions {
		if _, ok := s.functions[name]; !ok {
			s.markAmbiguousFunction(name)
		}
	}
}

func (s *hookSourceState) markAmbiguousFunction(name string) {
	if s.ambiguousFunctions == nil {
		s.ambiguousFunctions = make(map[string]bool)
	}

	s.ambiguousFunctions[name] = true
	delete(s.functions, name)
}

func (s hookSourceState) hasFunction(name string) bool {
	_, defined := s.functions[name]
	return defined || s.ambiguousFunctions[name]
}

func mergeHookPath(previous *hookSourceState, state hookSourceState) *hookSourceState {
	if previous != nil {
		state = state.join(*previous)
	}

	return &state
}

func hookAndOrLink(next string) bool {
	return next == "&&" || next == "||"
}

func hookAndOrEnd(stmts []*shellsyntax.Statement) int {
	end := 0
	for end+1 < len(stmts) && hookAndOrLink(stmts[end].Next) {
		end++
	}

	return end
}

type hookOutcomes struct {
	success, failure, stopped *hookSourceState
}

func (o hookOutcomes) merged() *hookSourceState {
	merged := o.stopped
	if o.success != nil {
		merged = mergeHookPath(merged, *o.success)
	}

	if o.failure != nil {
		merged = mergeHookPath(merged, *o.failure)
	}

	return merged
}

// The shell evaluates && and || left to right. A bypassed operand retains
// the status and bindings of the last command actually evaluated on that path.
func (w *hookSourceWalk) andOr(e *entry, view source.View, stmts []*shellsyntax.Statement, state hookSourceState, chain []report.SourceRef, entrypoint bool) hookOutcomes {
	out := hookOutcomes{success: &state}
	link := "&&"

	for _, stmt := range stmts {
		active := &out.success
		if link == "||" {
			active = &out.failure
		}

		link = stmt.Next

		if *active == nil {
			continue
		}

		current := **active
		*active = nil

		if !w.plugin.b.step() {
			out.stopped = mergeHookPath(out.stopped, current.opaque())
			break
		}

		w.routeOperand(e, view, stmt, current, chain, entrypoint, &out)
	}

	return out
}

func (w *hookSourceWalk) routeOperand(e *entry, view source.View, stmt *shellsyntax.Statement, state hookSourceState, chain []report.SourceRef, entrypoint bool, out *hookOutcomes) {
	next := state.clone()
	if hookKnownStatus(stmt, state, "cd") && !hookCommandWritesDuringExpansion(stmt.Commands[0]) {
		next.changeDirectory(w.directory(stmt.Commands[0].Words[1:], state))
		out.success = mergeHookPath(out.success, next)
		out.failure = mergeHookPath(out.failure, state)

		return
	}

	if !w.statement(e, view, stmt, chain, entrypoint, &next) {
		out.stopped = mergeHookPath(out.stopped, next)
		return
	}

	if !hookKnownStatus(stmt, state, "false") {
		out.success = mergeHookPath(out.success, next.clone())
	}

	switch {
	case hookKnownStatus(stmt, state, "true"), hookKnownStatus(stmt, state, ":"):
	default:
		out.failure = mergeHookPath(out.failure, next)
	}
}

func simpleHookCommand(stmt *shellsyntax.Statement, name string) bool {
	if stmt.Negated || len(stmt.Commands) != 1 {
		return false
	}

	cmd := stmt.Commands[0]
	if len(cmd.Words) == 0 || len(cmd.Assignments) != 0 || len(cmd.Redirects) != 0 {
		return false
	}

	head, _ := cmd.Words[0].Literal()

	return head == name && (name == "cd" || len(cmd.Words) == 1)
}

func hookKnownStatus(stmt *shellsyntax.Statement, state hookSourceState, name string) bool {
	return !state.lookupUnknown && !state.hasFunction(name) && !stmt.Background && stmt.Next != "&" && simpleHookCommand(stmt, name)
}

func (w *hookSourceWalk) conditional(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef, entrypoint bool) hookSourceState {
	if len(cmd.Alternatives) != 2 || cmd.Prelude == nil || len(cmd.Prelude.Statements) == 0 {
		return state.opaque()
	}

	predicate := cmd.Prelude.Statements

	last := len(predicate) - 1
	for last > 0 && hookAndOrLink(predicate[last-1].Next) {
		last--
	}

	state = w.commands(e, view, &shellsyntax.File{Statements: predicate[:last]}, state, chain, entrypoint)
	if state.returned || state.exited {
		return state
	}

	out := w.andOr(e, view, predicate[last:], state, chain, entrypoint)

	merged := out.stopped
	for i, branch := range []*hookSourceState{out.success, out.failure} {
		if branch != nil {
			next := w.commands(e, view, cmd.Alternatives[i], *branch, chain, entrypoint)
			merged = mergeHookPath(merged, next)
		}
	}

	return *merged
}

func (s *hookSourceState) changeDirectory(cwd string) {
	s.cwd = cwd
	delete(s.vars, "PWD")
	delete(s.vars, "OLDPWD")
}
