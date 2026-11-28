package hooktrace

import "github.com/skarm/scout/internal/syntax/shellsyntax"

const maxHookLocals = 128

type hookSourceLocal struct {
	shadowed hookSourceArgument
	maybe    bool // only some paths declared the local
}

func (w *hookSourceWalk) bindShellDeclaration(cmd *shellsyntax.Command, state *hookSourceState) bool {
	switch cmd.Declaration {
	case "local":
		return w.bindLocals(cmd, state)
	case "readonly":
		return w.bindReadonly(cmd, state)
	default:
		return false
	}
}

// Only bare scalar initializers are modeled. Later writes to a possibly
// locked name must not be used as facts, even if execution continues.
func (w *hookSourceWalk) bindReadonly(cmd *shellsyntax.Command, state *hookSourceState) bool {
	if state.lookupUnknown || state.hasFunction("readonly") || len(cmd.DeclarationArgs) != 0 ||
		len(state.readonly)+len(cmd.Assignments) > maxHookLocals {
		return false
	}

	root := pluginRootParameters[w.scope.Host]

	names := make(map[string]bool, len(cmd.Assignments))
	for _, assignment := range cmd.Assignments {
		if _, literal := assignment.Value.Literal(); !literal || names[assignment.Name] ||
			state.readonly[assignment.Name] || !hookLocalVariable(assignment.Name, root) {
			return false
		}

		names[assignment.Name] = true
	}

	w.bind(cmd, state)

	if state.readonly == nil {
		state.readonly = names
	} else {
		for name := range names {
			state.readonly[name] = true
		}
	}

	return true
}

func (w *hookSourceWalk) bindLocals(cmd *shellsyntax.Command, state *hookSourceState) bool {
	if !w.canBindLocals(cmd, *state) {
		return false
	}

	// All initializers expand against the bindings before the declaration.
	values := make([]struct {
		arg  hookSourceArgument
		kind hookVariableKind
	}, len(cmd.Assignments))

	for i, assignment := range cmd.Assignments {
		values[i].arg.value, values[i].arg.known = w.value(assignment.Value, *state, true)
		values[i].kind = w.assignmentKind(assignment.Value, *state)
	}

	for i, assignment := range cmd.Assignments {
		state.declareLocal(assignment.Name, assignment.Value != nil, values[i].arg)

		if values[i].kind != 0 {
			state.markAssignmentKind(assignment, values[i].kind)
		}
	}

	return true
}

func (w *hookSourceWalk) canBindLocals(cmd *shellsyntax.Command, state hookSourceState) bool {
	if state.locals == nil || state.lookupUnknown || state.hasFunction("local") ||
		cmd.ComplexLocal || len(state.locals)+len(cmd.Assignments) > maxHookLocals {
		return false
	}

	root := pluginRootParameters[w.scope.Host]
	for _, assignment := range cmd.Assignments {
		if !hookLocalVariable(assignment.Name, root) {
			return false
		}
	}

	return true
}

func hookLocalVariable(name, root string) bool {
	switch name {
	case "DIRSTACK", "EPOCHREALTIME", "EPOCHSECONDS", "EUID", "FUNCNAME", "GROUPS", "LINENO", "PIPESTATUS",
		"PPID", "RANDOM", "SECONDS", "SRANDOM", "UID", "_":
		return false
	default:
		return hookOrdinaryVariable(name, root)
	}
}

func (s *hookSourceState) unsetScalars(words []*shellsyntax.Word, root string) bool {
	if s.lookupUnknown || s.canReturn || len(words) == 0 {
		return false
	}

	for _, word := range words {
		name, known := word.Literal()
		if !known || !hookVariableName(name) || !hookLocalVariable(name, root) || s.hasFunction(name) {
			return false
		}
	}

	for _, word := range words {
		name, _ := word.Literal()
		s.bindValue(name, "", false)
	}

	return true
}

func (s *hookSourceState) declareLocal(name string, initialized bool, value hookSourceArgument) {
	local, exists := s.locals[name]
	switch {
	case !exists:
		local.shadowed.value, local.shadowed.known = s.vars[name]
	case local.maybe:
		// Some paths may have assigned to the outer variable since the join.
		local.shadowed = hookSourceArgument{}
		local.maybe = false
	case !initialized:
		return // a bare redeclaration keeps the existing local value
	}

	s.locals[name] = local
	s.bindValue(name, value.value, value.known)
}

func (s *hookSourceState) joinLocals(other hookSourceState) {
	if s.lookupUnknown || s.locals == nil || other.locals == nil {
		s.locals = nil
		return
	}

	for name, local := range s.locals {
		next, exists := other.locals[name]
		if local.shadowed != next.shadowed {
			local.shadowed = hookSourceArgument{}
		}

		local.maybe = local.maybe || next.maybe || !exists
		s.locals[name] = local
	}

	for name := range other.locals {
		if _, exists := s.locals[name]; !exists {
			s.locals[name] = hookSourceLocal{maybe: true}
		}
	}
}

func (s *hookSourceState) restoreLocals(caller map[string]hookSourceLocal) {
	if s.lookupUnknown {
		s.locals = nil
		return
	}

	for name, local := range s.locals {
		s.bindValue(name, local.shadowed.value, !local.maybe && local.shadowed.known)
	}

	s.locals = caller
}
