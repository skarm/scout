package shell

import (
	"context"
	"maps"
	"slices"
	"strconv"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

type generatedFunctionScan struct {
	definitions []generatedFunctionDefinition
	shadows     scriptWriterAliases
	declared    map[*shellsyntax.File]scriptEffects
	called      map[*shellsyntax.File]bool
	active      map[*shellsyntax.File]bool
	projections map[*shellsyntax.Redirect][]source.View
	steps       int
	fallback    bool
	opaque      bool
}

type generatedFunctionDefinition struct {
	name string
	body *shellsyntax.File
}

type functionReturnState struct {
	scope *scriptScope
}

func (r *functionReturnState) add(scope *scriptScope) {
	if r.scope == nil {
		snapshot := scope.nested()
		r.scope = &snapshot

		return
	}

	r.scope.mergeAlternativeFunctionState(scope)
}

func newGeneratedFunctionScan(root *shellsyntax.File) generatedFunctionScan {
	var f generatedFunctionScan
	f.collect(root)

	if len(f.definitions) != 0 {
		f.declared = make(map[*shellsyntax.File]scriptEffects)
		f.called = make(map[*shellsyntax.File]bool)
		f.active = make(map[*shellsyntax.File]bool)
		f.projections = make(map[*shellsyntax.Redirect][]source.View)
	}

	return f
}

func (f *generatedFunctionScan) collect(tree *shellsyntax.File) {
	if tree == nil {
		return
	}

	for _, stmt := range tree.Statements {
		for _, c := range stmt.Commands {
			if c.FunctionName != "" && c.FunctionBody != nil {
				f.definitions = append(f.definitions, generatedFunctionDefinition{c.FunctionName, c.FunctionBody})
				f.shadows.define(c.FunctionName)
			}

			f.collect(c.Group)
			f.collect(c.Prelude)

			for _, branch := range c.Alternatives {
				f.collect(branch)
			}

			for child := range scriptIsolatedTrees(c) {
				f.collect(child)
			}
		}
	}
}

func (f *generatedFunctionScan) define(c *shellsyntax.Command, scope *scriptScope, stable bool) {
	name, body := c.FunctionName, c.FunctionBody
	if name == "" || body == nil {
		return
	}

	scope.shadow.define(name)

	effects := f.declared[body]
	effects.merge(scope.scriptEffects)
	f.declared[body] = effects

	if !stable || scope.conditionalDefs {
		body = nil
	}

	scope.setFunction(name, body)
}

func (f *generatedFunctionScan) step(ctx context.Context) bool {
	if f.steps >= MaxShellOperations || !analysisbudget.Consume(ctx, 1) {
		return false
	}

	f.steps++

	return true
}

func (f *generatedFunctionScan) hasProjection(hdoc *shellsyntax.Redirect, view source.View) bool {
	return slices.ContainsFunc(f.projections[hdoc], view.SameProjection)
}

func (s *scriptScope) nested() scriptScope {
	return scriptScope{
		variables: maps.Clone(s.variables), functions: maps.Clone(s.functions), aliases: maps.Clone(s.aliases),
		functionBody: s.functionBody, repeated: s.repeated, stdoutPiped: s.stdoutPiped,
		temporaryPath: s.temporaryPath, temporaryCDPath: s.temporaryCDPath, scriptEffects: s.scriptEffects,
	}
}

func (s *scriptScope) setFunction(name string, body *shellsyntax.File) {
	if _, tracked := s.functions[name]; !tracked && len(s.functions) >= MaxShellBindings {
		s.unknown()
		return
	}

	if s.functions == nil {
		s.functions = make(map[string]*shellsyntax.File)
	}

	s.functions[name] = body
}

func (s *scriptScope) mergePossibleFunctionState(nested *scriptScope) {
	s.merge(nested.scriptEffects)

	for alias := range nested.aliases {
		if !s.aliases[alias] {
			s.rememberAlias(alias)
		}
	}

	for name, definition := range nested.functions {
		if prior, exists := s.functions[name]; !exists || prior != definition {
			s.setFunction(name, nil)
		}
	}
}

func (s *scriptScope) mergeAlternativeFunctionState(other *scriptScope) {
	s.mergePossibleFunctionState(other)

	for name := range s.functions {
		if _, exists := other.functions[name]; !exists {
			s.functions[name] = nil
		}
	}
}

func (s *scriptScope) rememberAlias(name string) {
	if len(s.aliases) >= MaxShellBindings {
		s.aliasUnsafe = true
		return
	}

	if s.aliases == nil {
		s.aliases = make(map[string]bool)
	}

	s.aliases[name] = true
}

func (s *scriptScope) mayAlias(word *shellsyntax.Word, name string) bool {
	return !word.Quoted && (s.aliasUnsafe || s.aliases[name])
}

func (s *scriptScope) unsetFunctions(args []*shellsyntax.Word) {
	if len(args) == 0 || literalWordEquals(args[0], "-v") {
		return
	}

	for _, arg := range args {
		name, literal := arg.Literal()
		if !literal {
			for key := range s.functions {
				s.functions[key] = nil
			}

			return
		}

		if _, exists := s.functions[name]; exists {
			s.functions[name] = nil
		}
	}
}

func (s *scriptScope) localFunctionCall(c *shellsyntax.Command) *shellsyntax.File {
	if len(s.functions) == 0 || s.trapUnsafe || s.repeated || len(c.Words) == 0 || len(c.Redirects) != 0 {
		return nil
	}

	name, literal := c.Words[0].Literal()
	if !literal || s.mayAlias(c.Words[0], name) || s.functions[name] == nil {
		return nil
	}

	for _, arg := range c.Words[1:] {
		if _, known := arg.Literal(); !known {
			return nil
		}
	}

	for _, assignment := range c.Assignments {
		if !staticScriptVariable(assignment.Name) || assignment.Value == nil || assignment.Value.Expands || generatedWordRunsCode(assignment.Value) {
			return nil
		}
	}

	return s.functions[name]
}

func (s *scriptScope) applyFunctionAssignments(assignments []shellsyntax.Assignment) {
	for _, assignment := range assignments {
		name := assignment.Name
		s.temporaryPath = s.temporaryPath || name == "PATH"
		s.temporaryCDPath = s.temporaryCDPath || name == "CDPATH"
		value, known := sourceWord(assignment.Value, s.variables)

		if !s.bindingsUnsafe && known && len(s.variables) < MaxShellBindings {
			s.variables[name] = value
		} else {
			delete(s.variables, name)
		}
	}
}

func (s *scriptScope) plainFunctionReturn(c *shellsyntax.Command) bool {
	if s.conditionalDefs || s.trapUnsafe || len(c.Words) == 0 || len(c.Words) > 2 || len(c.Assignments) != 0 || len(c.Redirects) != 0 {
		return false
	}

	if _, shadowed := s.functions["return"]; shadowed || !literalWordEquals(c.Words[0], "return") || s.mayAlias(c.Words[0], "return") {
		return false
	}

	if len(c.Words) == 1 {
		return true
	}

	value, _ := c.Words[1].Literal()
	_, err := strconv.Atoi(value)

	return err == nil
}

func (s *generatedShellScan) callFunction(c *shellsyntax.Command, body *shellsyntax.File, scope *scriptScope, stdoutPiped, stable bool) bool {
	f := &s.functions
	if f.active[body] || len(f.active) >= shellsyntax.MaxDepth {
		s.gaps |= document.GeneratedShellUnrecovered

		scope.unknown()

		f.opaque = f.opaque || !f.fallback

		return true
	}

	if !f.fallback {
		f.called[body] = true
	}

	f.active[body] = true
	nested := scope.nested()
	nested.stdoutPiped = nested.stdoutPiped || stdoutPiped
	nested.applyFunctionAssignments(c.Assignments)
	more := s.walkFunctionBody(body, &nested)
	delete(f.active, body)

	if stable && !scope.conditionalDefs {
		scope.merge(nested.scriptEffects)
		scope.aliases = nested.aliases
		scope.functions = nested.functions
	} else {
		scope.mergePossibleFunctionState(&nested)
	}

	return more
}

func (s *generatedShellScan) walkFunctionBody(body *shellsyntax.File, scope *scriptScope) bool {
	// Return branches contribute their effects to the caller, while the
	// remaining body sees only the branches that can continue.
	var exits functionReturnState

	scope.functionBody = true
	scope.returnEffects = &exits

	more := s.walk(body, scope, nil)
	if exits.scope != nil {
		scope.mergeAlternativeFunctionState(exits.scope)
	}

	return more
}

// Uncalled declarations remain analyzable under conservative file-wide
// effects. An opaque command may also invoke a previously observed function.
func (s *generatedShellScan) walkFunctions(scope *scriptScope) bool {
	f := &s.functions
	f.fallback = true
	possible := scriptScope{}

	for _, definition := range f.definitions {
		var body *shellsyntax.File
		if _, duplicate := possible.functions[definition.name]; !duplicate && scope.functions[definition.name] == definition.body {
			body = definition.body
		}

		possible.setFunction(definition.name, body)
	}

	for _, definition := range f.definitions {
		if f.called[definition.body] && !scope.trapUnsafe && !f.opaque {
			continue
		}

		effects := scope.scriptEffects
		effects.merge(possible.scriptEffects)
		effects.merge(f.declared[definition.body])
		effects.shadow.merge(f.shadows)

		if f.opaque {
			effects.unknown()
		}

		nested := scriptScope{
			variables: map[string]string{}, functions: maps.Clone(possible.functions), aliases: maps.Clone(scope.aliases),
			scriptEffects: effects,
		}
		f.active[definition.body] = true
		more := s.walkFunctionBody(definition.body, &nested)
		delete(f.active, definition.body)

		if !more {
			return false
		}
	}

	return true
}
