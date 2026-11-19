package harness

import (
	"path"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func (w *hookSourceWalk) hookPathSubstitution(part shellsyntax.Part, state hookSourceState, assignment bool) (string, bool) {
	if part.Tree == nil || state.lookupUnknown || state.rootUnknown || !assignment && !part.Quoted {
		return "", false
	}

	if value, ok := w.hookDirname(part.Tree, state); ok {
		return value, true
	}

	if assignment && hookNotifierLookup(part.Tree, state) {
		return hookNotifierExecutable, true
	}

	stmts := part.Tree.Statements
	if len(stmts) != 2 || stmts[0].Next != shellsyntax.AndThen || !hookKnownStatus(stmts[0], state, "cd") ||
		!hookKnownStatus(stmts[1], state, "pwd") {
		return "", false
	}

	args := stmts[0].Commands[0].Words[1:]
	if len(args) != 1 {
		return "", false
	}

	value, ok := w.value(args[0], state, false)
	if !ok || value != pluginRootValue && !strings.HasPrefix(value, pluginRootMarker) {
		return "", false
	}

	if value == pluginRootValue {
		return value, true
	}

	rel, known := w.capturedHookDirectory(value)
	if !known {
		return "", false
	}

	return path.Join(pluginRootValue, rel), true
}

func (w *hookSourceWalk) hookDirname(tree *shellsyntax.File, state hookSourceState) (string, bool) {
	cmd, simple := simpleShellCommand(tree)
	if !simple || tree.Statements[0].Negated || tree.Statements[0].Background || len(cmd.Words) != 2 ||
		state.hasFunction("dirname") {
		return "", false
	}

	head, _ := cmd.Words[0].Literal()
	if head != "dirname" {
		return "", false
	}

	value, ok := w.value(cmd.Words[1], state, false)
	if !ok || !strings.HasPrefix(value, pluginRootMarker) {
		return "", false
	}

	rel, reason := w.resolveFile(value, "")
	if reason != "" || value != pluginRootMarker+rel {
		return "", false
	}

	return path.Dir(value), true
}

func (w *hookSourceWalk) capturedHookDirectory(value string) (string, bool) {
	// Each entered directory must have evidence in the capture before
	// normalizing .., which otherwise could mask a missing component.
	dir := "."

	for component := range strings.SplitSeq(strings.TrimPrefix(value, pluginRootMarker), "/") {
		switch component {
		case "", ".":
		case "..":
			if dir == "." {
				return "", false
			}

			dir = path.Dir(dir)
		default:
			if _, reason := localPath(component, false); reason != "" {
				return "", false
			}

			dir = path.Join(dir, component)
			if len(w.plugin.ns.descendants(path.Join(w.plugin.root, dir))) == 0 {
				return "", false
			}
		}
	}

	return dir, true
}

func (w *hookSourceWalk) hookTraceableRedirectedLaunch(cmd *shellsyntax.Command, state hookSourceState, entrypoint bool) bool {
	if state.lookupUnknown || len(cmd.Words) == 0 || len(cmd.Assignments) != 0 || len(cmd.Redirects) == 0 {
		return false
	}

	name, known := cmd.Words[0].Literal()
	definitions, function := state.functions[name]
	value, resolved := w.value(cmd.Words[0], state, false)

	if function && len(definitions) == 0 ||
		!(known && (function || hookHasSourceCommand(cmd, entrypoint)) || resolved && hookLocalLaunchPath(value, state.cwd)) {
		return false
	}

	for _, redirect := range cmd.Redirects {
		if !hookDiscardedOutput(redirect) && !(function && hookFunctionRedirect(redirect, state)) {
			return false
		}
	}

	return true
}

func hookFunctionRedirect(r *shellsyntax.Redirect, state hookSourceState) bool {
	return hookFreshTemporaryRedirect(r, state) || r.Op == shellsyntax.RedirectInput && (r.FD == "" || r.FD == shellsyntax.StdinFD) &&
		r.Target != nil && hookTestOperand(r.Target)
}

func hookFreshTemporaryRedirect(r *shellsyntax.Redirect, state hookSourceState) bool {
	if r.Op != shellsyntax.RedirectOutput || r.FD != "" && r.FD != shellsyntax.StdoutFD || r.Target == nil || r.Target.Writes ||
		r.Target.Expands || len(r.Target.Parts) != 1 {
		return false
	}

	part := r.Target.Parts[0]

	return part.Kind == shellsyntax.PartParameter && part.PlainParameter && part.Quoted && state.kinds[part.Text].kind == hookFreshTemporary
}

func (w *hookSourceWalk) traceTemporaryEnvLaunch(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef) bool {
	if state.lookupUnknown || cmd.Declaration != "" || len(cmd.Assignments) == 0 || len(cmd.Words) < 2 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	if !hookSourceInterpreter(name) || state.hasFunction(name) || len(hookSourceOperands(cmd.Words, name)) == 0 {
		return false
	}

	for _, r := range cmd.Redirects {
		if !hookDiscardedOutput(r) {
			return false
		}
	}

	root := pluginRootParameters[w.plugin.host]
	for _, assignment := range cmd.Assignments {
		if !hookOrdinaryVariable(assignment.Name, root) {
			return false
		}
	}

	// Prefix assignments affect the launched process. Its further reads of
	// those variables are unknown to the trace, while the caller keeps its
	// previous bindings.
	w.resolveCommand(e, view, cmd, name, state, chain)

	return true
}
