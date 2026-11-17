package harness

import (
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const (
	hostEnvironmentFile   = "CLAUDE_ENV_FILE"
	hostEnvironmentMarker = "\x00scout-claude-env-file"
)

func (w *hookSourceWalk) seedHostEnvironment(state *hookSourceState) {
	if w.hostEnvironmentAvailable() {
		state.bindValue(hostEnvironmentFile, hostEnvironmentMarker, true)
	}
}

func (w *hookSourceWalk) inheritHostEnvironment(child *hookSourceState, parent hookSourceState, assignments []shellsyntax.Assignment) {
	if parent.vars[hostEnvironmentFile] == hostEnvironmentMarker && !slices.ContainsFunc(assignments, func(assignment shellsyntax.Assignment) bool {
		return assignment.Name == hostEnvironmentFile
	}) {
		w.seedHostEnvironment(child)
	}
}

func (w *hookSourceWalk) hostEnvironmentAvailable() bool {
	if w.plugin.host != report.HostClaudeCode || w.plugin.activation == "inactive_for_profile" {
		return false
	}

	switch w.event {
	case "SessionStart", "Setup", "CwdChanged", "FileChanged":
		return true
	default:
		return false
	}
}

func (w *hookSourceWalk) traceHostEnvironmentWrite(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState) bool {
	if len(cmd.Redirects) == 0 || !w.hostEnvironmentAvailable() {
		return false
	}

	redirect := hookEnvironmentOutput(cmd.Redirects)
	if redirect == nil {
		return false
	}

	value, known := state.vars[hostEnvironmentFile]
	if known && value != hostEnvironmentMarker {
		return false
	}

	if !known || state.lookupUnknown {
		w.commandGap(e, view, redirect.Span, "hook_source_host_env_target_unverified",
			"The hook's output may use the host-sourced Bash file, but the active path binding is unverified.")

		return false
	}

	if !w.hookEnvironmentWriter(cmd, state) {
		w.commandGap(e, view, redirect.Span, "hook_source_host_env_write_unverified",
			"The hook writes to a host-sourced Bash file using an unverified command.")

		return false
	}

	write, writeErr := view.Original(cmd.Span)
	target, targetErr := view.Original(redirect.Target.Span)

	if writeErr != nil || targetErr != nil {
		w.commandGap(e, view, cmd.Span, "hook_source_host_env_write_unverified",
			"The write to the host-sourced Bash file could not be mapped to captured source.")

		return false
	}

	link := document.GeneratedShellExecution{Write: write, Use: target, HostEnvironment: true}
	links, _ := e.doc.GeneratedShellExecutions()

	if !slices.Contains(links, link) {
		*e.doc = e.doc.WithGeneratedShellExecutions([]document.GeneratedShellExecution{link}, false)
	}

	return true
}

func (w *hookSourceWalk) hookEnvironmentWriter(cmd *shellsyntax.Command, state hookSourceState) bool {
	if len(cmd.Assignments) != 0 || cmd.Declaration != "" {
		return false
	}

	if cmd.Group != nil && len(cmd.Words) == 0 {
		return w.hookEnvironmentWriterGroup(cmd.Group, state)
	}

	return hookEnvironmentPrint(cmd, state)
}

func (w *hookSourceWalk) hookEnvironmentWriterGroup(group *shellsyntax.File, state hookSourceState) bool {
	for _, stmt := range group.Statements {
		if !w.plugin.b.step() || stmt.Background || stmt.Next == "&" || hookAndOrLink(stmt.Next) || len(stmt.Commands) != 1 {
			return false
		}

		cmd := stmt.Commands[0]
		if len(cmd.Redirects) != 0 || len(cmd.Assignments) != 0 || hookCommandWritesDuringExpansion(cmd) ||
			hookLoopSubstitutions(cmd) || !hookEnvironmentPrint(cmd, state) {
			return false
		}
	}

	return len(group.Statements) > 0
}

func hookEnvironmentPrint(cmd *shellsyntax.Command, state hookSourceState) bool {
	if len(cmd.Words) < 2 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	if state.hasFunction(name) {
		return false
	}

	args := cmd.Words[1:]

	switch name {
	case "echo":
		word := args[0]

		return !word.Expands && len(word.Parts) > 0 && word.Parts[0].Kind == "literal" &&
			word.Parts[0].Text != "" && !strings.HasPrefix(word.Parts[0].Text, "-")
	case "printf":
		first, _ := args[0].Literal()
		if first == "--" {
			if len(args) == 1 {
				return false
			}

			first, _ = args[1].Literal()
		}

		return first != "" && !hookPrintfMayWrite(args)
	default:
		return false
	}
}

func hookEnvironmentOutput(redirects []*shellsyntax.Redirect) *shellsyntax.Redirect {
	var output *shellsyntax.Redirect

	for _, r := range redirects {
		if r.FD == "2" && r.Op == ">" && hookDiscardedOutput(r) {
			continue
		}

		if output != nil || r.FD != "" && r.FD != "1" || (r.Op != ">" && r.Op != ">>") || r.Target == nil ||
			!quotedGlobVariable(r.Target, hostEnvironmentFile) {
			return nil
		}

		output = r
	}

	return output
}
