package hooktrace

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/report"
)

const geminiExtensionPath = "${extensionPath}"

func (w *hookSourceWalk) geminiLaunch(text string, args *jsonconfig.Node, initial report.SourceRef) {
	// Gemini replaces the placeholder before handing the command to a shell.
	// Inert characters suffice for resolving a path in the captured extension.
	const modelRoot = "/scout/gemini-extension"

	assumed := w.assumesShellHookRoot()
	if !assumed {
		w.gap(initial, "hook_source_gemini_root_unverified",
			"The Gemini extension path is substituted before shell parsing; the actual path is unknown.")
	}

	if args != nil || strings.Contains(text, modelRoot) || strings.Contains(text, "${workspacePath}") ||
		strings.Contains(text, "${/}") || strings.Count(text, geminiExtensionPath) > maxHookArguments {
		w.geminiLaunchGap(initial)
		return
	}

	launch, err := shellsyntax.Parse(w.trace.work.Context, strings.ReplaceAll(text, geminiExtensionPath, modelRoot))
	cmd, simple := SimpleShellCommand(launch)

	if err != nil || !simple || launch.Statements[0].Background || launch.Statements[0].Negated {
		w.geminiLaunchGap(initial)
		return
	}

	name, _ := cmd.Words[0].Literal()
	words := hookSourceOperands(cmd.Words, name)

	if len(words) == 0 || name == "." || name == "source" {
		w.geminiLaunchGap(initial)
		return
	}

	value, literal := words[0].Literal()
	suffix, rooted := strings.CutPrefix(value, modelRoot+"/")

	if !literal || !rooted {
		w.geminiLaunchGap(initial)
		return
	}

	value = pluginRootMarker + suffix
	rel, reason := w.resolveFile(value, "")

	if reason != "" {
		w.gap(initial, reason, "A shell source path could not be resolved within the captured extension.")
		return
	}

	steps := []report.SourceRef{initial}
	direct := !IsShellInterpreter(name)
	state := hookSourceState{scriptPath: value, sourcePath: value, explicitBash: w.knownLaunchBash(rel, steps, name, direct)}
	state.positional = w.arguments(words[1:], state)

	for i, arg := range state.positional.values {
		if arg.value == modelRoot {
			state.positional.values[i].value = pluginRootValue
		} else if suffix, rooted := strings.CutPrefix(arg.value, modelRoot+"/"); rooted {
			state.positional.values[i].value = pluginRootMarker + suffix
		}
	}

	if assumed {
		w.seedHookLocale(&state)
	}

	w.follow(rel, state, steps, direct)
}

func (w *hookSourceWalk) geminiLaunchGap(at report.SourceRef) {
	w.gap(at, "hook_source_gemini_command_unverified", "The Gemini extension hook is outside the supported simple launch syntax.")
}
