package harness

import (
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func (w *hookSourceWalk) traceNodeLaunch(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef) (replaces, traced bool) {
	if state.lookupUnknown || len(cmd.Words) < 2 || len(cmd.Assignments) != 0 ||
		slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool { return !hookDiscardedOutput(r) }) {
		return false, false
	}

	words, replaces := nodeLaunchWords(cmd.Words, state)
	if len(words) == 0 {
		return false, false
	}

	value, known := w.nodeFileOperand(e, view, cmd, words, state)
	if !known || !strings.HasPrefix(value, pluginRootMarker) && (state.cwd == "" || !strings.HasPrefix(value, "./")) {
		return false, false
	}

	switch path.Ext(value) {
	case ".js", ".cjs", ".mjs":
	default:
		return false, false
	}

	span, err := view.Original(cmd.Span)
	if err != nil {
		return false, false
	}

	at := ref(e, span)
	if at == nil {
		return false, false
	}

	rel, reason := w.resolveFile(value, state.cwd)
	if reason != "" {
		w.gap(*at, reason, "A Node hook script path could not be resolved within the captured plugin.")
		return false, false
	}

	target := w.plugin.entry(rel)
	if target == nil || target.doc == nil {
		w.gap(*at, "hook_source_not_captured", "A referenced Node hook script was not captured in the plugin.")
		return false, false
	}

	b := w.plugin.b
	if len(chain) >= maxHookSourceDepth || len(b.hookSourcePaths) >= b.r.Limits.References {
		w.gap(*at, "hook_source_limit", "The hook source path budget was exhausted.")
		return false, false
	}

	steps := append(slices.Clone(chain), *at)
	b.hookSourcePaths = append(b.hookSourcePaths, HookSourcePath{Target: target.meta.Path, Event: w.event, Language: language.JavaScript, Steps: steps})
	w.gap(*at, "hook_source_node_scope_unverified", "Node module resolution and runtime execution remain unverified for the captured hook script.")

	return replaces, true
}

func nodeLaunchWords(words []*shellsyntax.Word, state hookSourceState) ([]*shellsyntax.Word, bool) {
	name, _ := words[0].Literal()
	replaces := name == "exec" && !state.hasFunction("exec")
	external := replaces

	if replaces {
		words = hookSkipLiteral(words[1:], "--")
	}

	if len(words) > 1 {
		name, _ = words[0].Literal()
		if name == "env" && (replaces || !state.hasFunction("env")) {
			words = nodeEnvWords(words[1:])
			external = true
		}
	}

	if len(words) < 2 {
		return nil, false
	}

	name, _ = words[0].Literal()
	if !external && state.hasFunction(name) {
		return nil, false
	}

	switch name {
	case "node", "nodejs", "/usr/bin/node", "/usr/local/bin/node", "/opt/homebrew/bin/node":
		return hookSkipLiteral(words[1:], "--"), replaces
	default:
		return nil, false
	}
}

func nodeEnvWords(words []*shellsyntax.Word) []*shellsyntax.Word {
	words = hookSkipLiteral(words, "-i")
	words = hookSkipLiteral(words, "--")

	for i, word := range words {
		if i >= maxHookArguments {
			return nil
		}

		if !hookFixedArgument(word) || len(word.Parts) == 0 || word.Parts[0].Kind != "literal" {
			return nil
		}

		name, _, assignment := strings.Cut(word.Parts[0].Text, "=")
		if !assignment || !hookVariableName(name) {
			return words[i:]
		}
	}

	return nil
}

func hookSkipLiteral(words []*shellsyntax.Word, token string) []*shellsyntax.Word {
	if len(words) > 0 {
		if first, _ := words[0].Literal(); first == token {
			return words[1:]
		}
	}

	return words
}

func (w *hookSourceWalk) nodeFileOperand(e *entry, view source.View, cmd *shellsyntax.Command, words []*shellsyntax.Word, state hookSourceState) (string, bool) {
	args := w.arguments(words, state)
	if len(args.values) > 0 && args.values[0].known {
		return args.values[0].value, true
	}

	first := words[0]
	if !w.unquotedPluginPath(first, state) {
		return "", false
	}

	if (e != w.config || w.rootLaunch != cmd) && !w.singleFieldRoot(e, state) {
		w.commandGap(e, view, first.Parts[0].Span, "hook_source_unquoted_root",
			"An unquoted plugin root can split or expand before the shell resolves this file.")
	}

	return w.value(first, state, true)
}
