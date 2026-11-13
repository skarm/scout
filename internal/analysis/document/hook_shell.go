package document

import (
	"context"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/syntax/hookevent"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

// OriginHookShell identifies shell source projected from a hook command.
const OriginHookShell = "hook-command"

type hookShellContext struct {
	span  source.Span
	event string
}

// HookEvent identifies the declared hook owning a physical command span.
func (f File) HookEvent(span source.Span) string {
	i := sort.Search(len(f.hookShell), func(i int) bool { return f.hookShell[i].span.End > span.Start })
	if i < len(f.hookShell) {
		h := f.hookShell[i]
		if span.Start >= h.span.Start && span.End <= h.span.End {
			return h.event
		}
	}

	return ""
}

func (f *filePreparation) prepareNamedHookShell(ctx context.Context) {
	if strings.EqualFold(path.Base(f.file.Metadata().Path), "hooks.json") {
		f.prepareHookShell(ctx)
	}
}

// WithDeclaredHookShell prepares a captured file that a plugin manifest
// explicitly identifies as hook configuration. It uses the current run's
// parser registry and byte budget, regardless of filename or language hints.
func (f File) WithDeclaredHookShell(ctx context.Context) File {
	if f.hookShellReady || f.budget == nil || f.file.Metadata().Kind != "text" || ctx.Err() != nil {
		return f
	}

	f.units = slices.Clone(f.units)
	f.diagnostics = slices.Clone(f.diagnostics)
	preparation := (*filePreparation)(&f)
	preparation.prepareHookShell(ctx)

	return f
}

// WithHookSourceShell prepares an explicit local shell input identified by a
// captured hook or source command, including files without a shell suffix.
func (f File) WithHookSourceShell(ctx context.Context) File {
	if f.budget == nil || f.file.Metadata().Kind != "text" || ctx.Err() != nil {
		return f
	}

	for _, unit := range f.units {
		if unit.Origin == "file" && unit.Language == language.Shell {
			return f
		}
	}

	f.units = slices.Clone(f.units)
	f.diagnostics = slices.Clone(f.diagnostics)
	preparation := (*filePreparation)(&f)
	span := source.Span{End: len(f.file.Content())}

	view, err := source.NewView(f.file.Content(), []source.Span{span})
	if err != nil {
		preparation.issue("source_map_error", "Source mapping could not be constructed.")
		return f
	}

	preparation.addUnit(ctx, language.Shell, "file", span, view)

	return f
}

func (f *filePreparation) prepareHookShell(ctx context.Context) {
	f.hookShellReady = true

	for _, unit := range f.units {
		if unit.Origin == "file" && unit.Language == language.JSON {
			f.projectHookJSON(ctx, unit)
			return
		}
	}

	// The manifest is a stronger language hint than a suffix or content prefix.
	span := source.Span{End: len(f.file.Content())}

	view, err := source.NewView(f.file.Content(), []source.Span{span})
	if err != nil {
		f.issue("source_map_error", "Source mapping could not be constructed.")
		return
	}

	if len(f.units) >= MaxRegions {
		f.issue("analysis_unit_limit", "Analysis unit budget exhausted; remaining units are unverified.")
		return
	}

	unit := f.parseUnit(ctx, language.JSON, "file", span, view)
	f.publishUnit(ctx, unit)
	f.projectHookJSON(ctx, unit)
}

func (f *filePreparation) projectHookJSON(ctx context.Context, unit Unit) {
	if tree, ok := unit.Tree.(parse.JSONTree); ok {
		f.projectHookEvents(ctx, unit.View, tree.Root)
	}
}

func (f *filePreparation) projectHookEvents(ctx context.Context, parent source.View, root *jsonconfig.Node) {
	hooks := root.Get("hooks")
	if hooks == nil {
		hooks = root
	}

	if hooks == nil || hooks.Kind != jsonconfig.KindObject {
		return
	}

	for _, event := range hooks.Members {
		if !hookevent.Known(event.Key) || event.Value.Kind != jsonconfig.KindArray {
			continue
		}

		for _, group := range event.Value.Elements {
			for _, handler := range group.GetOrEmpty("hooks").Elements {
				if ctx.Err() != nil || !f.projectHookHandler(ctx, parent, event.Key, handler) {
					return
				}
			}
		}
	}
}

func (f *filePreparation) projectHookHandler(ctx context.Context, parent source.View, event string, handler *jsonconfig.Node) bool {
	kind, _ := handler.Get("type").Text()
	if kind != "command" {
		return true
	}

	if shell := handler.Get("shell"); shell != nil && shell.String != "bash" && shell.String != "sh" {
		return true
	}

	command := handler.Get("command")
	if args := handler.Get("args"); args != nil {
		// The explicit argv form has no outer shell quoting or operators.
		payload, uncertain := hookArgvScript(command, args)
		if uncertain {
			f.hookShellGap(args.Span.Start)
		}

		if payload == nil {
			return true
		}

		return f.projectHookString(ctx, parent, event, payload)
	}

	return f.projectHookString(ctx, parent, event, command)
}

func hookArgvScript(command, args *jsonconfig.Node) (*jsonconfig.Node, bool) {
	name, ok := command.Text()
	if !ok || !hookShellInterpreter(name) {
		return nil, false
	}

	if args.Kind != jsonconfig.KindArray {
		return nil, true
	}

	for _, arg := range args.Elements {
		value, ok := arg.Text()
		if !ok || strings.ContainsRune(value, 0) {
			return nil, true
		}
	}

	index, uncertain := hookShellScriptIndex(len(args.Elements), func(i int) (string, bool) { return args.Elements[i].Text() })
	if index < 0 {
		return nil, uncertain
	}

	return args.Elements[index], false
}

func (f *filePreparation) projectHookString(ctx context.Context, parent source.View, event string, node *jsonconfig.Node) bool {
	text, ok := node.Text()
	if !ok || strings.TrimSpace(text) == "" {
		return true
	}

	if len(f.units) >= MaxRegions {
		f.issue("analysis_unit_limit", "Analysis unit budget exhausted; remaining units are unverified.")
		return false
	}

	if strings.ContainsRune(text, 0) {
		f.hookShellGap(node.Span.Start)
		return true
	}

	view, ok := jsonconfig.StringView(parent, node, MaxSourceSegments)
	if !ok {
		f.hookShellGap(node.Span.Start)
		return true
	}

	span, err := view.Original(source.Span{End: len(view.Text())})
	if err != nil {
		f.hookShellGap(node.Span.Start)
		return true
	}

	f.hookShell = append(f.hookShell, hookShellContext{span: span, event: event})
	f.parseHookUnit(ctx, view, span, 0)

	return true
}

func (f *filePreparation) parseHookUnit(ctx context.Context, view source.View, span source.Span, depth int) {
	unit := f.parseUnit(ctx, language.Shell, OriginHookShell, span, view)
	f.publishUnit(ctx, unit)

	if tree, ok := unit.Tree.(parse.ShellTree); ok {
		root := tree.Tree
		if tree.ExecutionError != nil && tree.DeclarationError == nil && tree.Declarations != nil {
			root = tree.Declarations
		}

		functions := hookLocalFunctions(root)
		f.projectHookScripts(ctx, view, root, depth, functions)
	}
}

func (f *filePreparation) hookShellGap(at int) {
	f.generatedShellDiagnostic("hook_command_unverified", "A hook command could not be mapped to supported static shell source.", at)
}

func hookShellInterpreter(name string) bool {
	switch name {
	case "sh", "bash", "dash", "zsh", "ksh", "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh",
		"/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh", "/usr/bin/ksh":
		return true
	}

	return false
}

func hookShellScriptIndex(length int, operand func(int) (string, bool)) (int, bool) {
	var command, shortOptions, noexec bool

	for i := 0; i < length; i++ {
		value, ok := operand(i)
		if !ok {
			return -1, true
		}

		switch {
		case value == "-" || value == "--":
			return hookCommandOperand(command && !noexec, i+1, length)
		case !strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "+") || value == "+":
			return hookCommandOperand(command && !noexec, i, length)
		case !shortOptions && hookLongShellOption(value):
			continue
		}

		shortOptions = true

		flags := value[1:]
		if flags == "o" {
			i++

			option, ok := hookNamedShellOption(i, length, operand)
			if !ok {
				return -1, true
			}

			if option == "noexec" {
				noexec = value[0] == '-'
			}

			continue
		}

		if strings.Trim(flags, "censufxvlp") != "" {
			return -1, true
		}

		if strings.ContainsRune(flags, 'n') {
			noexec = value[0] == '-'
		}

		if strings.ContainsRune(flags, 'c') {
			if value[0] != '-' {
				return -1, true
			}

			command = true
		}
	}

	return -1, command && !noexec
}

func hookNamedShellOption(index, length int, operand func(int) (string, bool)) (string, bool) {
	if index >= length {
		return "", false
	}

	value, known := operand(index)
	if !known {
		return "", false
	}

	switch value {
	case "allexport", "errexit", "noexec", "noglob", "nounset", "pipefail", "verbose", "xtrace":
		return value, true
	default:
		return "", false
	}
}

func hookLongShellOption(value string) bool {
	switch value {
	case "--noprofile", "--norc", "--login", "--posix":
		return true
	default:
		return false
	}
}

func hookCommandOperand(command bool, index, length int) (int, bool) {
	if command && index < length {
		return index, false
	}

	return -1, command
}

func hookLocalFunctions(tree *shellsyntax.File) map[string]bool {
	var names map[string]bool

	if tree == nil {
		return nil
	}

	// A local definition makes a bare name ambiguous. Explicit executable
	// paths and command/exec wrappers still resolve as external commands.
	for _, stmt := range tree.Statements {
		for _, cmd := range stmt.Commands {
			if hookShellInterpreter(cmd.FunctionName) || cmd.FunctionName == "command" || cmd.FunctionName == "exec" {
				if names == nil {
					names = map[string]bool{}
				}

				names[cmd.FunctionName] = true
			}
		}
	}

	return names
}

func (f *filePreparation) projectHookScripts(ctx context.Context, view source.View, tree *shellsyntax.File, depth int, functions map[string]bool) bool {
	if tree == nil {
		return true
	}

	for _, stmt := range tree.Statements {
		for _, c := range stmt.Commands {
			if ctx.Err() != nil {
				return false
			}

			f.projectHookScript(ctx, view, c, depth, functions)

			if !f.projectHookChildren(ctx, view, c, depth, functions) {
				return false
			}
		}
	}

	return true
}

func (f *filePreparation) projectHookChildren(ctx context.Context, view source.View, cmd *shellsyntax.Command, depth int, functions map[string]bool) bool {
	for _, child := range []*shellsyntax.File{cmd.Subshell, cmd.Group, cmd.Prelude, cmd.FunctionBody} {
		if !f.projectHookScripts(ctx, view, child, depth, functions) {
			return false
		}
	}

	for _, branch := range cmd.Alternatives {
		if !f.projectHookScripts(ctx, view, branch, depth, functions) {
			return false
		}
	}

	for _, word := range cmd.Words {
		if !f.projectHookWordTrees(ctx, view, word, depth, functions) {
			return false
		}
	}

	for _, assignment := range cmd.Assignments {
		if !f.projectHookWordTrees(ctx, view, assignment.Value, depth, functions) {
			return false
		}
	}

	for _, redirect := range cmd.Redirects {
		if !f.projectHookWordTrees(ctx, view, redirect.Target, depth, functions) ||
			!redirect.QuotedDelimiter && !f.projectHookWordTrees(ctx, view, redirect.Body, depth, functions) {
			return false
		}
	}

	return true
}

func (f *filePreparation) projectHookWordTrees(ctx context.Context, view source.View, word *shellsyntax.Word, depth int, functions map[string]bool) bool {
	if word != nil {
		for _, part := range word.Parts {
			if part.Tree != nil && !f.projectHookScripts(ctx, view, part.Tree, depth, functions) {
				return false
			}
		}
	}

	return true
}

func (f *filePreparation) projectHookScript(ctx context.Context, parent source.View, cmd *shellsyntax.Command, depth int, functions map[string]bool) {
	if len(cmd.Words) == 0 {
		return
	}

	name, ok := cmd.Words[0].Literal()
	if !ok {
		return
	}

	if functions[name] {
		if hookShellInterpreter(name) || name == "command" || name == "exec" {
			f.hookWordGap(parent, cmd.Words[0].Span)
		}

		return
	}

	args := cmd.Words[1:]
	if name == "command" || name == "exec" {
		args = hookWrapperArgs(name, args)
		if len(args) == 0 {
			return
		}

		name, ok = args[0].Literal()
		args = args[1:]
	}

	if !ok || !hookShellInterpreter(name) {
		return
	}

	index, uncertain := hookShellScriptIndex(len(args), func(i int) (string, bool) { return args[i].Literal() })
	if index < 0 {
		if uncertain {
			f.hookWordGap(parent, cmd.Span)
		}

		return
	}

	word := args[index]
	if value, fixed := word.Literal(); fixed && strings.TrimSpace(value) == "" {
		return
	}

	if len(f.units) >= MaxRegions {
		f.issue("analysis_unit_limit", "Analysis unit budget exhausted; remaining units are unverified.")
		return
	}

	const maxNestedScripts = 4
	if depth >= maxNestedScripts {
		f.hookWordGap(parent, word.Span)

		return
	}

	view, ok := shellsyntax.LiteralView(parent, word, MaxSourceSegments)
	if !ok {
		f.hookWordGap(parent, word.Span)

		return
	}

	if span, err := view.Original(source.Span{End: len(view.Text())}); err == nil {
		f.parseHookUnit(ctx, view, span, depth+1)
	} else {
		f.hookWordGap(parent, word.Span)
	}
}

func hookWrapperArgs(name string, args []*shellsyntax.Word) []*shellsyntax.Word {
	if len(args) == 0 {
		return nil
	}

	if option, _ := args[0].Literal(); name == "command" && option == "-p" {
		args = args[1:]
	}

	if len(args) > 0 {
		if option, _ := args[0].Literal(); option == "--" {
			args = args[1:]
		}
	}

	return args
}

func (f *filePreparation) hookWordGap(parent source.View, span source.Span) {
	if at, err := parent.Original(span); err == nil {
		f.hookShellGap(at.Start)
	}
}
