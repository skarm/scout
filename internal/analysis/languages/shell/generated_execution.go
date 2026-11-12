package shell

import (
	"context"
	"path"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

type generatedShellExecutionCheck struct{}

func (generatedShellExecutionCheck) OmitNotApplicableFileCoverage() bool { return true }

func (generatedShellExecutionCheck) Rule() report.Rule {
	return report.Rule{
		ID: ruleSH005, Version: "1", Severity: report.Info, Category: "dynamic-execution", Method: "shell-generated-file-flow",
		Title:       "Generated shell script reaches a local execution command",
		Description: "A recovered heredoc write and a later source or execution command refer to the same modeled path.",
		Limitation:  "Bounded command sequences within one shell unit or local block, using lexical paths and successful modeled commands. Runtime success, permissions, symlinks and external shell state are unverified.",
	}
}

func (generatedShellExecutionCheck) AppliesTo(doc document.File) bool {
	links, limited := doc.GeneratedShellExecutions()
	return len(links) > 0 || limited
}

func (generatedShellExecutionCheck) Find(ctx context.Context, doc document.File, limit int) (result, error) {
	links, limited := doc.GeneratedShellExecutions()

	out := result{Truncated: limited}
	for _, link := range links {
		if len(out.Matches) >= limit || !analysisbudget.Consume(ctx, 1) {
			out.Truncated = true
			break
		}

		out.Matches = append(out.Matches, match{
			Start: link.Use.Start, End: link.Use.End,
			Trace: []trace{
				{Role: "source", Start: link.Write.Start, End: link.Write.End},
				{Role: "transform", Start: link.Body.Start, End: link.Body.End},
				{Role: "sink", Start: link.Use.Start, End: link.Use.End},
			},
		})
	}

	return out, ctx.Err()
}

type generatedShellWrite struct{ header, body source.Span }

type generatedShellFlow struct {
	cwd, previous string
	files         map[string]generatedShellWrite
}

func (f *generatedShellFlow) reset() {
	f.cwd, f.previous = ".", ""
	clear(f.files)
}

func plainGeneratedShellGroup(c *shellsyntax.Command) bool {
	return c.Group != nil && c.Prelude == nil && len(c.Alternatives) == 0 &&
		len(c.Words) == 0 && len(c.Redirects) == 0 && len(c.Assignments) == 0
}

func (f *generatedShellFlow) key(value string) string {
	if path.IsAbs(value) {
		return path.Clean(value)
	}

	return path.Join(f.cwd, value)
}

func (f *generatedShellFlow) invalidateBefore(c *shellsyntax.Command, vars map[string]string) {
	if len(f.files) == 0 {
		return
	}

	for child := range scriptIsolatedTrees(c) {
		if child != nil && child != c.FunctionBody && child != c.Subshell {
			clear(f.files)
			return
		}
	}

	for _, r := range c.Redirects {
		if len(f.files) == 0 {
			return
		}

		if generatedWordRunsCode(r.Target) || generatedWordRunsCode(r.Body) {
			clear(f.files)
			return
		}

		switch r.Op {
		case ">", ">|", ">>", "<>", "&>", "&>>":
			if target, ok := scriptPathWord(r.Target, vars); ok && target != "" {
				delete(f.files, f.key(target))
			} else {
				clear(f.files)
			}
		case ">&":
			// An unresolved descriptor or a filename can be an output write.
			if value, ok := r.Target.Literal(); !ok || strings.Trim(value, "0123456789-") != "" {
				clear(f.files)
			}
		}
	}
}

func generatedWordRunsCode(word *shellsyntax.Word) bool {
	if word != nil {
		for _, p := range word.Parts {
			if p.Kind == "substitution" || p.Tree != nil {
				return true
			}
		}
	}

	return false
}

func (s *generatedShellScan) rememberGeneratedWrite(flow *generatedShellFlow, c *shellsyntax.Command, hdoc *shellsyntax.Redirect, writer *shellsyntax.Word, body source.View, vars map[string]string) {
	header := c.Span

	header.End = min(header.End, hdoc.Body.Span.Start)
	if header.End > header.Start {
		header.End = header.Start + len(strings.TrimRight(s.view.Text()[header.Start:header.End], " \t\r\n"))
	}

	at, headerErr := s.view.Original(header)

	bodyAt, bodyErr := body.Original(source.Span{End: len(body.Text())})
	if headerErr != nil || bodyErr != nil {
		s.executionLimit = true

		flow.reset()

		return
	}

	write := generatedShellWrite{header: at, body: bodyAt}

	for _, r := range c.Redirects {
		if (r.FD == "" || r.FD == "1") && (r.Op == ">" || r.Op == ">|") {
			s.rememberGeneratedTarget(flow, r.Target, vars, write)
		}
	}

	if value, _ := writer.Literal(); path.Base(value) == "tee" {
		words, _ := scriptWriterWords(c.Words)
		for _, word := range words[1:] {
			s.rememberGeneratedTarget(flow, word, vars, write)
		}
	}
}

func (s *generatedShellScan) rememberGeneratedTarget(flow *generatedShellFlow, word *shellsyntax.Word, vars map[string]string, write generatedShellWrite) {
	value, ok := scriptPathWord(word, vars)
	if !ok || !strings.HasSuffix(value, ".sh") || !localWritePath(value) {
		return
	}

	key := flow.key(value)
	if _, exists := flow.files[key]; !exists && len(flow.files) >= MaxShellBindings {
		s.executionLimit = true
		return
	}

	if flow.files == nil {
		flow.files = map[string]generatedShellWrite{}
	}

	flow.files[key] = write
}

func shellConsumerBit(name string) uint32 {
	for i, candidate := range []string{"cd", "source", ".", "sh", "bash", "dash", "zsh", "ksh", "exec", "chmod", "echo", "printf", ":", "true", "false", "test", "["} {
		if name == candidate {
			return 1 << i
		}
	}

	return 0
}

func (a scriptWriterAliases) shadowsConsumer(word *shellsyntax.Word, bypass bool) bool {
	if bypass {
		return false
	}

	name, _ := word.Literal()
	mask := shellConsumerBit(name)

	return a.consumerFunctions&mask != 0 || !word.Quoted && a.consumerAliases&mask != 0
}

func (s *generatedShellScan) observeGeneratedUse(c *shellsyntax.Command, scope *scriptScope, flow *generatedShellFlow) {
	if len(c.Words) == 0 {
		flow.observeWithoutInvocation(c)
		return
	}

	words, name, ok := generatedUseWords(c, scope)
	if !ok {
		flow.reset()
		return
	}

	if name == "cd" {
		flow.changeDirectory(words[1:], scope)
		return
	}

	requiresLookup := name != "." && name != "source" && !strings.Contains(name, "/")
	if target, ok := generatedShellOperand(name, words[1:], scope.variables); ok &&
		(!requiresLookup || !scope.lookupUncertain(c.Words, words[0])) {
		if write, found := flow.files[flow.key(target)]; found {
			s.recordGeneratedUse(c, write)
		}
		// The invoked script can write files or change the directory.
		flow.reset()

		return
	}

	switch name {
	case ":", "echo", "true", "false", "test", "[":
		return
	case "printf":
		if len(words) < 2 || !literalWordEquals(words[1], "-v") {
			return
		}
	case "chmod", "/bin/chmod", "/usr/bin/chmod":
		if !scope.lookupUncertain(c.Words, words[0]) {
			return
		}
	}

	flow.reset()
}

func (f *generatedShellFlow) observeWithoutInvocation(c *shellsyntax.Command) {
	if c.Group != nil || c.Subshell != nil || c.Prelude != nil || len(c.Alternatives) > 0 ||
		c.Declaration != "" || len(c.Invalidates) > 0 {
		f.reset()
	}

	for _, assignment := range c.Assignments {
		switch assignment.Name {
		case "OLDPWD":
			f.previous = ""
		case "PWD":
			f.reset()
		}
	}
}

func generatedUseWords(c *shellsyntax.Command, scope *scriptScope) ([]*shellsyntax.Word, string, bool) {
	words, bypass := scriptWriterWords(c.Words)
	if len(words) == 0 || len(c.Assignments) != 0 ||
		bypass && scope.shadow.shadows(c.Words[0], false) || scope.shadow.shadowsConsumer(words[0], bypass) {
		return nil, "", false
	}

	name, literal := words[0].Literal()
	if name != "exec" {
		return words, name, literal
	}

	words = words[1:]
	if len(words) > 0 && literalWordEquals(words[0], "--") {
		words = words[1:]
	}

	if len(words) == 0 {
		return nil, "", false
	}

	name, literal = words[0].Literal()
	// Exec resolves an external executable, so builtin names cannot act as sinks.
	return words, name, literal && (isShellInterpreter(name) || strings.Contains(name, "/"))
}

func (f *generatedShellFlow) changeDirectory(args []*shellsyntax.Word, scope *scriptScope) {
	if len(args) > 0 && literalWordEquals(args[0], "-L") {
		args = args[1:]
	}

	if len(args) > 0 && literalWordEquals(args[0], "--") {
		args = args[1:]
	}

	if len(args) != 1 {
		f.reset()
		return
	}

	dir, ok := scriptPathWord(args[0], scope.variables)
	if ok && dir == "-" && f.previous != "" {
		f.cwd, f.previous = f.previous, f.cwd
		return
	}

	if !ok || dir == "" || strings.HasPrefix(dir, "-") || strings.HasPrefix(dir, "//") {
		f.reset()
		return
	}

	if scope.cdpathUnsafe && !path.IsAbs(dir) && dir != "." && dir != ".." &&
		!strings.HasPrefix(dir, "./") && !strings.HasPrefix(dir, "../") {
		f.reset()
		return
	}

	f.cwd, f.previous = f.key(dir), f.cwd
}

func generatedShellOperand(name string, words []*shellsyntax.Word, vars map[string]string) (string, bool) {
	switch name {
	case "source", ".":
		if len(words) > 0 && literalWordEquals(words[0], "--") {
			words = words[1:]
		}

		if len(words) > 0 {
			value, ok := scriptPathWord(words[0], vars)
			// Bare source operands can resolve through the shell's search path.
			return value, ok && strings.Contains(value, "/") && !strings.HasPrefix(value, "-")
		}
	default:
		if !isShellInterpreter(name) {
			return name, strings.Contains(name, "/") && strings.HasSuffix(name, ".sh") && !strings.HasPrefix(name, "-")
		}

		args := make([]shellValue, 0, len(words))
		for _, word := range words {
			value, ok := scriptPathWord(word, vars)
			args = append(args, shellValue{text: value, known: ok})
		}

		file := shellScriptFile(args)

		return file.text, file.known
	}

	return "", false
}

func isShellInterpreter(name string) bool {
	switch name {
	case "sh", "bash", "dash", "zsh", "ksh", "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh",
		"/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh", "/usr/bin/ksh":
		return true
	}

	return false
}

func (s *generatedShellScan) recordGeneratedUse(c *shellsyntax.Command, write generatedShellWrite) {
	if len(s.executions) >= document.MaxRegions || !analysisbudget.Consume(s.ctx, 1) {
		s.executionLimit = true
		return
	}

	use, err := s.view.Original(c.Span)
	if err != nil {
		s.executionLimit = true
		return
	}

	s.executions = append(s.executions, document.GeneratedShellExecution{Write: write.header, Body: write.body, Use: use})
}
