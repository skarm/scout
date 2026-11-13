package shell

import (
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

type generatedHeredocWrite struct {
	input  *shellsyntax.Redirect
	writer *shellsyntax.Word
	paths  []string
	bypass bool
}

type pendingGeneratedAppend struct {
	key   string
	prior generatedShellWrite
	known bool
}

// Admit only identity append writers with deterministic local destinations.
func scriptAppendHeredoc(c *shellsyntax.Command, vars map[string]string, mergesStderr, stdoutPiped bool) generatedHeredocWrite {
	if mergesStderr || len(c.Words) == 0 || len(c.Redirects) == 0 || len(c.Assignments) != 0 {
		return generatedHeredocWrite{}
	}

	input, output := generatedWriterRedirects(c.Redirects)
	words, bypass := scriptWriterWords(c.Words)

	if input == nil || len(words) == 0 {
		return generatedHeredocWrite{}
	}

	name, absolute := generatedWriterName(words[0])

	return newGeneratedHeredocWrite(input, words[0], scriptAppendTargets(name, words[1:], output, stdoutPiped), vars, bypass || absolute)
}

func newGeneratedHeredocWrite(input *shellsyntax.Redirect, writer *shellsyntax.Word, targets []*shellsyntax.Word, vars map[string]string, bypass bool) generatedHeredocWrite {
	if len(targets) == 0 {
		return generatedHeredocWrite{}
	}

	seen := make(map[string]bool, len(targets))

	var paths []string

	for _, target := range targets {
		value, known := scriptPathWord(target, vars)
		if !known {
			return generatedHeredocWrite{}
		}

		if value == "/dev/null" {
			continue
		}

		key := strings.TrimPrefix(value, "./")
		if key == "." || !localWritePath(value) || seen[key] {
			return generatedHeredocWrite{}
		}

		seen[key] = true

		paths = append(paths, value)
	}

	if len(paths) == 0 {
		return generatedHeredocWrite{}
	}

	return generatedHeredocWrite{input: input, writer: writer, paths: paths, bypass: bypass}
}

func scriptAppendTargets(name string, args []*shellsyntax.Word, output *shellsyntax.Redirect, stdoutPiped bool) []*shellsyntax.Word {
	if output != nil && output.Op == ">>" {
		operands := skipGeneratedOptionEnd(args)
		if name == "cat" && (len(operands) == 0 || len(operands) == 1 && literalWordEquals(operands[0], "-")) ||
			name == "tee" && len(operands) == 0 {
			return []*shellsyntax.Word{output.Target}
		}

		return nil
	}

	if name != "tee" || len(args) == 0 || stdoutPiped && output == nil {
		return nil
	}

	if output != nil && !literalWordEquals(output.Target, "/dev/null") {
		return nil
	}

	if !literalWordEquals(args[0], "-a") && !literalWordEquals(args[0], "--append") &&
		!literalWordEquals(args[0], "-ai") && !literalWordEquals(args[0], "-ia") {
		return nil
	}

	return skipGeneratedOptionEnd(args[1:])
}

func skipGeneratedOptionEnd(args []*shellsyntax.Word) []*shellsyntax.Word {
	if len(args) > 0 && literalWordEquals(args[0], "--") {
		return args[1:]
	}

	return args
}

func (s *generatedShellScan) recoverAppend(c *shellsyntax.Command, scope *scriptScope, flow *generatedShellFlow, app generatedHeredocWrite, pending []pendingGeneratedAppend) (written, more bool) {
	preamble := generatedHeredocPreamble(s.view, app.input, scope.variables)
	if reason := generatedWriterIssue(c, scope, app.input, app.writer, app.bypass); reason != "" {
		for _, item := range pending {
			if item.prior.confirmed || generatedShellName(item.key) || shellShebang(preamble) {
				s.noteGap(c.Span.Start, document.GeneratedShellAppend, reason)
				break
			}
		}

		return false, true
	}

	if app.input.Body.Span.Start == app.input.Body.Span.End {
		for _, item := range pending {
			if item.known {
				s.storeGeneratedWrite(flow, item.key, item.prior)
			}
		}

		return true, true
	}

	pending = s.stageGeneratedAppends(c, scope, flow, app.input, pending, preamble)
	if len(pending) == 0 {
		return true, true
	}

	if !analysisbudget.Consume(s.ctx, 1) {
		s.noteGap(c.Span.Start, document.GeneratedShellAppend|document.GeneratedShellUnrecovered, document.GeneratedShellLimit)
		return false, true
	}

	suffix, reason := scriptHeredocView(s.view, app.input, scope.variables)
	if reason != "" {
		kinds := document.GeneratedShellAppend
		if reason == document.GeneratedShellLimit {
			kinds |= document.GeneratedShellUnrecovered
		}

		s.noteGap(c.Span.Start, kinds, reason)

		return false, true
	}

	if suffix.Text() == "" {
		for _, item := range pending {
			s.storeGeneratedWrite(flow, item.key, item.prior)
		}

		return true, true
	}

	span, err := suffix.Original(source.Span{End: len(suffix.Text())})
	if err != nil {
		s.noteGap(c.Span.Start, document.GeneratedShellAppend, document.GeneratedShellInput)
		return false, true
	}

	for i, item := range pending {
		if i > 0 && !analysisbudget.Consume(s.ctx, 1) {
			s.noteGap(c.Span.Start, document.GeneratedShellAppend|document.GeneratedShellUnrecovered, document.GeneratedShellLimit)
			return written, false
		}

		retained, more := s.appendGeneratedVersion(c.Span.Start, scope.functionBody, flow, app.input, item, suffix, span)

		written = written || retained
		if !more {
			return written, false
		}
	}

	return written, true
}

func (s *generatedShellScan) stageGeneratedAppends(c *shellsyntax.Command, scope *scriptScope, flow *generatedShellFlow, input *shellsyntax.Redirect, pending []pendingGeneratedAppend, preamble string) []pendingGeneratedAppend {
	shebang := shellShebang(preamble)
	ready := pending[:0]

	var suffix *generatedShellCandidate

	for _, item := range pending {
		if !item.known {
			if generatedShellName(item.key) || shebang {
				s.noteGap(c.Span.Start, document.GeneratedShellAppend, "")
			} else {
				s.storeGeneratedWrite(flow, item.key, generatedShellWrite{candidate: &generatedShellCandidate{
					gap: document.GeneratedShellAppend, at: c.Span.Start, depth: 1,
				}})
			}

			continue
		}

		if item.prior.knownEmpty() && strings.HasPrefix(preamble, "#!") {
			item.prior.foreignShebang = !shebang
			if shebang {
				item.prior.confirmed = true
				item.prior.candidate = nil
			}
		}

		if item.prior.confirmed {
			ready = append(ready, item)
			continue
		}

		if suffix == nil {
			suffix = newGeneratedCandidate(c, input, scope)
		}

		staged := item.prior
		staged.clearTransforms()

		candidate := *suffix

		candidate.prior = &item.prior
		if staged.candidate != nil {
			candidate.depth += staged.candidate.depth
		}

		if candidate.depth > document.MaxRegions {
			candidate = generatedShellCandidate{gap: document.GeneratedShellUnrecovered, reason: document.GeneratedShellLimit, at: c.Span.Start, depth: 1}
		}

		staged.candidate = &candidate
		s.storeGeneratedWrite(flow, item.key, staged)
	}

	return ready
}

func (s *generatedShellScan) appendGeneratedVersion(at int, functionBody bool, flow *generatedShellFlow, input *shellsyntax.Redirect, item pendingGeneratedAppend, suffix source.View, span source.Span) (retained, more bool) {
	prior := item.prior
	if len(prior.view.Text())+len(suffix.Text()) > shellsyntax.MaxBytes {
		s.noteGap(at, document.GeneratedShellAppend|document.GeneratedShellUnrecovered, document.GeneratedShellLimit)
		return false, true
	}

	view := source.Concat(prior.view, suffix)
	if retained, more := s.retainGeneratedView(at, input, view, functionBody); !retained {
		s.noteGap(at, document.GeneratedShellAppend, document.GeneratedShellLimit)
		return false, more
	}

	prior.view = view
	prior.addTransform(span)
	s.storeGeneratedWrite(flow, item.key, prior)

	return true, true
}
