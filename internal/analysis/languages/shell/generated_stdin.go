package shell

import (
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

func (s *generatedShellScan) recoverDirectStdin(c *shellsyntax.Command, scope *scriptScope) bool {
	input, modeled := generatedStdinRedirect(c)
	if !modeled || input == nil || !generatedShellReadsStdin(c, scope) {
		return true
	}

	return s.recoverStdin(c, input, scope)
}

func (s *generatedShellScan) recoverPipedStdin(stmt *shellsyntax.Statement, scope *scriptScope) bool {
	if len(stmt.Commands) != 2 || len(stmt.Pipes) != 1 || stmt.Pipes[0] != "|" {
		return true
	}

	producer, consumer := stmt.Commands[0], stmt.Commands[1]
	if input, modeled := generatedStdinRedirect(consumer); !modeled || input != nil || !generatedShellReadsStdin(consumer, scope) {
		return true
	}

	input := generatedPipeHeredoc(producer, scope)
	if input == nil {
		return true
	}

	return s.recoverStdin(producer, input, scope)
}

func generatedPipeHeredoc(c *shellsyntax.Command, scope *scriptScope) *shellsyntax.Redirect {
	if len(c.Words) == 0 || len(c.Assignments) != 0 {
		return nil
	}

	input, output := generatedWriterRedirects(c.Redirects)

	words, bypass := scriptWriterWords(c.Words)
	if input == nil || output != nil || len(words) == 0 {
		return nil
	}

	name, absolute := generatedWriterName(words[0])

	args := skipGeneratedOptionEnd(words[1:])
	if name != "cat" || len(args) > 1 || len(args) == 1 && !literalWordEquals(args[0], "-") {
		return nil
	}

	if bypass && scope.shadow.shadows(c.Words[0], false) || scope.shadow.shadows(words[0], bypass || absolute) || scope.lookupUncertain(c.Words, words[0]) {
		return nil
	}

	return input
}

// Only ordinary output redirections are independent of the selected stdin.
func generatedStdinRedirect(c *shellsyntax.Command) (*shellsyntax.Redirect, bool) {
	var input *shellsyntax.Redirect

	for _, r := range c.Redirects {
		if r.FD != "" && generatedFD(r.FD) == "0" || r.FD == "" && strings.HasPrefix(r.Op, "<") {
			if input != nil || r.Op != "<<" && r.Op != "<<-" {
				return nil, false
			}

			input = r

			continue
		}

		if (r.Op != ">" && r.Op != ">>" && r.Op != ">|") || generatedRedirectRunsCode(r) {
			return nil, false
		}
	}

	return input, true
}

func generatedShellReadsStdin(c *shellsyntax.Command, scope *scriptScope) bool {
	if len(c.Words) == 0 {
		return false
	}

	words, name, known := generatedUseWords(c, scope)
	if !known || !isShellInterpreter(name) || scope.lookupUncertain(c.Words, words[0]) {
		return false
	}

	args := make([]shellValue, 0, len(words)-1)
	for _, word := range words[1:] {
		value, ok := scriptPathWord(word, scope.variables)
		args = append(args, shellValue{text: value, known: ok})
	}

	_, stdin := shellExecution(args)

	return stdin
}

func (s *generatedShellScan) recoverStdin(c *shellsyntax.Command, input *shellsyntax.Redirect, scope *scriptScope) bool {
	at := c.Span.Start
	if input.Body == nil || !input.BodyVerified {
		s.noteGap(at, document.GeneratedShellUnrecovered, document.GeneratedShellInput)
		return true
	}

	if input.Body.Span.Start == input.Body.Span.End {
		return true
	}

	if !analysisbudget.Consume(s.ctx, 1) {
		s.noteGap(at, document.GeneratedShellUnrecovered, document.GeneratedShellLimit)
		return false
	}

	view, reason := scriptHeredocView(s.view, input, scope.variables)
	if reason != "" {
		s.noteGap(at, document.GeneratedShellUnrecovered, reason)
		return true
	}

	_, more := s.retainGeneratedView(at, input, view, scope.functionBody)

	return more
}
