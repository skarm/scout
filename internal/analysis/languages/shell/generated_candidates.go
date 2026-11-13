package shell

import (
	"maps"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

// A write without shell evidence keeps its source and bindings, so ordinary
// data files do not spend the recovery quota or become parser inputs.
type generatedShellCandidate struct {
	input        *shellsyntax.Redirect
	variables    map[string]string
	prior        *generatedShellWrite
	reason       document.GeneratedShellReason
	at, depth    int
	gap          document.GeneratedShellGaps
	functionBody bool
}

func (w generatedShellWrite) knownEmpty() bool {
	if w.candidate == nil {
		return w.view.Text() == ""
	}

	return w.candidate.gap == 0 && w.candidate.prior == nil && w.candidate.input.Body.Span.Start == w.candidate.input.Body.Span.End
}

type candidateFailure struct {
	gap    document.GeneratedShellGaps
	reason document.GeneratedShellReason
	at     int
}

func (c *generatedShellCandidate) failed(reason document.GeneratedShellReason) candidateFailure {
	gap := document.GeneratedShellUnrecovered
	if c.prior != nil {
		gap = document.GeneratedShellAppend
		if reason == document.GeneratedShellLimit {
			gap |= document.GeneratedShellUnrecovered
		}
	}

	return candidateFailure{gap: gap, at: c.at, reason: reason}
}

func newGeneratedCandidate(c *shellsyntax.Command, input *shellsyntax.Redirect, scope *scriptScope) *generatedShellCandidate {
	candidate := &generatedShellCandidate{input: input, at: c.Span.Start, depth: 1, functionBody: scope.functionBody}
	if !input.QuotedDelimiter && len(scope.variables) != 0 {
		candidate.variables = maps.Clone(scope.variables)
	}

	return candidate
}

func (s *generatedShellScan) useGeneratedWrite(c *shellsyntax.Command, target string, write generatedShellWrite, direct bool) {
	if direct && !generatedShellName(target) && write.foreignShebang {
		return
	}

	if pending := write.candidate; pending != nil {
		resolved, failure := s.resolveGeneratedCandidate(write)
		if failure.gap != 0 {
			s.noteGap(failure.at, failure.gap, failure.reason)
			return
		}

		if direct && !generatedShellName(target) && strings.HasPrefix(resolved.view.Text(), "#!") && !shellShebang(resolved.view.Text()) {
			return
		}

		if retained, _ := s.retainGeneratedView(pending.at, pending.input, resolved.view, pending.functionBody); !retained {
			return
		}

		write = resolved
	}

	if write.view.Text() != "" {
		s.recordGeneratedUse(c, write)
	}
}

func (s *generatedShellScan) resolveGeneratedCandidate(write generatedShellWrite) (generatedShellWrite, candidateFailure) {
	layers := make([]generatedShellWrite, 0, write.candidate.depth)
	for write.candidate != nil {
		pending := write.candidate
		if pending.gap != 0 {
			return generatedShellWrite{}, candidateFailure{gap: pending.gap, reason: pending.reason, at: pending.at}
		}

		layers = append(layers, write)

		if pending.prior == nil {
			break
		}

		write = *pending.prior
	}

	parts := []source.View{write.view}

	bytes := len(write.view.Text())
	if write.candidate != nil {
		write.clearTransforms()
	}

	write.candidate = nil

	for _, step := range slices.Backward(layers) {
		layer := step.candidate
		if !analysisbudget.Consume(s.ctx, 1) {
			return generatedShellWrite{}, layer.failed(document.GeneratedShellLimit)
		}

		body, reason := scriptHeredocView(s.view, layer.input, layer.variables)
		if reason != "" {
			return generatedShellWrite{}, layer.failed(reason)
		}

		if body.Text() != "" {
			bytes += len(body.Text())
			if bytes > shellsyntax.MaxBytes {
				return generatedShellWrite{}, layer.failed(document.GeneratedShellLimit)
			}

			span, err := body.Original(source.Span{End: len(body.Text())})
			if err != nil {
				return generatedShellWrite{}, layer.failed(document.GeneratedShellInput)
			}

			if layer.prior == nil {
				write.body = span
				parts[0] = body
			} else {
				write.addTransform(span)

				parts = append(parts, body)
			}
		}

		write.addTransforms(step)
	}

	write.view = parts[0]
	if len(parts) > 1 {
		write.view = source.Concat(parts...)
	}

	return write, candidateFailure{}
}

func (w *generatedShellWrite) addTransform(span source.Span) {
	if w.transformCount < len(w.transforms) {
		w.transforms[w.transformCount] = span
	}

	w.transformCount++
}

func (w *generatedShellWrite) addTransforms(other generatedShellWrite) {
	for _, span := range other.transforms[:min(other.transformCount, len(other.transforms))] {
		w.addTransform(span)
	}

	w.transformCount += max(0, other.transformCount-len(other.transforms))
}

func (w *generatedShellWrite) clearTransforms() {
	clear(w.transforms[:])
	w.transformCount = 0
}

// Only the first logical line is needed to select the interpreter. Keep the
// check bounded, and apply the same tab stripping and expansion as recovery.
func generatedHeredocPreamble(parent source.View, input *shellsyntax.Redirect, vars map[string]string) string {
	if input.Body == nil || !input.BodyVerified {
		return ""
	}

	span := input.Body.Span
	text := parent.Text()

	if span.Start < 0 || span.Start >= span.End || span.End > len(text) {
		return ""
	}

	raw := text[span.Start:span.End]
	prefix := raw

	if input.Op == "<<-" {
		prefix = strings.TrimLeft(prefix, "\t")
	}

	if prefix == "" || !strings.ContainsRune("#$\\`", rune(prefix[0])) {
		return ""
	}

	const maxPreamble = 512

	width := generatedPreambleWidth(raw[:min(len(raw), maxPreamble+1)], input.QuotedDelimiter)
	if width > maxPreamble {
		return ""
	}

	if input.QuotedDelimiter {
		return prefix[:width-(len(raw)-len(prefix))]
	}

	header, body := *input, *input.Body
	body.Span.End = span.Start + width
	header.Body = &body

	view, reason := scriptHeredocView(parent, &header, vars)
	if reason == "" {
		return view.Text()
	}

	// An unknown argument after a literal interpreter does not hide a
	// shell shebang. Full recovery will report the unresolved expansion.
	if shellShebang(prefix) {
		return prefix
	}

	return ""
}

func generatedPreambleWidth(raw string, quoted bool) int {
	for i := 0; i < len(raw); i++ {
		if !quoted && raw[i] == '\\' && i+1 < len(raw) && strings.ContainsRune("\\\n", rune(raw[i+1])) {
			i++
			continue
		}

		if raw[i] == '\n' {
			return i + 1
		}
	}

	return len(raw)
}

func shellShebang(text string) bool {
	hint, ok := language.Shebang(text)
	return ok && hint.Language == language.Shell
}
