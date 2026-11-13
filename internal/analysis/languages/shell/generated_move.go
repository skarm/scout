package shell

import (
	"path"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

func generatedMoveCommand(name string) bool {
	return name == "mv" || name == "/bin/mv" || name == "/usr/bin/mv"
}

func (s *generatedShellScan) observeGeneratedMove(c *shellsyntax.Command, scope *scriptScope, flow *generatedShellFlow, words []*shellsyntax.Word) bool {
	if len(c.Redirects) != 0 || !generatedMoveHead(c.Words) || scope.lookupUncertain(c.Words, words[0]) {
		return false
	}

	args := words[1:]
	if len(args) > 0 && (literalWordEquals(args[0], "-T") || literalWordEquals(args[0], "--no-target-directory")) {
		args = args[1:]
	}

	args = skipGeneratedOptionEnd(args)
	if len(args) != 2 {
		return false
	}

	from, fromKnown := scriptPathWord(args[0], scope.variables)

	to, toKnown := scriptPathWord(args[1], scope.variables)
	if !fromKnown || !toKnown || !localWritePath(from) || !localWritePath(to) || from == "." || to == "." {
		return false
	}

	from, to = flow.key(from), flow.key(to)
	if from == to || flow.knownDirectory(from) || flow.knownDirectory(to) || flow.hasFileParent(to) {
		return false
	}

	write, known := flow.files[from]
	if !known {
		// An unknown source could be a directory and affect descendants.
		return false
	}

	span, err := s.view.Original(c.Span)
	if err != nil {
		return false
	}

	delete(flow.files, from)
	write.addTransform(span)

	if pending := write.candidate; pending != nil && generatedShellName(to) {
		resolved, failure := s.resolveGeneratedCandidate(write)
		if failure.gap != 0 {
			s.noteGap(failure.at, failure.gap, failure.reason)
			delete(flow.files, to)

			return true
		}

		if retained, _ := s.retainGeneratedView(pending.at, pending.input, resolved.view, pending.functionBody); !retained {
			delete(flow.files, to)

			return true
		}

		write = resolved
		write.confirmed = true
	}

	s.storeGeneratedWrite(flow, to, write)

	return true
}

func (f *generatedShellFlow) hasFileParent(key string) bool {
	for dir := path.Dir(key); dir != "." && dir != "/"; dir = path.Dir(dir) {
		if _, file := f.files[dir]; file {
			return true
		}
	}

	return false
}

func generatedMoveHead(words []*shellsyntax.Word) bool {
	words, _ = scriptWriterWords(words)
	return len(words) > 0 && !literalWordEquals(words[0], "exec")
}

func (f *generatedShellFlow) knownDirectory(key string) bool {
	prefix := key + "/"
	if f.cwd == key || strings.HasPrefix(f.cwd, prefix) || f.previous == key || strings.HasPrefix(f.previous, prefix) {
		return true
	}

	for name := range f.files {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}
