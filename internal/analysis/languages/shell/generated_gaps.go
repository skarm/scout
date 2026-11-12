package shell

import (
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

// Recognize writes even when their paths or contents cannot be recovered.
// This check never supplies a body or a write-to-execution link.
func generatedShellWriteGaps(c *shellsyntax.Command, vars map[string]string) document.GeneratedShellGaps {
	if len(c.Words) == 0 || len(c.Redirects) == 0 {
		return 0
	}

	words, _ := scriptWriterWords(c.Words)
	if len(words) == 0 {
		return 0
	}

	name, _ := generatedWriterName(words[0])
	if name != "cat" && name != "tee" {
		return 0
	}

	input, output := generatedWriteDescriptors(c.Redirects, vars)
	if input == nil || input.Op != "<<" && input.Op != "<<-" ||
		input.BodyVerified && input.Body != nil && input.Body.Span.Start == input.Body.Span.End {
		return 0
	}

	var targets generatedWriteTargets

	if output != nil {
		switch output.Op {
		case ">", ">|", "&>", "<>", ">&":
			targets.observe(output.Target, vars, false)
		case ">>", "&>>":
			targets.observe(output.Target, vars, true)
		}
	}

	if name == "cat" {
		if !catReadsHeredoc(words[1:], vars, false) && !catReadsHeredoc(words[1:], vars, true) {
			return 0
		}
	} else {
		// GNU tee can parse options after a filename. BSD tee stops there.
		gnu := targets.teeOperands(words[1:], vars, false)

		bsd := targets.teeOperands(words[1:], vars, true)
		if !gnu && !bsd {
			return 0
		}
	}

	if !targets.script {
		return 0
	}

	var gaps document.GeneratedShellGaps
	if targets.dynamic {
		gaps |= document.GeneratedShellDynamicPath
	}

	if targets.appendScript {
		gaps |= document.GeneratedShellAppend
	}

	if gaps == 0 {
		gaps = document.GeneratedShellUnrecovered
	}

	return gaps
}

// Redirections take effect left to right. Copies keep the destination at the
// time of duplication, even if the original descriptor is redirected later.
func generatedWriteDescriptors(redirects []*shellsyntax.Redirect, vars map[string]string) (input, output *shellsyntax.Redirect) {
	fds := make(map[string]*shellsyntax.Redirect)

	for _, r := range redirects {
		fd := r.FD
		if fd == "" {
			fd = "1"
			if strings.HasPrefix(r.Op, "<") {
				fd = "0"
			}
		}

		switch r.Op {
		case "&>", "&>>":
			fds["1"], fds["2"] = r, r
		case "<&", ">&":
			if !generatedDuplicateDescriptor(fds, fd, r, vars) {
				return nil, nil
			}
		default:
			fds[generatedFD(fd)] = r
		}
	}

	return fds["0"], fds["1"]
}

func generatedDuplicateDescriptor(fds map[string]*shellsyntax.Redirect, fd string, r *shellsyntax.Redirect, vars map[string]string) bool {
	fd = generatedFD(fd)
	value, known := scriptPathWord(r.Target, vars)

	number, move := strings.CutSuffix(value, "-")
	switch {
	case known && number != "" && strings.Trim(number, "0123456789") == "":
		from := generatedFD(number)

		src, tracked := fds[from]
		if tracked && src == nil {
			return false
		}

		// An inherited descriptor has an unknown destination. A nil map
		// entry records an explicitly closed descriptor.
		if tracked {
			fds[fd] = src
		} else {
			delete(fds, fd)
		}

		if move && from != fd {
			fds[from] = nil
		}
	case known && value == "-":
		fds[fd] = nil
	case r.Op == ">&" && fd == "1":
		// Bash also accepts [1]>&filename as a combined stdout/stderr write.
		if known && value == "" {
			return false
		}

		fds["1"], fds["2"] = r, r
	case known:
		return false
	default:
		delete(fds, fd)
	}

	return true
}

func generatedFD(fd string) string {
	if digits := strings.TrimLeft(fd, "0"); digits != "" {
		return digits
	}

	return "0"
}

func catReadsHeredoc(args []*shellsyntax.Word, vars map[string]string, bsd bool) bool {
	options := true

	var stdin, files bool

	for _, arg := range args {
		value, _ := scriptPathWord(arg, vars)
		if options && value != "-" && strings.HasPrefix(value, "-") {
			if value == "--" {
				options = false
			} else if !catHeredocOption(value, bsd) {
				return false
			}

			continue
		}

		stdin = stdin || value == "-" || value == "/dev/stdin" || value == "/dev/fd/0"
		files = true
		options = options && !bsd
	}

	return stdin || !files
}

func catHeredocOption(value string, bsd bool) bool {
	if bsd {
		return strings.Trim(value[1:], "belnstuv") == ""
	}

	switch value {
	case "--show-all", "--number-nonblank", "--show-ends", "--number", "--squeeze-blank", "--show-tabs", "--show-nonprinting":
		return true
	}

	return strings.Trim(value[1:], "AbeEnstTuv") == ""
}

type generatedWriteTargets struct {
	script, dynamic, appendScript bool
}

func (t *generatedWriteTargets) observe(word *shellsyntax.Word, vars map[string]string, appendMode bool) {
	value, known := scriptPathWord(word, vars)

	script := known && generatedScriptDestination(value)
	if !known {
		t.dynamic = true
		script = dynamicScriptPath(word, vars)
	}

	t.script = t.script || script
	t.appendScript = t.appendScript || script && appendMode
}

func generatedScriptDestination(value string) bool {
	// Redirect targets and operands after -- may begin with a dash.
	if strings.HasPrefix(value, "-") {
		value = "./" + value
	}

	return strings.HasSuffix(value, ".sh") && localWritePath(value)
}

func (t *generatedWriteTargets) teeOperands(args []*shellsyntax.Word, vars map[string]string, bsd bool) bool {
	appendMode := false

	// Options can appear after operands. Determine the mode before classifying
	// any destination, and honor -- for filenames that look like options.
	for _, arg := range args {
		value, _ := scriptPathWord(arg, vars)
		if value == "--" {
			break
		}

		if !strings.HasPrefix(value, "-") || value == "-" {
			if bsd {
				break
			}

			continue
		}

		appendOption, writes := teeWriteOption(value, bsd)
		if !writes {
			return false
		}

		appendMode = appendMode || appendOption
	}

	options := true

	for _, arg := range args {
		value, _ := scriptPathWord(arg, vars)
		switch {
		case options && value == "--":
			options = false
		case options && strings.HasPrefix(value, "-") && value != "-":
		default:
			t.observe(arg, vars, appendMode)

			options = options && !bsd
		}
	}

	return true
}

func teeWriteOption(value string, bsd bool) (appendMode, writes bool) {
	allowed := "aip"
	if bsd {
		allowed = "ai"
	}

	if bsd || !strings.HasPrefix(value, "--") {
		flags := value[1:]
		return strings.Contains(flags, "a"), strings.Trim(flags, allowed) == ""
	}

	name, mode, hasMode := strings.Cut(value, "=")
	// GNU long options also accept unambiguous abbreviations.
	switch {
	case teeAbbreviates(name, "--append"):
		return true, !hasMode
	case teeAbbreviates(name, "--ignore-interrupts"):
		return false, !hasMode
	case teeAbbreviates(name, "--output-error"):
		return false, !hasMode || mode == "warn" || mode == "exit" ||
			strings.HasPrefix(mode, "warn-") && teeAbbreviates(mode, "warn-nopipe") ||
			strings.HasPrefix(mode, "exit-") && teeAbbreviates(mode, "exit-nopipe")
	}

	return false, false
}

func teeAbbreviates(candidate, full string) bool {
	return strings.HasPrefix(full, candidate)
}

func dynamicScriptPath(word *shellsyntax.Word, vars map[string]string) bool {
	if value, known := sourceWord(word, vars); known {
		// An unquoted parameter may split or glob even with a known value.
		return generatedScriptDestination(value)
	}

	if word == nil || fixedNonlocalScriptPath(word) {
		return false
	}

	// Retain only the suffix after the last unresolved expansion. This also
	// handles extensions split across adjacent quoted and unquoted literals.
	const extension = ".sh"

	var tail string

	for i := len(word.Parts) - 1; i >= 0; i-- {
		part := word.Parts[i]

		var value string

		switch part.Kind {
		case "literal":
			value = part.Text
		case "parameter":
			var known bool

			value, known = vars[part.Text]
			if !known || word.Expands {
				return false
			}
		default:
			return false
		}

		n := min(len(value), len(extension)-len(tail))

		tail = value[len(value)-n:] + tail
		if len(tail) == len(extension) {
			return tail == extension
		}
	}

	return false
}

func fixedNonlocalScriptPath(word *shellsyntax.Word) bool {
	const parent = "../"

	var prefix strings.Builder

	expansion := false

	for _, part := range word.Parts {
		if part.Kind != "literal" {
			// An unquoted expansion can supply separate relative operands.
			if !part.Quoted {
				return false
			}

			expansion = true
		}

		if !expansion {
			prefix.WriteString(part.Text[:min(len(part.Text), len(parent)-prefix.Len())])
		}
	}

	return strings.HasPrefix(prefix.String(), "/") || prefix.String() == parent
}
