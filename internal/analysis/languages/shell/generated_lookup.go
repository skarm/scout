package shell

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

func (s *scriptScope) observeHash(args []*shellsyntax.Word) {
	explicit := false

	for len(args) > 0 {
		option, known := scriptPathWord(args[0], s.variables)
		if !known {
			s.hashUnsafe = s.hashUnsafe || explicit || len(args) > 1
			return
		}

		if option == "--" {
			args = args[1:]
			break
		}

		flags, short := strings.CutPrefix(option, "-")
		if !short || flags == "" {
			break
		}

		args = args[1:]

		prefix, pathname, setsPath := strings.Cut(flags, "p")
		if strings.Trim(prefix, "dlrt") != "" {
			return
		}

		if setsPath {
			if pathname == "" {
				if len(args) == 0 {
					return
				}

				args = args[1:]
			}

			explicit = true
		}
	}

	if !explicit {
		return
	}

	for _, operand := range args {
		name, known := scriptPathWord(operand, s.variables)
		s.hashUnsafe = s.hashUnsafe || !known || name == "cat" || name == "tee"
		s.consumerHashes |= shellConsumerBit(name)
	}
}

func (s *scriptScope) observePrintfAssignment(args []*shellsyntax.Word) {
	var (
		target            string
		assigns, resolved bool
	)

	for len(args) > 0 {
		option, known := scriptPathWord(args[0], s.variables)

		name, variable := strings.CutPrefix(option, "-v")
		if !known || !variable {
			break
		}

		args = args[1:]
		if name == "" {
			if len(args) == 0 {
				return
			}

			name, known = scriptPathWord(args[0], s.variables)
			args = args[1:]
		}

		target, assigns, resolved = name, true, known
	}

	if assigns && len(args) > 0 {
		s.observeVariableName(target, resolved)
	}
}

func (s *scriptScope) observeReferenceOptions(name string, args []*shellsyntax.Word) {
	if name == "nameref" {
		s.observeVariableName("", false)
		return
	}

	if name == "readonly" {
		return
	}

	for _, arg := range args {
		option, known := scriptPathWord(arg, s.variables)
		if !known || option == "--" || !strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "+") {
			return
		}

		if strings.HasPrefix(option, "-") && strings.Contains(option[1:], "n") {
			// An assignment through a nameref can change the lookup variables
			// even when the assignment itself names a different variable.
			s.observeVariableName("", false)
			return
		}
	}
}

func (s *scriptScope) observeSearchPathOperands(args []*shellsyntax.Word, unknownTarget bool) {
	for _, arg := range args {
		name, known := scriptPathWord(arg, s.variables)
		if !known {
			name, known = literalAssignmentName(arg)
		}

		if known || unknownTarget {
			s.observeVariableName(name, known)
		}
	}
}

func (s *scriptScope) observeReadTargets(args []*shellsyntax.Word) {
	for len(args) > 0 {
		option, known := scriptPathWord(args[0], s.variables)
		if !known || !strings.HasPrefix(option, "-") || option == "-" {
			break
		}

		args = args[1:]

		if option == "--" {
			break
		}

		flags := option[1:]

		at := strings.IndexAny(flags, "adinNptu")
		if at < 0 {
			continue
		}

		value, resolved := flags[at+1:], true
		if value == "" {
			if len(args) == 0 {
				return
			}

			value, resolved = scriptPathWord(args[0], s.variables)
			args = args[1:]
		}

		if flags[at] == 'a' {
			s.observeVariableName(value, resolved)
		}
	}

	s.observeSearchPathOperands(args, true)
}

func literalAssignmentName(word *shellsyntax.Word) (string, bool) {
	var prefix strings.Builder

	for _, part := range word.Parts {
		if part.Kind != "literal" {
			break
		}

		name, _, assigned := strings.Cut(part.Text, "=")
		prefix.WriteString(name)

		if assigned {
			return prefix.String(), true
		}
	}

	return "", false
}

func (s *scriptScope) observeVariableName(operand string, known bool) {
	if !known {
		s.pathUnsafe, s.cdpathUnsafe = true, true
		return
	}

	if end := strings.IndexAny(operand, "=["); end >= 0 {
		operand = operand[:end]
	}

	s.observeSearchPath(operand)
}
