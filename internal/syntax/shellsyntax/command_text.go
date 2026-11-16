package shellsyntax

import "strings"

// CommandTextIndex recognizes bounded shell options followed by code for -c.
// The second result flags a command that could not be projected exactly.
func CommandTextIndex(length int, operand func(int) (string, bool), allowDynamic bool) (int, bool) {
	var command, shortOptions, noexec bool

	for i := 0; i < length; i++ {
		value, ok := operand(i)
		if !ok {
			if command && !noexec && allowDynamic {
				return i, true
			}

			return -1, true
		}

		switch {
		case value == "-" || value == "--":
			return commandTextOperand(command && !noexec, i+1, length)
		case !strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "+") || value == "+":
			return commandTextOperand(command && !noexec, i, length)
		case !shortOptions && longShellOption(value):
			continue
		}

		shortOptions = true

		flags := value[1:]
		if flags == "o" {
			i++

			option, ok := namedShellOption(i, length, operand)
			if !ok {
				return -1, true
			}

			if option == "noexec" {
				noexec = value[0] == '-'
			}

			continue
		}

		if stop, uncertain := commandTextFlags(value[0], flags, &command, &noexec); stop {
			return -1, uncertain
		}
	}

	return -1, command && !noexec
}

func commandTextFlags(sign byte, flags string, command, noexec *bool) (stop, uncertain bool) {
	if strings.Trim(flags, "censufxvlpD") != "" || sign == '+' && strings.ContainsAny(flags, "cD") {
		return true, true
	}

	if strings.ContainsRune(flags, 'D') {
		return true, false
	}

	if strings.ContainsRune(flags, 'n') {
		*noexec = sign == '-'
	}

	*command = *command || strings.ContainsRune(flags, 'c')

	return false, false
}

func namedShellOption(index, length int, operand func(int) (string, bool)) (string, bool) {
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

func longShellOption(value string) bool {
	switch value {
	case "--noprofile", "--norc", "--login", "--posix":
		return true
	default:
		return false
	}
}

func commandTextOperand(command bool, index, length int) (int, bool) {
	if command && index < length {
		return index, false
	}

	return -1, command
}

// FileArgumentIndex returns the script operand of a supported shell launch.
// Flags that select command text, stdin, startup code or syntax-only mode
// are outside this file-operand grammar.
func FileArgumentIndex(length int, operand func(int) (string, bool)) int {
	shortOptions := false

	for i := 0; i < length; i++ {
		value, known := operand(i)
		if !known {
			return i // The trace must still prove the actual file value.
		}

		switch {
		case value == "--":
			if i+1 < length {
				return i + 1
			}

			return -1
		case !shortOptions && (value == "--noprofile" || value == "--norc"):
		case value == "-o":
			shortOptions = true
			i++

			if i >= length {
				return -1
			}

			if option, ok := operand(i); !ok || option != "pipefail" {
				return -1
			}
		case strings.HasPrefix(value, "-"):
			shortOptions = true

			if len(value) < 2 || strings.Trim(value[1:], "euExv") != "" {
				return -1
			}
		case strings.HasPrefix(value, "+"):
			return -1
		default:
			return i
		}
	}

	return -1
}
