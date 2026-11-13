package language

import (
	"path"
	"strings"
)

// Shebang classifies the selected interpreter in a first line. It does not
// infer a language from arguments to an unknown executable.
func Shebang(text string) (Hint, bool) {
	if !strings.HasPrefix(text, "#!") {
		return Hint{}, false
	}

	const maxLine = 512

	line, _, ended := strings.Cut(text[:min(len(text), maxLine+1)], "\n")
	if !ended && len(text) > maxLine {
		return Hint{}, false
	}

	fields := strings.Fields(line[2:])
	if len(fields) == 0 {
		return Hint{}, false
	}

	exe, args := shebangExecutable(fields[0]), fields[1:]
	if exe == "env" {
		exe, args = envShebang(args)
	}

	if exe == "uv" && len(args) > 0 && args[0] == "run" {
		return Hint{Language: Python, Basis: "uv-shebang"}, true
	}

	id := shebangLanguage(exe)

	return Hint{Language: id, Basis: "shebang"}, id != Unknown
}

func shebangLanguage(exe string) string {
	if strings.HasPrefix(exe, "python2.") || strings.HasPrefix(exe, "python3.") {
		return Python
	}

	switch exe {
	case "sh", "bash", "dash", "zsh", "ksh":
		return Shell
	case "Rscript":
		return r
	}

	id := Normalize(exe)
	if id != Shell && Structured(id) {
		return id
	}

	return Unknown
}

func shebangExecutable(word string) string {
	if strings.ContainsAny(word, "\x00\"'\\$`") || strings.HasSuffix(word, "/") {
		return ""
	}

	return path.Base(word)
}

func envShebang(args []string) (string, []string) {
	if len(args) == 1 && !strings.HasPrefix(args[0], "-") && !strings.Contains(args[0], "=") {
		return shebangExecutable(args[0]), nil
	}

	if len(args) < 2 || args[0] != "-S" && args[0] != "--split-string" {
		return "", nil
	}

	options := true

	for i, field := range args[1:] {
		switch {
		case options && field == "--":
			options = false
		case options && (field == "-i" || field == "--ignore-environment"):
		case strings.HasPrefix(field, "-"), strings.ContainsAny(field, "\x00\"'\\$`"):
			return "", nil
		case strings.Contains(field, "="):
			options = false
		default:
			return shebangExecutable(field), args[i+2:]
		}
	}

	return "", nil
}
