package dependencies

import (
	"context"
	"strings"
)

// Source options affect every requirement, including preceding lines. Only
// literal public indexes retain the default declaration identity; includes and
// alternate candidate locations stay unresolved without opening anything.
func requirementsPublicSource(ctx context.Context, text string) bool {
	public := true

	for line := range strings.SplitSeq(text, "\n") {
		if ctx.Err() != nil {
			return false
		}

		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-") {
			continue
		}
		// Continuations and escaped option tokens require pip's lexer. Do not
		// infer a public source from a partially recognized global option line.
		if strings.Contains(line, "\\") {
			return false
		}

		var resolved bool

		public, resolved = requirementsSourceLine(line, public)
		if !resolved {
			return false
		}
	}

	return public
}

func requirementsSourceLine(line string, public bool) (bool, bool) {
	words := strings.Fields(line)
	for i := 0; i < len(words); i++ {
		if strings.HasPrefix(words[i], "#") {
			break
		}

		flag, value, attached := strings.Cut(words[i], "=")
		if !strings.HasPrefix(flag, "--") && len(flag) > 2 {
			flag, value, attached = flag[:2], words[i][2:], true
		}

		switch flag {
		case "--no-index", "--find-links", "-f", "--requirement", "-r", "--constraint", "-c":
			return false, false
		case "--index-url", "-i", "--extra-index-url":
			if !attached && i+1 < len(words) {
				i++
				value = words[i]
			}

			if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
				value = value[1 : len(value)-1]
			}

			known := publicPythonRegistry(value)
			if flag == "--extra-index-url" && !known {
				return false, false
			}

			if flag != "--extra-index-url" {
				public = known
			}
		}
	}

	return public, true
}
