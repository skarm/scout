package filetype

import (
	"path"
	"strings"
)

// Surface is a non-authoritative display hint, never a trust or suppression
// decision. A malicious author can name a file tests/payload or LICENSE.
func Surface(name string) string {
	switch strings.ToLower(path.Base(name)) {
	case "skill.md", "agents.md", "claude.md":
		return "instructions"
	}

	for part := range strings.SplitSeq(name, "/") {
		switch strings.ToLower(part) {
		case "tests", "test", "testdata", "fixtures", "evals":
			return "tests"
		}
	}

	if strings.HasPrefix(strings.ToUpper(path.Base(name)), "LICENSE") {
		return "license"
	}

	switch strings.ToLower(path.Ext(name)) {
	case ".sh", ".bash", ".py", ".go", ".js", ".ts", ".jsx", ".tsx", ".ps1", ".rb", ".pl", ".bat", ".cmd":
		return "code"
	case ".json", ".yaml", ".yml", ".toml", ".ini":
		return "config"
	case ".md", ".txt", ".rst":
		return "docs"
	}

	return "other"
}
