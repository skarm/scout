package analyzer

import (
	"regexp"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
)

var credentialTypeLabel = regexp.MustCompile(`(?i)^[\t ]*\*{0,2}credential[ -]+types?(?:\(s\))?:\*{0,2}[\t ]*`)

func credentialPrecision(d document.File, m Match) bool {
	source := sourceForPattern(d)
	if source.kind&patternMarkdown == 0 {
		return false
	}

	at := source.line(m)
	start, end, text := at.Start, at.End, source.text

	if end-start > 256 {
		return false
	}

	line := text[start:end]

	prefix := credentialTypeLabel.FindStringIndex(line)
	if prefix == nil {
		return false
	}

	value := strings.TrimSpace(line[prefix[1]:])
	if strings.HasPrefix(value, "[") {
		if !strings.HasSuffix(value, "]") {
			return false
		}

		value = strings.TrimSpace(value[1 : len(value)-1])
	}

	switch strings.ToLower(value) {
	case "access token", "access tokens", "access credentials", "refresh token", "refresh tokens", "oauth access token", "oauth access tokens":
		return true
	}

	return false
}
