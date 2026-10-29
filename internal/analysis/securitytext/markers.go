package securitytext

import (
	"context"
	"regexp"
	"strings"

	"github.com/skarm/scout/internal/syntax/source"
)

// A selected, explicitly declared literal removal followed by a quoted command.
// This creates an inspection view, never an instruction to execute that command.
var (
	markerDirective   = regexp.MustCompile(`(?i)\b(?:remove|strip|delete|drop)\s+['"]([^'"\r\n]{1,16})['"][^\r\n]{0,128}?\b(?:execute|run|call)\s+['"]([^'"\r\n]{1,1000})['"]`)
	markerProhibition = regexp.MustCompile(`(?i)(?:do\s+not|don't|never)\s+$`)
)

func declaredMarkers(ctx context.Context, text string) ([]source.Replacement, bool) {
	out := make([]source.Replacement, 0)

	matches := markerDirective.FindAllStringSubmatchIndex(text, 1025)
	if len(matches) > 1024 {
		return nil, true
	}

	for _, match := range matches {
		if ctx.Err() != nil {
			return out, true
		}

		marker, payload, valid := markerPayload(text, match)
		if !valid {
			continue
		}

		var limited bool

		out, limited = appendMarkerReplacements(out, marker, payload, match[4])
		if limited {
			return nil, true
		}
	}

	return out, false
}

func markerPayload(text string, match []int) (string, string, bool) {
	left := max(0, match[0]-128)
	if at := strings.LastIndexAny(text[left:match[0]], "\r\n.!?;"); at >= 0 {
		left += at + 1
	}

	if markerProhibition.MatchString(text[left:match[0]]) {
		return "", "", false
	}

	marker := text[match[2]:match[3]]

	payload := text[match[4]:match[5]]
	if strings.ContainsAny(marker, " \t\\") || !strings.Contains(payload, marker) {
		return "", "", false
	}

	return marker, payload, true
}

func appendMarkerReplacements(out []source.Replacement, marker, payload string, start int) ([]source.Replacement, bool) {
	for at := 0; at < len(payload); {
		next := strings.Index(payload[at:], marker)
		if next < 0 {
			break
		}

		at += next
		out = append(out, source.Replacement{Span: source.Span{Start: start + at, End: start + at + len(marker)}})

		at += len(marker)
		if len(out) > MaxChanges {
			return nil, true
		}
	}

	return out, false
}
