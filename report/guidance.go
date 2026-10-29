package report

import (
	"fmt"
	"html"
	"strings"
)

func ruleGuides(rules []Rule) map[string]*Guidance {
	out := make(map[string]*Guidance, len(rules))
	for _, r := range rules {
		if r.Guidance != nil {
			out[r.ID] = r.Guidance
		}
	}

	return out
}

// Guides are compiled scanner-authored material. No model prose or source
// excerpts are rendered; context labels are advisory, never exemptions.
func writeRuleGuidance(b *strings.Builder, g *Guidance, signals []string, markdown bool) {
	if g != nil {
		if markdown {
			_, _ = fmt.Fprintf(b, "**Why review:** %s\n\n**Remediation:** %s\n\n", html.EscapeString(g.Explanation), html.EscapeString(g.Remediation))
			_, _ = fmt.Fprintf(b, "**Check:** %s\n\n", html.EscapeString(strings.Join(g.ReviewChecks, "; ")))
			_, _ = fmt.Fprintf(b, "**Benign considerations:** %s\n\n", html.EscapeString(strings.Join(g.BenignConsiderations, "; ")))
		} else {
			_, _ = fmt.Fprintf(b, "  Why review: %s\n  Remediation: %s\n", g.Explanation, g.Remediation)
		}
	}

	for _, s := range signals {
		if markdown {
			_, _ = fmt.Fprintf(b, "Context hint: %s (not an exemption).\n\n", mdCode(s))
		} else {
			_, _ = fmt.Fprintf(b, "  Context hint: %s (not an exemption)\n", s)
		}
	}
}
