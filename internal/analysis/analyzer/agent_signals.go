package analyzer

import (
	"regexp"
	"sync"

	"github.com/skarm/scout/report"
)

// Agent signals flag literal wording in installable instructions.
//
//nolint:gochecknoglobals // Cached rules contain only immutable descriptors and compiled regexps; callers receive detached lists.
var compiledAgentRules = sync.OnceValue(buildAgentRules)

func agentRules() []Analyzer {
	return append([]Analyzer(nil), compiledAgentRules()...)
}

func buildAgentRules() []Analyzer {
	return []Analyzer{
		agentSignal(rulePI002, "Instruction to conceal actions from the user", `(?i)\b(?:do not|don't|never)[\t ]+(?:tell|inform|notify)[\t ]+(?:the[\t ]+)?user\b|(?i:не)[\t ]+(?:сообщай(?:те)?|рассказывай(?:те)?|уведомляй(?:те)?)[\t ]+пользовател(?:ю|я)`, "prompt-injection", "Narrow English/Russian concealment wording only; quotation, legitimate privacy instructions and negation require review."),
		agentSignal(ruleAG001, "Agent approval or sandbox bypass flag is referenced", `(?:--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox)\b`, "approval-bypass", "A literal flag reference, not proof of invocation. A prohibition or example can match; host restrictions are not evaluated."),
		agentSignal(ruleAG002, "Claude-style dynamic context command marker", "(?m)(?:^|[\\t ])!`[^`\\r\\n]+`", "preprocessing-execution", "Recognizes a single-line marker, not all Claude preprocessing forms. It can be an example, is not executed, and is not classified as malicious by itself."),
	}
}

func agentSignal(id, title, expression, category, limitation string) Analyzer {
	return literal{
		rule: report.Rule{
			ID: id, Version: "1", Title: title, Description: title,
			Severity: report.Medium, Category: category, Method: "literal-agent-signal", Limitation: limitation,
		},
		expression: regexp.MustCompile(expression),
		hint:       literalFilter(expression),
	}
}
