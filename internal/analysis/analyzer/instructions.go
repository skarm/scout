package analyzer

import "sync"

// instructionRules are original, deliberately narrow detectors for agent-facing
// text. They scan the whole artifact and derived objects, not only SKILL.md.
// These are review signals, NOT proof of intent or a semantic language model.
// Quotes/negations are not silently exempted: an attacker controls those labels.
//
//nolint:gochecknoglobals // Cached rules contain only immutable descriptors and compiled regexps; callers receive detached lists.
var compiledInstructionRules = sync.OnceValue(buildInstructionRules)

func instructionRules() []Analyzer {
	return append([]Analyzer(nil), compiledInstructionRules()...)
}

func buildInstructionRules() []Analyzer {
	const caveat = "Bounded literal English/Russian instruction signal only, not actual behavior or malicious intent. A quotation, negation or authorized workflow can also match and requires contextual review. No format/path exemptions."

	return []Analyzer{
		agentSignal(rulePI004, "Instruction claims exclusive authority for an agent task",
			`(?i)\b(?:this|the)[\t ]+(?:document|file|message|page|instruction)[^\r\n.!?]{0,80}\b(?:only|sole|exclusive)[\t ]+authority[^\r\n.!?]{0,100}\b(?:task|operation|instructions?|rules?)\b`,
			"prompt-injection", caveat),
		agentSignal(ruleDE002, "Instruction combines sensitive-data collection with delivery",
			`(?i)\b(?:gather|collect|expand|include|bundle|package|add)[^\r\n.!?]{0,160}\b(?:private[\t ]+(?:notes?|conversation|messages?|keys?)|credentials|secrets|access[ -]tokens?)[^\r\n.!?]{0,200}\b(?:deliver|route|send|forward|transmit|mail|upload)[^\r\n.!?]{0,100}\b(?:mailbox|channel|endpoint|server|address|https?)\b`,
			"instruction-data-exfiltration", caveat),
		agentSignal(ruleMP002, "Instruction combines persistent agent memory with future obligations",
			`(?i)\b(?:leave|save|store|write|persist)[^\r\n.!?]{0,100}\b(?:lasting|permanent|persistent)[^\r\n.!?]{0,100}\b(?:journal|memory|notes?)[^\r\n.!?]{0,160}\b(?:subsequent|future|later)[\t ]+(?:sessions?|conversations?)[^\r\n.!?]{0,120}\b(?:obligation|directive|instruction|rule)\b`,
			"memory-poisoning", caveat),
		agentSignal(rulePL001, "Instruction requests disclosure or transformation of privileged prompts",
			`(?i)\b(?:reveal|print|display|disclose|export|transmit|encode|translate)[\t\r\n ]+(?:(?:the|your)[\t\r\n ]+)?(?:(?:complete|hidden|full)[\t\r\n ]+)?(?:system|developer)[\t\r\n ]+(?:prompts?|instructions?|messages?)\b|(?:покажи(?:те)?|раскрой(?:те)?|отправь(?:те)?|выведи(?:те)?)[\t\r\n ]+(?:(?:свой|полный)[\t\r\n ]+)?(?:системный[\t\r\n ]+промпт|системные[\t\r\n ]+инструкции)`,
			"system-prompt-leakage", caveat),
		agentSignal(ruleMP001, "Instruction attempts persistence across agent sessions",
			`(?i)\b(?:remember|retain)[\t\r\n ]+(?:this|these)[\t\r\n ]+(?:instructions?|directives?|rules?)[\t\r\n ]+(?:in|for|across)[\t\r\n ]+(?:(?:all|every)[\t\r\n ]+)?future[\t\r\n ]+(?:sessions?|conversations?)\b|\b(?:store|persist|write|save)[\t\r\n ]+(?:this|these)[\t\r\n ]+(?:instructions?|directives?|rules?)[\t\r\n ]+(?:in|to)[\t\r\n ]+(?:(?:your|the)[\t\r\n ]+)?(?:persistent|long-term|permanent)[\t\r\n ]+memory\b|(?:запомни(?:те)?|сохрани(?:те)?)[\t\r\n ]+(?:эту[\t\r\n ]+инструкцию|это[\t\r\n ]+правило)[\t\r\n ]+для[\t\r\n ]+(?:всех[\t\r\n ]+)?будущих[\t\r\n ]+(?:сеансов|диалогов|сессий)`,
			"memory-poisoning", caveat),
		agentSignal(ruleDE001, "Instruction requests transfer of sensitive data to a destination",
			`(?i)\b(?:send|upload|post|forward|transmit)[\t\r\n ]+(?:(?:all|the)[\t\r\n ]+)?(?:user[\t\r\n ]+)?(?:api[ -]keys?|access[ -]tokens?|credentials|private[ -]keys?|environment[\t ]+variables|conversation[\t ]+history)[\t\r\n ]+(?:to|via)[\t\r\n ]+(?:https?://[^\s<>"']{1,256}|(?:an?[\t ]+)?(?:external|remote)[\t ]+(?:endpoint|server|service))|(?:отправь(?:те)?|передай(?:те)?|загрузи(?:те)?)[\t\r\n ]+(?:секреты|токены|учётные[\t ]+данные|приватный[\t ]+ключ|историю[\t ]+переписки)[\t\r\n ]+(?:на|в)[\t\r\n ]+https?://[^\s<>"']{1,256}`,
			"instruction-data-exfiltration", caveat+" The destination is text only; no URL is accessed and no sensitive data is read."),
		agentSignal(rulePI003, "Embedded chat delimiter claims a privileged instruction role",
			`(?i)<\|im_start\|>[\t ]*(?:system|developer)\b|<\|start_header_id\|>[\t ]*(?:system|developer)[\t ]*<\|end_header_id\|>`,
			"role-spoofing", caveat+" Only selected literal serialization markers; ordinary system/developer words and arbitrary XML are not classified by this rule."),
	}
}
