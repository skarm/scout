// Package analyzer assembles bounded language, literal and configuration checks.
// The checks do not establish malicious intent or full semantic coverage.
package analyzer

import (
	"context"
	"regexp"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/filetype"

	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var literalGuards = map[string]func(string, int, int) bool{rulePL001: promptPatternExempt}

type (
	Match    = check.Match
	Trace    = check.Trace
	Result   = check.Result
	Analyzer = check.Analyzer
)

type literal struct {
	rule       report.Rule
	expression *regexp.Regexp
}

type opaque struct{}

// literalRules checks every captured byte stream, including examples and hidden files.
func literalRules() []Analyzer {
	return []Analyzer{
		newLiteral(rulePI001, "Instruction-hierarchy override phrase", `(?i)\b(?:ignore|disregard|override)[\t ]+(?:all[\t ]+)?(?:previous|prior|system)[\t ]+(?:instructions?|prompts?|rules?)\b|(?i:игнорируй(?:те)?|проигнорируй(?:те)?)[\t ]+(?:все[\t ]+)?(?:предыдущие|системные)[\t ]+инструкции`, report.Medium, "prompt-injection", "Literal English/Russian phrases only; negation, quotation and intent require review. No automatic suppression in examples."),
		newLiteral(ruleEX001, "Download piped to a shell", `(?im)\b(?:curl|wget)\b[^\r\n|]+\|[\t ]*(?:(?:sudo|env)[\t ]+)?(?:ba|da|z|k)?sh\b`, report.High, "remote-execution", "Single-line literal pipeline only; aliases, constructed commands and shell grammar are not analyzed. A match may be an example."),
		newLiteral(ruleSE001, "Private-key PEM marker", `-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`, report.High, "credential-material", "Marker only; not proof of a valid or live key. Values and source excerpts are never included in reports."),
		newLiteral(ruleFS001, "Sensitive credential-path reference", `(?:~|\$HOME|\$\{HOME\})/\.ssh/(?:id_rsa|id_ed25519)\b|/etc/shadow\b|(?:~|\$HOME|\$\{HOME\})/\.aws/credentials\b`, report.Medium, "credential-access", "Literal path reference only, not a confirmed read or data-flow. Constructed paths require future AST analysis."),
	}
}

func IsOpaqueExecutable(f artifact.File) bool {
	return filetype.Inspect(f.Metadata().Path, f.Content(), f.Metadata().Executable).Executable
}

func newLiteral(id, title, expression string, severity report.Severity, category, limitation string) Analyzer {
	return literal{
		rule: report.Rule{
			ID: id, Version: "2", Title: title, Description: title,
			Severity: severity, Category: category, Method: "literal-heuristic", Limitation: limitation,
		},
		expression: regexp.MustCompile(expression),
	}
}

func (a literal) Rule() report.Rule { return a.rule }

// Scan every captured byte stream, including binary files. A NUL byte, invalid
// UTF-8, or image suffix must not disable basic literal checks. This does not
// decode encodings or compressed/embedded objects.

func (a literal) AppliesTo(document.File) bool { return true }

func (a literal) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	matcher := familyAnalyzer{patterns: []*regexp.Regexp{a.expression}, exempt: literalGuards[a.rule.ID]}

	out, err := matcher.findText(ctx, d.Artifact().Content(), max(1, budget))
	if budget < 1 && len(out.Matches) > 0 {
		return Result{Truncated: true}, err
	}

	if err != nil || out.Truncated {
		return out, err
	}

	collected := collectMatches(&out, budget)
	_, err = matcher.inspectSecurityViews(ctx, d, collected)

	return out, err
}

func (opaque) Rule() report.Rule {
	return report.Rule{
		ID:          ruleBI001,
		Version:     "2",
		Title:       "Opaque executable payload requires dedicated analysis",
		Description: "Compiled, executable or bytecode payload is present; this profile cannot inspect its behavior.",
		Severity:    report.High,
		Category:    "unverified-executable",
		Method:      "file-classification",
		Limitation:  "A suffix/signature is a candidate, not proof of type or maliciousness; the default policy refuses unverified executable payloads.",
	}
}
func (opaque) AppliesTo(f document.File) bool { return IsOpaqueExecutable(f.Artifact()) }
func (opaque) Find(ctx context.Context, f document.File, budget int) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	if budget < 1 {
		return Result{Truncated: true}, nil
	}

	return Result{Matches: []Match{{Start: 0, End: len(f.Artifact().Content())}}}, nil
}
