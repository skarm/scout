// Package analyzer assembles bounded language, literal and configuration checks.
// The checks do not establish malicious intent or full semantic coverage.
package analyzer

import (
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/skarm/scout/internal/analysis/bundle"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/golang"
	"github.com/skarm/scout/internal/analysis/languages/javascript"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/analysis/languages/sql"
	"github.com/skarm/scout/internal/analysis/rendertext"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/filetype"

	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var literalGuards = map[string]func(string, int, int) bool{rulePL001: promptPatternExempt}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var instructionFilenames = stringSet("skill.md agents.md claude.md")

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

// Builtins returns a new registry. Fences, tests, LICENSE and hidden directories
// do not disable rules. Findings describe matched text, not proven intent.
func Builtins() []Analyzer {
	rules := []Analyzer{
		newLiteral(rulePI001, "Instruction-hierarchy override phrase", `(?i)\b(?:ignore|disregard|override)[\t ]+(?:all[\t ]+)?(?:previous|prior|system)[\t ]+(?:instructions?|prompts?|rules?)\b|(?i:игнорируй(?:те)?|проигнорируй(?:те)?)[\t ]+(?:все[\t ]+)?(?:предыдущие|системные)[\t ]+инструкции`, report.Medium, "prompt-injection", "Literal English/Russian phrases only; negation, quotation and intent require review. No automatic suppression in examples."),
		newLiteral(ruleEX001, "Download piped to a shell", `(?im)\b(?:curl|wget)\b[^\r\n|]+\|[\t ]*(?:(?:sudo|env)[\t ]+)?(?:ba|da|z|k)?sh\b`, report.High, "remote-execution", "Single-line literal pipeline only; aliases, constructed commands and shell grammar are not analyzed. A match may be an example."),
		newLiteral(ruleSE001, "Private-key PEM marker", `-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`, report.High, "credential-material", "Marker only; not proof of a valid or live key. Values and source excerpts are never included in reports."),
		newLiteral(ruleFS001, "Sensitive credential-path reference", `(?:~|\$HOME|\$\{HOME\})/\.ssh/(?:id_rsa|id_ed25519)\b|/etc/shadow\b|(?:~|\$HOME|\$\{HOME\})/\.aws/credentials\b`, report.Medium, "credential-access", "Literal path reference only, not a confirmed read or data-flow. Constructed paths require future AST analysis."),
		opaque{},
		moduleCheck{id: ruleSC002},
		moduleCheck{id: ruleSC003},
	}
	rules = append(rules, rendertext.Rules()...)
	// Keep descriptor ordering stable across the package split.
	goRules := golang.Rules()
	rules = append(rules, goRules[:4]...)
	rules = append(rules, shell.Rules()...)
	rules = append(rules, agentRules()...)
	rules = append(rules, instructionRules()...)
	rules = append(rules, javascript.Rules()...)
	rules = append(rules, sql.Rules()...)
	rules = append(rules, goRules[4:]...)
	rules = append(rules, bundle.Rules()...)

	return append(rules, artifactIntegrityRules()...)
}

func IsOpaqueExecutable(f artifact.File) bool {
	return filetype.Inspect(f.Metadata().Path, f.Content(), f.Metadata().Executable).Executable
}

// Surface is a non-authoritative display hint, never a trust or suppression
// decision. A malicious author can name a file tests/payload or LICENSE.
func Surface(name string) string {
	if instructionFilenames[strings.ToLower(path.Base(name))] {
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
