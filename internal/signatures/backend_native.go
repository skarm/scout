//go:build !coreonly && cgo

package signatures

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/skarm/scout/internal/analysis/promptguard"
	"github.com/skarm/scout/internal/buildinfo"
	"github.com/skarm/scout/report"

	yrx "github.com/VirusTotal/yara-x/go"
)

type nativeEngine struct {
	rules     *yrx.Rules
	scanner   *yrx.Scanner
	ownsRules bool
}

type nativeSource struct {
	data       []byte
	text       string
	longBase64 []Span
}

type nativeSpanCollector struct {
	spans     []Span
	seen      map[Span]bool
	rejected  bool
	truncated bool
}

// Backend reports the linked native capability. Library presence follows from
// successful linking, not filesystem probes. The binding has no native version API.
func Backend() Capability {
	return Capability{
		Name:           "yara-x",
		BindingVersion: buildinfo.ModuleVersion("github.com/VirusTotal/yara-x/go"),
		NativeVersion:  "unknown",
		Available:      true,
	}
}

func compileRules(ctx context.Context, source string) (compiledEngine, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}

	compiler, e := yrx.NewCompiler(yrx.EnableIncludes(false), yrx.BanModule("console", "disabled module", "console output is forbidden in a security scanner"), yrx.MaxWarnings(32), yrx.Globals(map[string]any{longBase64Global: false}))
	if e != nil {
		return nil, errors.New("YARA-X compiler initialization failed")
	}
	defer compiler.Destroy()

	if e = compileNativeSource(ctx, compiler, source); e != nil {
		return nil, e
	}

	rules, e := buildNativeRules(compiler)
	if e != nil {
		return nil, e
	}

	return ownNativeRules(rules)
}

func compileNativeSource(ctx context.Context, compiler *yrx.Compiler, source string) error {
	if err := compiler.AddSource(source); err != nil {
		return errors.New("YARA-X rules rejected")
	}

	return ctx.Err()
}

func buildNativeRules(compiler *yrx.Compiler) (*yrx.Rules, error) {
	rules := compiler.Build()
	if rules == nil {
		return nil, errors.New("YARA-X did not build rules")
	}

	if rules.Count() > 2048 {
		rules.Destroy()
		return nil, errors.New("YARA-X compiled rule limit")
	}

	return rules, nil
}

// ownNativeRules consumes the rules on success and failure. Only the returned
// parent engine owns them; forked engines borrow them until their scanner closes.
func ownNativeRules(rules *yrx.Rules) (compiledEngine, error) {
	scanner := yrx.NewScanner(rules)
	if scanner == nil {
		rules.Destroy()
		return nil, errors.New("YARA-X scanner initialization failed")
	}

	return &nativeEngine{rules: rules, scanner: scanner, ownsRules: true}, nil
}

func (e *nativeEngine) fork() (compiledEngine, error) {
	scanner := yrx.NewScanner(e.rules)
	if scanner == nil {
		return nil, errors.New("YARA-X scanner initialization failed")
	}

	return &nativeEngine{rules: e.rules, scanner: scanner}, nil
}

func (e *nativeEngine) scan(ctx context.Context, data []byte) (reply, error) {
	source := nativeSource{data: data, text: string(data), longBase64: longBase64Spans(data)}
	// Globals persist across scans. Set both true and false while this scanner
	// is exclusively borrowed, so a previous file cannot affect the next one.
	if err := e.scanner.SetGlobal(longBase64Global, len(source.longBase64) != 0); err != nil {
		return reply{}, errors.New("YARA-X built-in predicate initialization failed")
	}

	result, status, err := e.scanNative(ctx, data)
	if err != nil {
		return reply{}, err
	}

	out := reply{Status: status, Matches: []Match{}}
	if result == nil {
		return out, nil
	}

	out.Matches, out.Truncated, err = collectNativeRules(result.MatchingRules(), source)
	if err != nil {
		return reply{}, err
	}

	if ctx.Err() != nil {
		out.Status = report.OutcomePartial
	} // preserve already completed native evidence

	return out, nil
}

func (e *nativeEngine) scanNative(ctx context.Context, data []byte) (*yrx.ScanResults, string, error) {
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, report.OutcomeDeadline, nil
		}

		return nil, report.OutcomeCancelled, nil
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, "", errors.New("native scan requires a deadline")
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, report.OutcomeDeadline, nil
	}

	// The binding rounds positive durations UP to whole seconds. Flooring here
	// shortened the default 3s budget to 2s and skipped every sub-second scan.
	// Native timeouts are cooperative and share a second-resolution heartbeat;
	// the context check after projection still marks late evidence as partial.
	e.scanner.SetTimeout(remaining)

	result, err := e.scanner.Scan(data)
	// The Go binding returns a non-nil, empty result even on a native timeout.
	// The C API only emits rule callbacks after a successful scan; that empty
	// object is not completed or partial evidence.
	if err != nil {
		return nil, nativeFailureStatus(err), nil
	}

	if result == nil {
		return nil, "", errors.New("missing YARA-X scan results")
	}

	return result, report.OutcomeCompleted, nil
}

func (e *nativeEngine) close() {
	if e.scanner != nil {
		e.scanner.Destroy()
		e.scanner = nil
	}

	if e.ownsRules && e.rules != nil {
		e.rules.Destroy()
		e.rules = nil
	}
}

func nativeFailureStatus(err error) string {
	if errors.Is(err, yrx.ErrTimeout) {
		return report.OutcomeDeadline
	}

	return report.OutcomeFailed
}

func collectNativeRules(rules []*yrx.Rule, source nativeSource) ([]Match, bool, error) {
	matches := make([]Match, 0)
	truncated := false

	for _, rule := range rules {
		if len(matches) >= 32 {
			return matches, true, nil
		}

		match, accepted, limited, err := projectNativeRule(rule, source)
		if err != nil {
			return nil, false, err
		}

		truncated = truncated || limited

		if accepted {
			matches = append(matches, match)
		}
	}

	return matches, truncated, nil
}

func projectNativeRule(rule *yrx.Rule, source nativeSource) (Match, bool, bool, error) {
	match := Match{Rule: rule.Identifier(), Category: nativeRuleCategory(rule), Spans: []Span{}}
	patterns := rule.Patterns()
	// Retain an affirmative witness before weak markers can exhaust the eight
	// evidence slots. Ordering within each family remains native and stable.
	slices.SortStableFunc(patterns, func(a, b yrx.Pattern) int {
		return assessmentPatternRank(match.Rule, a.Identifier()) - assessmentPatternRank(match.Rule, b.Identifier())
	})

	severity, eligible, limited, err := source.assessRule(match.Rule, patterns)
	if err != nil || !eligible {
		return match, false, limited, err
	}

	match.Severity = severity

	spans, err := source.collectSpans(match.Rule, patterns)
	if err != nil {
		return Match{}, false, false, err
	}

	limited = limited || spans.truncated
	// Rejected-only instances are not evidence about the full file.
	if len(spans.spans) == 0 && spans.rejected {
		return match, false, limited, nil
	}

	match.Spans = spans.spans
	// Conditions without a matching string describe the full file. This also
	// retains empty-file matches without inventing substring evidence.
	if len(match.Spans) == 0 {
		match.Spans = []Span{{Start: 0, End: len(source.data)}}
	}

	return match, true, limited, nil
}

func nativeRuleCategory(rule *yrx.Rule) string {
	category := "unknown"

	for _, meta := range rule.Metadata() {
		if meta.Identifier() != "category" {
			continue
		}

		if value, ok := acceptedNativeCategory(meta.Value()); ok {
			category = value
		}
	}

	return category
}

func acceptedNativeCategory(value any) (string, bool) {
	category, ok := value.(string)
	if !ok {
		return "", false
	}

	switch category {
	case "malware", "webshell", "cryptominer", "hack_tool", "exploit":
		return category, true
	default:
		return "", false
	}
}

func (s nativeSource) selectPatterns(rule string, patterns []yrx.Pattern) (bool, bool, error) {
	if rule != "agent_skill_prompt_injection_hidden_instructions" {
		return true, false, nil
	}

	identifiers, limited, err := s.promptIdentifiers(patterns)
	if err != nil {
		return false, false, err
	}

	if limited {
		return true, true, nil
	}

	return promptIdentifiersEligible(identifiers), false, nil
}

func (s nativeSource) promptIdentifiers(patterns []yrx.Pattern) (map[string]bool, bool, error) {
	identifiers := map[string]bool{}
	count := 0

	for _, pattern := range patterns {
		for _, hit := range pattern.Matches() {
			count++
			if count > 4096 {
				return identifiers, true, nil
			}

			span, err := s.span(hit)
			if err != nil {
				return nil, false, err
			}

			if pattern.Identifier() == "$inj_reveal_prompt" && promptguard.Prohibited(s.text, span.Start, span.End) {
				continue
			}

			identifiers[pattern.Identifier()] = true
		}
	}

	return identifiers, false, nil
}

func (s nativeSource) collectSpans(rule string, patterns []yrx.Pattern) (nativeSpanCollector, error) {
	collector := nativeSpanCollector{spans: []Span{}, seen: map[Span]bool{}}
	if err := s.seedP1Evidence(rule, patterns, &collector); err != nil {
		return collector, err
	}

	for _, pattern := range patterns {
		// Restore the base64 witnesses after the strong instruction family and
		// before the final weak RTL family. The existence predicate is unchanged.
		if rule == metadataPoisoningRule && pattern.Identifier() == "$rtl_lro" {
			if slices.ContainsFunc(s.longBase64, collector.appendSpan) {
				return collector, nil
			}
		}

		for _, hit := range pattern.Matches() {
			full, err := collector.add(s, rule, pattern.Identifier(), hit)
			if err != nil || full {
				return collector, err
			}
		}
	}

	return collector, nil
}

func (s nativeSource) span(hit yrx.Match) (Span, error) {
	start, length := hit.Offset(), hit.Length()

	end := start + length
	if end < start || start > math.MaxInt || end > math.MaxInt || end > uint64(len(s.data)) {
		return Span{}, errors.New("invalid YARA-X range")
	}

	return Span{Start: int(start), End: int(end)}, nil
}

func (s nativeSource) acceptsInstance(rule, pattern string, span Span) bool {
	switch rule {
	case "agent_skill_prompt_injection_hidden_instructions":
		if pattern == "$agent_context" {
			return false
		}

		return pattern != "$inj_reveal_prompt" || !promptguard.Prohibited(s.text, span.Start, span.End)
	case ransomwareRule:
		return acceptRansomwareInstance(pattern, s.data, span.Start, span.End)
	case multilineShellRule:
		switch pattern {
		case pythonShellAliasPattern:
			return s.pythonShellAlias(span)
		case pythonSocketStreamPattern:
			return s.pythonSocketStream(span)
		}

		return true
	case metadataPoisoningRule:
		return pattern != metadataInstruction || !s.metadataProhibited(span)
	default:
		return true
	}
}

func promptIdentifiersEligible(identifiers map[string]bool) bool {
	hidden, injections := false, 0
	for id := range identifiers {
		hidden = hidden || strings.HasPrefix(id, "$hidden_")
		if strings.HasPrefix(id, "$inj_") {
			injections++
		}
	}

	return hidden || identifiers["$agent_context"] && injections > 0 || injections >= 2
}

func (c *nativeSpanCollector) add(source nativeSource, rule, pattern string, hit yrx.Match) (bool, error) {
	span, err := source.span(hit)
	if err != nil {
		return false, err
	}

	if span.Start == span.End {
		return false, nil
	}

	if !source.acceptsInstance(rule, pattern, span) {
		c.rejected = true
		return false, nil
	}

	return c.appendSpan(span), nil
}

func (c *nativeSpanCollector) appendSpan(span Span) bool {
	if c.seen[span] {
		return false
	}

	if len(c.spans) >= 8 {
		c.truncated = true
		return true
	}

	c.seen[span] = true
	c.spans = append(c.spans, span)

	return false
}
