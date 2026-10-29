// Package signatures embeds YARA-X. It never invokes Python, a YARA executable,
// or inspected code. Extra rules are explicit trusted operator input.
package signatures

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/skarm/scout/internal/textmatch"
	scanreport "github.com/skarm/scout/report"

	_ "embed"
)

//go:embed rules/agent_skills.yar
var agentRules string

//go:embed rules/webshells.yar
var webshellRules string

//go:embed rules/hacktools.yar
var hacktoolRules string

//go:embed rules/cryptominers.yar
var cryptominerRules string

//go:embed rules/malware.yar
var malwareRules string

//go:embed rules/cisco_adapted.yar
var ciscoRules string

//nolint:gochecknoglobals // Immutable embedded rule text shared by all compiled engines.
var builtinRules = malwareRules + "\n" + agentRules + "\n" + webshellRules + "\n" + hacktoolRules + "\n" + cryptominerRules + "\n" + ciscoRules

//nolint:gochecknoglobals // Immutable protocol status table shared by native response validation.
var replyStatuses = map[string]bool{
	scanreport.OutcomeCompleted: true,
	scanreport.OutcomePartial:   true,
	scanreport.OutcomeDeadline:  false,
	scanreport.OutcomeCancelled: false,
	scanreport.OutcomeFailed:    false,
}

type Options struct {
	Enabled                               bool
	ExtraRules                            []byte
	Timeout                               time.Duration
	MaxFileBytes, MaxTotalBytes, MaxFiles int
}

type Input struct{ Path, SHA256, Data string }

// Capability describes the linked backend without requiring report consumers
// to import the native adapter. The public result aliases preserve source and
// JSON compatibility.
type (
	Capability = scanreport.SignatureCapability
	Span       = scanreport.SignatureSpan
	Match      = scanreport.SignatureMatch
	Outcome    = scanreport.SignatureOutcome
	Report     = scanreport.SignatureReport
	reply      struct {
		Status    string
		Matches   []Match
		Truncated bool
	}
)

type compiledEngine interface {
	scan(context.Context, []byte) (reply, error)
	fork() (compiledEngine, error)
	close()
}

// signatureScan owns compilation and the aggregate admission budgets of a batch.
// A failed compilation is remembered; per-input refusals do not poison it.
type signatureScan struct {
	engine      compiledEngine
	ownsEngine  bool
	rules       string
	options     Options
	backend     Capability
	used, count int
	fatal       string
}

func DefaultOptions() Options {
	return Options{Timeout: 3 * time.Second, MaxFileBytes: 1 << 20, MaxTotalBytes: 8 << 20, MaxFiles: 64}
}

func BuiltinRulesSHA256() string { return hash([]byte(builtinRules)) }

func Check(ctx context.Context, inputs []Input, o Options) (Report, error) {
	return check(ctx, inputs, o, nil, true)
}

func (o Options) Validate() error {
	for _, budget := range []struct{ value, min, max int64 }{
		{value: int64(o.Timeout), min: 1, max: int64(10 * time.Second)},
		{value: int64(o.MaxFiles), min: 1, max: 4096},
		{value: int64(o.MaxFileBytes), min: 1, max: 4 << 20},
		{value: int64(o.MaxTotalBytes), min: int64(o.MaxFileBytes), max: 256 << 20},
		{value: int64(len(o.ExtraRules)), min: 0, max: 256 << 10},
	} {
		if budget.value < budget.min || budget.value > budget.max {
			return errors.New("invalid YARA-X budgets")
		}
	}

	if !o.Enabled && len(o.ExtraRules) > 0 {
		return errors.New("YARA-X rules require explicit enablement")
	}

	return nil
}

func checkCompiled(ctx context.Context, inputs []Input, o Options, engine compiledEngine) (Report, error) {
	return check(ctx, inputs, o, engine, false)
}

func check(ctx context.Context, inputs []Input, o Options, engine compiledEngine, ownsEngine bool) (Report, error) {
	r := Report{
		Enabled:      o.Enabled,
		Engine:       Backend(),
		Completeness: string(scanreport.Complete),
		Outcomes:     []Outcome{},
		Limitations: []string{
			"Embedded YARA-X observes signatures, not execution or intent. Native compiler/scanner memory is in-process; budgets and native scan timeout are not a hard OS sandbox. Compilation cannot be forcibly cancelled.",
			"27 adapted SkillSpector rules and 8 adapted Cisco compound rules are bundled. Broad tool references and examples can match. Classic YARA and YARA-X differ; no general external rule-pack compatibility is claimed. Includes and the console module are disabled; invalid rules are never silently ignored.",
			"The reported binding version is not a measured native-library version. Native engine identity is unknown unless separately attested by the build system.",
		},
	}
	if ctx == nil {
		r.Completeness = string(scanreport.Failed)
		return r, errors.New("nil YARA-X context")
	}

	if e := o.Validate(); e != nil {
		r.Completeness = string(scanreport.Failed)
		return r, e
	}

	if !o.Enabled {
		return r, nil
	}

	rules := builtinRules + "\n" + string(o.ExtraRules)

	r.RulesSHA256 = hash([]byte(rules))

	state := signatureScan{engine: engine, ownsEngine: ownsEngine, rules: rules, options: o, backend: r.Engine}
	defer state.close()

	for _, input := range inputs {
		out := state.scan(ctx, input)

		r.Outcomes = append(r.Outcomes, out)
		if out.Status != scanreport.OutcomeCompleted || out.Truncated {
			r.Completeness = string(scanreport.Partial)
		}
	}

	if ctx.Err() != nil && r.Completeness == string(scanreport.Complete) {
		r.Completeness = string(scanreport.Partial)
	}

	return r, ctx.Err()
}

func scanInput(ctx context.Context, engine compiledEngine, f Input, timeout time.Duration, out *Outcome, info Capability) {
	call, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := engine.scan(call, []byte(f.Data))
	if err != nil {
		out.Status = scanreport.OutcomeFailed
	} else if err = validateReply(result, len(f.Data)); err != nil {
		out.Status = "invalid_evidence"
	} else {
		out.Status = result.Status
		out.Matches = result.Matches
		out.Truncated = result.Truncated
		out.EngineVersion = "go-binding-" + info.BindingVersion + ";native-" + info.NativeVersion
	}
}

func validateReply(r reply, size int) error {
	verified, known := replyStatuses[r.Status]
	if !known {
		return errors.New("invalid YARA-X status")
	}

	if len(r.Matches) > 32 {
		return errors.New("YARA-X match budget")
	}

	if !verified && len(r.Matches) > 0 {
		return errors.New("unverified native results")
	}

	for _, m := range r.Matches {
		if err := validateMatch(m, size); err != nil {
			return err
		}
	}

	return nil
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func validateMatch(m Match, size int) error {
	if !validBuiltinSeverity(m) {
		return errors.New("invalid signature severity")
	}

	if !textmatch.Identifier(m.Rule, 128) || len(m.Spans) == 0 || len(m.Spans) > 8 {
		return errors.New("invalid YARA-X match")
	}

	if !slices.Contains([]string{"malware", "webshell", "cryptominer", "hack_tool", "exploit", "unknown"}, m.Category) {
		return errors.New("invalid category")
	}

	for _, s := range m.Spans {
		if !validSignatureSpan(s, size) {
			return errors.New("invalid signature evidence")
		}
	}

	return nil
}

func validSignatureSpan(s Span, size int) bool {
	return s.Start >= 0 && s.End >= s.Start && s.End <= size && (s.End != s.Start || size == 0)
}

func (s *signatureScan) close() {
	if s.engine != nil && s.ownsEngine {
		s.engine.close()
	}
}

func (s *signatureScan) scan(ctx context.Context, input Input) Outcome {
	out := Outcome{Path: input.Path, SHA256: input.SHA256, Status: scanreport.OutcomeNotRun, Matches: []Match{}}
	if status := s.admission(ctx, input); status != "" {
		out.Status = status
		return out
	}

	s.used += len(input.Data)

	s.count++
	if status := s.prepareEngine(ctx); status != "" {
		out.Status = status
		return out
	}

	scanInput(ctx, s.engine, input, s.options.Timeout, &out, s.backend)

	return out
}

func (s *signatureScan) admission(ctx context.Context, input Input) string {
	switch {
	case ctx.Err() != nil:
		return scanreport.OutcomeCancelled
	case s.fatal != "":
		return s.fatal
	case len(input.Data) > s.options.MaxFileBytes || len(input.Data) > s.options.MaxTotalBytes-s.used || s.count >= s.options.MaxFiles:
		return "limit"
	case hash([]byte(input.Data)) != input.SHA256:
		return "invalid_input"
	case !s.backend.Available:
		return "unavailable"
	}

	return ""
}

func (s *signatureScan) prepareEngine(ctx context.Context) string {
	if s.engine != nil {
		return ""
	}

	if !s.ownsEngine {
		return "unavailable"
	}

	var err error

	s.engine, err = compileRules(ctx, s.rules)
	if err != nil || s.engine == nil {
		s.fatal = "invalid_rules"
		if ctx.Err() != nil {
			s.fatal = scanreport.OutcomeCancelled
		}
	}

	return s.fatal
}
