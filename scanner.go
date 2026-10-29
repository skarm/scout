package scout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/engine"
	"github.com/skarm/scout/internal/analysis/semantic"
	"github.com/skarm/scout/internal/buildinfo"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Set once by the linker with -X for builds without VCS metadata; never changed at runtime.
var buildVersionOverride string

// Scanner owns a configured inspection pipeline and its native resources.
// Construct it with New and release it with Close. It supports concurrent
// scans and must not be copied. Caller-supplied providers must also support
// concurrent calls.
type Scanner struct {
	// options is the constructor-owned copy of validated operator settings.
	options Options
	// engine holds the immutable analyzer configuration shared by admitted calls.
	engine *engine.Engine
	// signatures owns the native signature runtime released after all active calls
	// finish.
	signatures *signatures.Runtime
	// plan records selection and effective limits fixed at construction.
	plan report.InspectionPlan
	// identity binds this Scanner's version and selected rulepack configuration.
	identity report.EngineIdentity
	// mu serializes admission against the transition to closed.
	mu sync.Mutex
	// closed prevents any new work from entering the active wait group.
	closed bool
	// active tracks admitted calls so Close can wait before releasing native
	// resources.
	active sync.WaitGroup
	// closeOnce makes resource release idempotent across concurrent Close calls.
	closeOnce sync.Once
}

// New validates options and opens the selected backends. The caller must close
// the returned Scanner. It rejects unavailable selected checks without
// downgrading the plan.
func New(ctx context.Context, options Options) (*Scanner, error) {
	checks, err := validateConstruction(ctx, options)
	if err != nil {
		return nil, err
	}

	options = cloneOptions(options)
	catalog := analyzer.NewCatalog(analyzer.Selection{Patterns: checks.Patterns, Python: checks.Python}).Analyzers()

	execution, err := configuredEngine(options, checks, catalog)
	if err != nil {
		return nil, err
	}

	scanner := &Scanner{options: options, engine: execution, plan: inspectionPlan(options, checks)}
	if err = validateAvailableChecks(scanner.plan); err != nil {
		return nil, err
	}

	if checks.YARA {
		scanner.signatures, err = signatures.Open(ctx, options.signatureOptions(checks), options.Concurrency.Workers)
		if err != nil {
			return nil, err
		}
	}

	scanner.identity = engineIdentity(options, checks, catalog)

	return scanner, nil
}

// Version returns the linker-supplied version, then Scout's module version. When Scout
// is a dependency, the host application's version and VCS settings are ignored.
func Version() string {
	if buildVersionOverride != "" {
		return buildVersionOverride
	}

	return buildinfo.ModuleVersion("github.com/skarm/scout")
}

// Close rejects new work, waits for active calls and releases native
// resources. It is safe to call repeatedly, including on a nil Scanner.
func (s *Scanner) Close() error {
	if s == nil {
		return nil
	}

	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.active.Wait()

		if s.signatures != nil {
			_ = s.signatures.Close()
		}
	})

	return nil
}

// InspectionPlan returns a detached copy of the selected checks, requirements
// and effective limits before execution.
func (s *Scanner) InspectionPlan() report.InspectionPlan {
	p := s.plan
	p.Checks = append([]report.InspectionCheck(nil), p.Checks...)

	p.Requirements = append([]string(nil), p.Requirements...)
	if p.Limits != nil {
		limits := *p.Limits
		p.Limits = &limits
	}

	return p
}

// Limits returns the effective configured limits. It contains values only;
// changing the returned copy cannot change an active Scanner.
func (s *Scanner) Limits() Limits { return s.options.Limits }

func (s *Scanner) admit() error {
	if s == nil {
		return ErrClosed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}

	s.active.Add(1)

	return nil
}

func validateConstruction(ctx context.Context, options Options) (Checks, error) {
	if ctx == nil {
		return Checks{}, &Error{Code: "invalid_context", Cause: ErrInvalidOptions}
	}

	if err := ctx.Err(); err != nil {
		return Checks{}, err
	}

	checks, err := options.selection()
	if err == nil {
		err = options.validate(checks)
	}

	if err != nil {
		return Checks{}, &Error{Code: "invalid_options", Cause: errors.Join(ErrInvalidOptions, err)}
	}

	return checks, nil
}

func configuredEngine(options Options, checks Checks, catalog []analyzer.Analyzer) (*engine.Engine, error) {
	registry, err := parse.WithFrontends(options.parserOptions(checks))
	if err != nil {
		return nil, err
	}

	if options.Review != nil {
		if _, err = semantic.ProviderIdentity(options.Review.Provider); err != nil {
			return nil, err
		}
	}

	execution, err := engine.NewWithRegistry(catalog, options.Concurrency.Workers, registry)
	if err != nil {
		return nil, err
	}

	return execution.WithSignatures(options.signatureOptions(checks))
}

func validateAvailableChecks(plan report.InspectionPlan) error {
	for _, check := range plan.Checks {
		if check.Selected && !check.Available {
			return &Error{Code: "backend_unavailable", Cause: ErrInvalidOptions}
		}
	}

	return nil
}

func engineIdentity(options Options, checks Checks, catalog []analyzer.Analyzer) report.EngineIdentity {
	var (
		signaturesDigest string
		extraRules       []byte
	)

	if checks.YARA {
		signaturesDigest = signatures.BuiltinRulesSHA256()
		extraRules = options.Signatures.ExtraRules
	}

	data, _ := json.Marshal(struct {
		Checks     Checks
		Semantic   bool
		Rules      []report.Rule
		Signatures string
		Knowledge  string
		ExtraRules []byte
	}{
		Checks:     checks,
		Semantic:   options.Review != nil,
		Rules:      ruleCatalog(catalog, checks.YARA, options.Vulnerabilities != nil),
		Signatures: signaturesDigest,
		Knowledge:  knowledge.Inventory().SHA256,
		ExtraRules: extraRules,
	})
	digest := sha256.Sum256(data)

	return report.EngineIdentity{Version: Version(), RulepackDigest: "sha256:" + hex.EncodeToString(digest[:])}
}

func cloneOptions(o Options) Options {
	if o.External != nil {
		v := *o.External
		v.AllowedOrigins = append([]string(nil), v.AllowedOrigins...)
		o.External = &v
	}

	if o.Checks != nil {
		c := *o.Checks
		o.Checks = &c
	}

	o.Signatures.ExtraRules = append([]byte(nil), o.Signatures.ExtraRules...)
	if o.Download != nil {
		v := *o.Download
		if v.RootCAs != nil {
			v.RootCAs = v.RootCAs.Clone()
		}

		o.Download = &v
	}

	if o.Vulnerabilities != nil {
		v := *o.Vulnerabilities

		v.Offline = append([]byte(nil), v.Offline...)
		if v.RootCAs != nil {
			v.RootCAs = v.RootCAs.Clone()
		}

		o.Vulnerabilities = &v
	}

	if o.Review != nil {
		v := *o.Review
		o.Review = &v
	}

	return o
}

func ruleCatalog(checks []analyzer.Analyzer, yara, vulnerabilities bool) []report.Rule {
	rules := make([]report.Rule, 0, len(checks)+6)
	for _, c := range checks {
		rules = append(rules, knowledge.WithGuidance(c.Rule()))
	}

	if yara {
		rules = append(rules, engine.SignatureRules()...)
	}

	if vulnerabilities {
		rules = append(rules, engine.VulnerabilityRule())
	}

	return rules
}
