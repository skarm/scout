package scout

import (
	"errors"
	"time"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/capture/external"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

// Profile names an inspection preset. Use Custom to select checks explicitly.
type Profile string

const (
	// Standard selects all standard static checks and requires their backends to
	// be available.
	Standard Profile = "standard"
	// Review selects standard static checks and explicitly configured semantic
	// review.
	Review Profile = "review"
	// Custom selects the optional checks specified by Checks.
	Custom Profile = "custom"
)

type (
	// Checks selects optional static checks for the Custom profile. Built-in
	// checks remain enabled.
	Checks struct {
		// Patterns enables supplemental adapted pattern checks.
		Patterns bool
		// Python enables Python AST analysis.
		Python bool
		// YAML enables structural YAML parsing.
		YAML bool
		// TOML enables structural TOML parsing.
		TOML bool
		// YARA enables native YARA-X signatures.
		YARA bool
	}
	// Concurrency bounds simultaneous target scans and analyzer workers within a
	// run.
	Concurrency struct {
		// Targets limits simultaneous target scans within one operation.
		Targets int
		// Workers limits analyzer workers shared by the operation's targets.
		Workers int
	}
	// CaptureLimits bounds inventory traversal and captured bytes for each target.
	// All limits must be positive.
	// Part of the supported Go API for callers outside this repository.
	//goland:noinspection GoUnnecessarilyExportedIdentifiers
	CaptureLimits struct {
		// MaxEntries limits inventoried entries, including unread and rejected
		// entries.
		MaxEntries int
		// MaxFiles limits captured files per target.
		MaxFiles int
		// MaxFileBytes limits bytes captured from one file.
		MaxFileBytes int64
		// MaxTotalBytes limits captured bytes across one target's files.
		MaxTotalBytes int64
		// MaxArchiveBytes limits the source archive size in bytes.
		MaxArchiveBytes int64
		// MaxPathBytes limits inventory path length in bytes.
		MaxPathBytes int
		// MaxDepth limits inventory path depth.
		MaxDepth int
	}
)

// AnalysisLimits bounds analyzer work, matches and cooperative parser
// execution.
type AnalysisLimits struct {
	// MaxOperations limits analysis work across the run, divided among targets,
	// preparation tasks and checks.
	MaxOperations uint64
	// MaxMatchesPerRule limits retained matches per analyzer across one target's
	// files.
	MaxMatchesPerRule int
	// ParserTimeout sets the cooperative deadline for a parser operation.
	ParserTimeout time.Duration
}
type (
	// RetentionLimits bounds the findings retained across a run. Omitted findings
	// make the run incomplete.
	// Part of the supported Go API for callers outside this repository.
	//goland:noinspection GoUnnecessarilyExportedIdentifiers
	RetentionLimits struct {
		// MaxFindings bounds retained findings. Exceeding it leaves an explicit
		// completeness gap.
		MaxFindings int
	}
	// Limits combines per-target limits with aggregate budgets shared by all
	// targets in a run.
	Limits struct {
		// Capture bounds input capture separately for each target.
		Capture CaptureLimits
		// Extraction bounds extraction separately for each target; aggregate extracted
		// bytes are also limited by MaxExtractedBytes.
		Extraction report.ExtractionLimits
		// Analysis bounds analyzer work and cooperative parser execution.
		Analysis AnalysisLimits
		// Retention bounds findings retained across the whole run.
		Retention RetentionLimits
		// MaxCaptureBytes limits captured bytes across all targets in the run.
		MaxCaptureBytes int64
		// MaxExtractedBytes limits extracted bytes across all targets in the run.
		MaxExtractedBytes int64
		// MaxCaptureFiles limits captured files across all targets in the run.
		MaxCaptureFiles int
		// MaxCaptureEntries limits inventory entries across all targets in the run.
		MaxCaptureEntries int
		// MaxServiceRequests limits external traversal, advisory and review requests
		// across the run.
		MaxServiceRequests int
		// Timeout bounds the complete scan or comparison operation.
		Timeout time.Duration
	}
)

// SignatureOptions configures YARA-X rules and the per-input execution
// timeout.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type SignatureOptions struct {
	// ExtraRules contains additional trusted operator-supplied YARA source.
	ExtraRules []byte
	// Timeout bounds signature execution for an input through the native backend's
	// timeout mechanism.
	Timeout time.Duration
}

// ReviewOptions connects a trusted operator-supplied provider to explicit
// semantic review settings.
type ReviewOptions struct {
	// Provider is trusted operator code that receives bounded review requests. It
	// is not sandboxed by the Provider interface.
	Provider review.Provider
	// Settings contains permissions and budgets for semantic review.
	Settings review.Options
}

// Options configures a Scanner. Start with DefaultOptions; the zero value is
// not a valid configuration.
type Options struct {
	// Profile selects Standard, Review or Custom. The empty profile is invalid.
	Profile Profile
	// Checks must be non-nil for Custom and nil for Standard or Review.
	Checks *Checks
	// Limits sets per-target and aggregate operation budgets.
	Limits Limits
	// Concurrency sets target and analyzer worker limits.
	Concurrency Concurrency
	// Signatures configures the native signature engine and additional trusted
	// rules.
	Signatures SignatureOptions
	// Harness selects automatic or explicit host interpretation of plugin
	// declarations.
	Harness report.HarnessOptions
	// Download permits and configures remote acquisition when non-nil and enabled.
	Download *fetch.Options
	// External configures explicit traversal of external references when non-nil.
	External *ExternalOptions
	// Vulnerabilities configures optional advisory lookup; nil performs no
	// advisory queries.
	Vulnerabilities *osv.Options
	// Review configures semantic review; it is required by the Review profile.
	Review *ReviewOptions
}

// ExternalOptions bounds explicitly permitted traversal of literal external
// references.
type ExternalOptions struct {
	// AllowedOrigins lists explicitly permitted origins for this operation.
	AllowedOrigins []string
	// MaxDepth limits reference hops from the original target.
	MaxDepth int
	// MaxRequests limits attempted external downloads.
	MaxRequests int
	// MaxBytes bounds bytes acquired during external-reference traversal.
	MaxBytes int64
}

// CompareOptions bounds retained update changes independently of the limits
// for either scan.
type CompareOptions struct {
	// MaxChanges bounds retained comparison changes. Omitted changes leave the
	// comparison incomplete.
	MaxChanges int
}

// DefaultExternalOptions returns traversal limits and the default permitted
// origins. Applying these options still requires explicit download permission.
func DefaultExternalOptions() ExternalOptions {
	return ExternalOptions{
		AllowedOrigins: []string{"https://raw.githubusercontent.com", "https://github.com"},
		MaxDepth:       2,
		MaxRequests:    16,
		MaxBytes:       4 << 20,
	}
}

// DefaultOptions returns a complete Standard configuration with bounded
// resources and optional network services disabled.
func DefaultOptions() Options {
	c := report.DefaultCaptureLimits()
	e := report.DefaultExtractionLimits()

	return Options{
		Profile:     Standard,
		Concurrency: Concurrency{Targets: 1, Workers: 4},
		Harness:     report.HarnessOptions{Host: report.HostAuto},
		Signatures:  SignatureOptions{Timeout: 3 * time.Second},
		Limits: Limits{
			Capture: CaptureLimits{
				MaxEntries:      c.MaxEntries,
				MaxFiles:        c.MaxFiles,
				MaxFileBytes:    c.MaxFileBytes,
				MaxTotalBytes:   c.MaxTotalBytes,
				MaxArchiveBytes: c.MaxArchiveBytes,
				MaxPathBytes:    c.MaxPathBytes,
				MaxDepth:        c.MaxDepth,
			},
			Extraction: e,
			Analysis: AnalysisLimits{
				MaxOperations:     16 << 20,
				MaxMatchesPerRule: 1024,
				ParserTimeout:     3 * time.Second,
			},
			Retention:          RetentionLimits{MaxFindings: c.MaxFindings},
			MaxCaptureBytes:    c.MaxTotalBytes,
			MaxExtractedBytes:  e.MaxTotalBytes,
			MaxCaptureFiles:    c.MaxFiles,
			MaxCaptureEntries:  c.MaxEntries,
			MaxServiceRequests: 64,
			Timeout:            2 * time.Minute,
		},
	}
}

// DefaultCompareOptions returns the standard ceiling for retained comparison
// changes.
func DefaultCompareOptions() CompareOptions { return CompareOptions{MaxChanges: 4096} }

func (o ExternalOptions) internal() external.Options {
	return external.Options{
		AllowedOrigins: o.AllowedOrigins,
		MaxDepth:       o.MaxDepth,
		MaxRequests:    o.MaxRequests,
		MaxBytes:       o.MaxBytes,
	}
}

func (o Options) selection() (Checks, error) {
	switch o.Profile {
	case Standard, Review:
		if o.Checks != nil {
			return Checks{}, errors.New("named profiles cannot be overridden; select custom explicitly")
		}

		return Checks{Patterns: true, Python: true, YAML: true, TOML: true, YARA: true}, nil
	case Custom:
		if o.Checks == nil {
			return Checks{}, errors.New("custom profile requires explicit checks")
		}

		return *o.Checks, nil
	default:
		return Checks{}, errors.New("unknown inspection profile")
	}
}

func (o Options) captureLimits() report.CaptureLimits {
	c := o.Limits.Capture

	return report.CaptureLimits{
		MaxEntries:      c.MaxEntries,
		MaxFiles:        c.MaxFiles,
		MaxFileBytes:    c.MaxFileBytes,
		MaxTotalBytes:   c.MaxTotalBytes,
		MaxArchiveBytes: c.MaxArchiveBytes,
		MaxPathBytes:    c.MaxPathBytes,
		MaxDepth:        c.MaxDepth,
		MaxFindings:     o.Limits.Retention.MaxFindings,
	}
}

func (o Options) parserOptions(c Checks) frontend.Options {
	return frontend.Options{Python: c.Python, YAML: c.YAML, TOML: c.TOML, Timeout: o.Limits.Analysis.ParserTimeout}
}

func (o Options) signatureOptions(c Checks) signatures.Options {
	s := signatures.DefaultOptions()
	s.Enabled = c.YARA

	s.ExtraRules = append([]byte(nil), o.Signatures.ExtraRules...)
	s.Timeout = o.Signatures.Timeout
	s.MaxFiles = min(o.Limits.Capture.MaxFiles, 4096)
	s.MaxFileBytes = int(min(o.Limits.Capture.MaxFileBytes, 4<<20))
	s.MaxTotalBytes = int(max(int64(s.MaxFileBytes), o.Limits.MaxCaptureBytes))

	return s
}

func (o Options) validate(c Checks) error {
	if err := o.validatePipeline(c); err != nil {
		return err
	}

	if err := o.Concurrency.validate(); err != nil {
		return err
	}

	if err := o.Limits.validateAnalysisBudget(); err != nil {
		return err
	}

	if err := o.Limits.validateAggregateBudget(); err != nil {
		return err
	}

	return o.validateServices()
}

func (o Options) validatePipeline(c Checks) error {
	if err := o.captureLimits().Validate(); err != nil {
		return err
	}

	if err := o.Limits.Extraction.Validate(); err != nil {
		return err
	}

	if err := o.parserOptions(c).Validate(); err != nil {
		return err
	}

	if err := o.signatureOptions(c).Validate(); err != nil {
		return err
	}

	return o.Harness.Validate()
}

func (o Options) validateServices() error {
	if o.External != nil {
		if o.Download == nil || !o.Download.Enabled {
			return errors.New("external traversal requires download permission")
		}

		if err := o.External.internal().Validate(o.Download.AllowLoopback); err != nil {
			return err
		}
	}

	if o.Download != nil {
		if err := o.Download.Validate(); err != nil {
			return err
		}
	}

	if o.Vulnerabilities != nil {
		if !o.Vulnerabilities.Enabled {
			return errors.New("configured vulnerability service must be enabled")
		}

		if err := o.Vulnerabilities.Validate(); err != nil {
			return err
		}
	}

	return o.validateReview()
}

func (o Options) validateReview() error {
	if o.Profile == Review && o.Review == nil {
		return errors.New("review profile requires an explicit provider and source-upload consent")
	}

	if o.Review == nil {
		return nil
	}

	if !o.Review.Settings.Enabled {
		return errors.New("configured review service must be enabled")
	}

	if err := o.Review.Settings.Validate(); err != nil {
		return err
	}

	if o.Review.Provider == nil {
		return errors.New("review provider is required")
	}

	return nil
}

func (c Concurrency) validate() error {
	if c.Targets < 1 || c.Targets > 32 || c.Workers < 1 || c.Workers > 32 {
		return errors.New("concurrency must be in 1..32")
	}

	return nil
}

func (l Limits) validateAnalysisBudget() error {
	if l.Timeout <= 0 || l.Timeout > 10*time.Minute || l.Analysis.MaxOperations < 1 || l.Analysis.MaxOperations > 1<<40 || l.Analysis.MaxMatchesPerRule < 1 || l.Analysis.MaxMatchesPerRule > 100000 {
		return errors.New("invalid analysis budget")
	}

	return nil
}

func (l Limits) validateAggregateBudget() error {
	if l.MaxCaptureBytes < 1 || l.MaxCaptureBytes > 256<<20 || l.MaxExtractedBytes < 1 || l.MaxExtractedBytes > 256<<20 {
		return errors.New("invalid aggregate budget")
	}

	return l.validateAggregateCounts()
}

func (l Limits) validateAggregateCounts() error {
	if l.MaxCaptureFiles < 1 || l.MaxCaptureFiles > 100000 || l.MaxCaptureEntries < l.MaxCaptureFiles || l.MaxCaptureEntries > 100000 || l.MaxServiceRequests < 1 || l.MaxServiceRequests > 256 {
		return errors.New("invalid aggregate budget")
	}

	return nil
}
