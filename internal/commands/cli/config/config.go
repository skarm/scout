// Package config translates an explicitly supplied, versioned document into
// caller-owned scanner and policy options. Parsing never reads files or targets.
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

const schema = "scout.config/v1"

// Grants come from the current invocation, never from the config document.
type Grants struct{ Download, VulnerabilityNetwork, SourceUpload bool }

type Settings struct {
	Scanner                                    scout.Options
	Policy                                     policy.Options
	BaselinePath, OSVCachePath, ExtraRulesPath string
	RemotePins                                 map[string]scout.RemotePin
	Reviewer                                   *Reviewer
}

// Reviewer preserves the operator's declarative provider settings until all
// invocation patches are applied. Resolving credentials is a separate phase.
type Reviewer struct {
	Provider review.ProviderSpec
	Settings review.Options
}

// Pointer patches distinguish an absent value from an explicit zero or false.
// Numeric budgets remain exact; the scanner constructor owns budget validation.
type document struct {
	Schema          string               `json:"schema"`
	Profile         *scout.Profile       `json:"profile"`
	Checks          *checks              `json:"checks"`
	Concurrency     *concurrency         `json:"concurrency"`
	Timeout         *string              `json:"timeout"`
	Harness         *string              `json:"harness"`
	Policy          *policyPatch         `json:"policy"`
	Limits          *limits              `json:"limits"`
	Signatures      *signatures          `json:"signatures"`
	Download        *download            `json:"download"`
	RemotePins      map[string]remotePin `json:"remote_pins"`
	Review          *reviewPatch         `json:"review"`
	Vulnerabilities *vulnerabilities     `json:"vulnerabilities"`
}

type checks struct {
	Patterns *bool `json:"patterns"`
	Python   *bool `json:"python"`
	YAML     *bool `json:"yaml"`
	TOML     *bool `json:"toml"`
	YARA     *bool `json:"yara"`
}
type concurrency struct {
	Targets *int `json:"targets"`
	Workers *int `json:"workers"`
}
type policyPatch struct {
	Scope                *policy.ScopePolicy `json:"scope"`
	FailAt               *report.Severity    `json:"fail_at"`
	ReviewBelowThreshold *bool               `json:"review_below_threshold"`
	Baseline             *string             `json:"baseline"`
	AllowGlobs           *bool               `json:"allow_globs"`
}
type limits struct {
	Capture            *captureLimits    `json:"capture"`
	Extraction         *extractionLimits `json:"extraction"`
	Analysis           *analysisLimits   `json:"analysis"`
	Retention          *retentionLimits  `json:"retention"`
	MaxCaptureBytes    *int64            `json:"max_capture_bytes"`
	MaxExtractedBytes  *int64            `json:"max_extracted_bytes"`
	MaxCaptureFiles    *int              `json:"max_capture_files"`
	MaxCaptureEntries  *int              `json:"max_capture_entries"`
	MaxServiceRequests *int              `json:"max_service_requests"`
}
type captureLimits struct {
	MaxEntries      *int   `json:"max_entries"`
	MaxFiles        *int   `json:"max_files"`
	MaxFileBytes    *int64 `json:"max_file_bytes"`
	MaxTotalBytes   *int64 `json:"max_total_bytes"`
	MaxArchiveBytes *int64 `json:"max_archive_bytes"`
	MaxPathBytes    *int   `json:"max_path_bytes"`
	MaxDepth        *int   `json:"max_depth"`
}
type extractionLimits struct {
	MaxDepth       *int   `json:"max_depth"`
	MaxObjects     *int   `json:"max_objects"`
	MaxEntries     *int   `json:"max_entries"`
	MaxObjectBytes *int64 `json:"max_object_bytes"`
	MaxTotalBytes  *int64 `json:"max_total_bytes"`
}
type analysisLimits struct {
	MaxOperations     *uint64 `json:"max_operations"`
	MaxMatchesPerRule *int    `json:"max_matches_per_rule"`
	ParserTimeout     *string `json:"parser_timeout"`
}
type retentionLimits struct {
	MaxFindings *int `json:"max_findings"`
}
type signatures struct {
	RulesFile *string `json:"rules_file"`
	Timeout   *string `json:"timeout"`
}
type download struct {
	Timeout       *string `json:"timeout"`
	AllowLoopback *bool   `json:"allow_loopback"`
}
type remotePin struct {
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
}
type reviewPatch struct {
	Provider         string  `json:"provider"`
	Endpoint         string  `json:"endpoint"`
	Model            string  `json:"model"`
	KeyEnv           *string `json:"key_env"`
	AWSRegion        *string `json:"aws_region"`
	AccessKeyEnv     *string `json:"access_key_env"`
	SecretKeyEnv     *string `json:"secret_key_env"`
	SessionEnv       *string `json:"session_token_env"`
	AllowLoopback    *bool   `json:"allow_loopback"`
	Quality          *bool   `json:"quality"`
	MaxRequests      *int    `json:"max_requests"`
	MaxInputBytes    *int    `json:"max_input_bytes"`
	MaxOutputTokens  *int    `json:"max_output_tokens"`
	MaxResponseBytes *int    `json:"max_response_bytes"`
	Timeout          *string `json:"timeout"`
}
type vulnerabilities struct {
	Endpoint      *string `json:"endpoint"`
	Cache         *string `json:"cache"`
	AllowLoopback *bool   `json:"allow_loopback"`
	MaxRequests   *int    `json:"max_requests"`
}

func DefaultSettings() Settings {
	return Settings{Scanner: scout.DefaultOptions(), Policy: policy.Options{FailAt: report.High}}
}

func (s *Settings) Resolve(lookupEnv func(string) (string, bool)) error {
	if s.Reviewer == nil {
		if s.Scanner.Profile == scout.Review {
			return errors.New("review profile requires provider config")
		}

		return nil
	}

	if !s.Reviewer.Settings.AllowSourceUpload {
		return errors.New("review config requires the source-upload grant")
	}

	if err := s.Reviewer.Settings.Validate(); err != nil {
		return err
	}

	provider, err := s.Reviewer.Provider.Build(lookupEnv)
	if err != nil {
		return err
	}

	s.Scanner.Review = &scout.ReviewOptions{Provider: provider, Settings: s.Reviewer.Settings}

	return nil
}

// Parse does not infer permissions, discover credentials or open configured
// paths. Callers load the returned baseline, rules and cache paths explicitly.
func Parse(data []byte, grants Grants) (Settings, error) {
	doc, err := decode(data)
	if err != nil {
		return Settings{}, err
	}

	s := DefaultSettings()
	if err := doc.apply(&s); err != nil {
		return Settings{}, err
	}

	if err := doc.services(&s, grants); err != nil {
		return Settings{}, err
	}

	return s, nil
}

func decode(data []byte) (document, error) {
	var doc document
	if len(data) > jsonconfig.MaxBytes {
		return doc, errors.New("config exceeds byte limit")
	}

	root, err := jsonconfig.Parse(context.Background(), string(data))
	if err != nil || !knownShape(root, reflect.TypeFor[document]()) {
		return doc, errors.New("invalid config JSON or unknown field")
	}

	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()

	if d.Decode(&doc) != nil {
		return document{}, errors.New("invalid config value type")
	}

	var trailing any
	if !errors.Is(d.Decode(&trailing), io.EOF) || doc.Schema != schema {
		return document{}, errors.New("unsupported or missing config schema")
	}

	return doc, nil
}

// encoding/json also accepts case-insensitive struct names. Walk the bounded
// tree against exact JSON tags so aliases cannot silently select an option.
func knownShape(n *jsonconfig.Node, typ reflect.Type) bool {
	if n == nil || n.Kind == jsonconfig.KindNull {
		return false
	}

	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	switch typ.Kind() {
	case reflect.Struct:
		if n.Kind != jsonconfig.KindObject {
			return false
		}

		return knownStruct(n, typ)

	case reflect.Map:
		return knownMap(n, typ)
	default:
		// Scalar values are checked by the subsequent JSON decoder.
		return true
	}
}

func assign[T any](dst *T, patch *T) {
	if patch != nil {
		*dst = *patch
	}
}

func duration(dst *time.Duration, patch *string, maximum time.Duration) error {
	if patch == nil {
		return nil
	}

	value, err := time.ParseDuration(*patch)
	if err != nil || value <= 0 || value > maximum {
		return errors.New("invalid config duration")
	}

	*dst = value

	return nil
}

func (d document) apply(s *Settings) error {
	assign(&s.Scanner.Profile, d.Profile)

	if err := d.applyChecks(&s.Scanner); err != nil {
		return err
	}

	if d.Concurrency != nil {
		assign(&s.Scanner.Concurrency.Targets, d.Concurrency.Targets)
		assign(&s.Scanner.Concurrency.Workers, d.Concurrency.Workers)
	}

	assign(&s.Scanner.Harness.Host, d.Harness)

	if err := s.Scanner.Harness.Validate(); err != nil {
		return err
	}

	if err := duration(&s.Scanner.Limits.Timeout, d.Timeout, 10*time.Minute); err != nil {
		return err
	}

	if d.Limits != nil {
		if err := d.Limits.apply(&s.Scanner.Limits); err != nil {
			return err
		}
	}

	return d.applyPolicyAndSignatures(s)
}

func (d document) applyPolicyAndSignatures(s *Settings) error {
	if d.Policy != nil {
		assign(&s.Policy.Scope, d.Policy.Scope)
		assign(&s.Policy.FailAt, d.Policy.FailAt)
		assign(&s.Policy.ReviewBelowThreshold, d.Policy.ReviewBelowThreshold)
		assign(&s.Policy.AllowGlobs, d.Policy.AllowGlobs)
		assign(&s.BaselinePath, d.Policy.Baseline)
	}

	if _, err := policy.New(s.Policy); err != nil {
		return errors.New("invalid config policy")
	}

	if d.Signatures != nil {
		assign(&s.ExtraRulesPath, d.Signatures.RulesFile)

		if err := duration(&s.Scanner.Signatures.Timeout, d.Signatures.Timeout, 10*time.Second); err != nil {
			return err
		}
	}

	return d.applyPins(s)
}

func (d document) applyChecks(o *scout.Options) error {
	switch o.Profile {
	case scout.Standard, scout.Review:
		if d.Checks != nil {
			return errors.New("checks require the custom profile")
		}
	case scout.Custom:
		if d.Checks == nil {
			return errors.New("custom profile requires checks")
		}

		c := &scout.Checks{Patterns: true, Python: true, YAML: true, TOML: true, YARA: true}
		assign(&c.Patterns, d.Checks.Patterns)
		assign(&c.Python, d.Checks.Python)
		assign(&c.YAML, d.Checks.YAML)
		assign(&c.TOML, d.Checks.TOML)
		assign(&c.YARA, d.Checks.YARA)
		o.Checks = c
	default:
		return errors.New("unknown config profile")
	}

	return nil
}

func (d document) applyPins(s *Settings) error {
	if d.RemotePins == nil {
		return nil
	}

	s.RemotePins = make(map[string]scout.RemotePin, len(d.RemotePins))
	for address, pin := range d.RemotePins {
		if _, err := scout.Remote(address, scout.RemotePin{}); err != nil {
			return errors.New("invalid remote pin URL")
		}

		v := fetch.DefaultOptions()

		v.Enabled, v.Revision, v.ExpectedSHA256 = true, pin.Revision, pin.SHA256
		if err := v.Validate(); err != nil || pin.Revision == "" && pin.SHA256 == "" {
			return errors.New("remote pin requires a full revision or SHA-256")
		}

		s.RemotePins[address] = scout.RemotePin{Revision: pin.Revision, SHA256: pin.SHA256}
	}

	return nil
}

func (d document) services(s *Settings, grants Grants) error {
	if d.Download != nil && !grants.Download {
		return errors.New("download config requires the download grant")
	}

	if grants.Download {
		opts := fetch.DefaultOptions()

		opts.Enabled = true
		if d.Download != nil {
			assign(&opts.AllowLoopback, d.Download.AllowLoopback)

			if err := duration(&opts.Timeout, d.Download.Timeout, 2*time.Minute); err != nil {
				return err
			}
		}

		s.Scanner.Download = &opts
	}

	if d.Vulnerabilities != nil {
		if err := d.Vulnerabilities.apply(s, grants); err != nil {
			return err
		}
	}

	if d.Review != nil {
		opts, err := d.Review.options()
		if err != nil {
			return err
		}

		opts.Settings.AllowSourceUpload = grants.SourceUpload
		s.Reviewer = opts
	}

	return nil
}

func (p *limits) apply(l *scout.Limits) error {
	if c := p.Capture; c != nil {
		assign(&l.Capture.MaxEntries, c.MaxEntries)
		assign(&l.Capture.MaxFiles, c.MaxFiles)
		assign(&l.Capture.MaxFileBytes, c.MaxFileBytes)
		assign(&l.Capture.MaxTotalBytes, c.MaxTotalBytes)
		assign(&l.Capture.MaxArchiveBytes, c.MaxArchiveBytes)
		assign(&l.Capture.MaxPathBytes, c.MaxPathBytes)
		assign(&l.Capture.MaxDepth, c.MaxDepth)
	}

	if e := p.Extraction; e != nil {
		assign(&l.Extraction.MaxDepth, e.MaxDepth)
		assign(&l.Extraction.MaxObjects, e.MaxObjects)
		assign(&l.Extraction.MaxEntries, e.MaxEntries)
		assign(&l.Extraction.MaxObjectBytes, e.MaxObjectBytes)
		assign(&l.Extraction.MaxTotalBytes, e.MaxTotalBytes)
	}

	if a := p.Analysis; a != nil {
		assign(&l.Analysis.MaxOperations, a.MaxOperations)
		assign(&l.Analysis.MaxMatchesPerRule, a.MaxMatchesPerRule)

		if err := duration(&l.Analysis.ParserTimeout, a.ParserTimeout, 10*time.Second); err != nil {
			return err
		}
	}

	if p.Retention != nil {
		assign(&l.Retention.MaxFindings, p.Retention.MaxFindings)
	}

	assign(&l.MaxCaptureBytes, p.MaxCaptureBytes)
	assign(&l.MaxExtractedBytes, p.MaxExtractedBytes)
	assign(&l.MaxCaptureFiles, p.MaxCaptureFiles)
	assign(&l.MaxCaptureEntries, p.MaxCaptureEntries)
	assign(&l.MaxServiceRequests, p.MaxServiceRequests)

	return nil
}

func (p *vulnerabilities) apply(s *Settings, grants Grants) error {
	o := osv.DefaultOptions()
	o.Enabled, o.AllowNetwork = true, grants.VulnerabilityNetwork
	assign(&o.Endpoint, p.Endpoint)
	assign(&o.AllowLoopback, p.AllowLoopback)
	assign(&o.MaxRequests, p.MaxRequests)
	assign(&s.OSVCachePath, p.Cache)

	if !o.AllowNetwork && s.OSVCachePath == "" {
		return errors.New("vulnerabilities require network grant or explicit cache path")
	}
	// Validate the endpoint and scalar options without loading the offline cache
	// or granting network access in the settings returned to the caller.
	check := o

	check.AllowNetwork = true
	if err := check.Validate(); err != nil {
		return errors.New("invalid vulnerability config")
	}

	s.Scanner.Vulnerabilities = &o

	return nil
}

func (p *reviewPatch) options() (*Reviewer, error) {
	if err := p.credentialFields(); err != nil {
		return nil, err
	}

	o := review.DefaultOptions()
	o.Enabled, o.AllowSourceUpload = true, true
	assign(&o.QualityPolicy, p.Quality)
	assign(&o.MaxRequests, p.MaxRequests)
	assign(&o.MaxInputBytes, p.MaxInputBytes)

	if err := duration(&o.Timeout, p.Timeout, 2*time.Minute); err != nil {
		return nil, err
	}

	if err := o.Validate(); err != nil {
		return nil, errors.New("invalid review limits")
	}

	spec := review.DefaultProviderSpec()
	spec.Kind, spec.Endpoint, spec.Model, spec.Timeout = p.Provider, p.Endpoint, p.Model, o.Timeout
	assign(&spec.KeyEnv, p.KeyEnv)
	assign(&spec.Region, p.AWSRegion)
	assign(&spec.AccessEnv, p.AccessKeyEnv)
	assign(&spec.SecretEnv, p.SecretKeyEnv)
	assign(&spec.SessionEnv, p.SessionEnv)
	assign(&spec.AllowLoopback, p.AllowLoopback)
	assign(&spec.MaxOutputTokens, p.MaxOutputTokens)
	assign(&spec.MaxResponseBytes, p.MaxResponseBytes)

	return &Reviewer{Provider: spec, Settings: o}, nil
}

func (p *reviewPatch) credentialFields() error {
	if err := p.credentialProvider(); err != nil {
		return err
	}

	for _, value := range []*string{p.KeyEnv, p.AccessKeyEnv, p.SecretKeyEnv, p.SessionEnv} {
		if value != nil && *value == "" {
			return errors.New("explicit credential variable must not be empty")
		}
	}

	return nil
}

func (p *reviewPatch) credentialProvider() error {
	if p.Provider != review.ProviderBedrock && (p.AWSRegion != nil || p.AccessKeyEnv != nil || p.SecretKeyEnv != nil || p.SessionEnv != nil) {
		return errors.New("AWS fields require Bedrock")
	}

	if p.Provider == review.ProviderBedrock && p.KeyEnv != nil {
		return errors.New("explicit AWS credential variables are required for Bedrock")
	}

	return nil
}

func knownStruct(n *jsonconfig.Node, typ reflect.Type) bool {
	fields := make(map[string]reflect.Type, typ.NumField())
	for field := range typ.Fields() {
		fields[field.Tag.Get("json")] = field.Type
	}

	for _, m := range n.Members {
		field, exists := fields[m.Key]
		if !exists || !knownShape(m.Value, field) {
			return false
		}
	}

	return true
}

func knownMap(n *jsonconfig.Node, typ reflect.Type) bool {
	if n.Kind != jsonconfig.KindObject {
		return false
	}

	for _, m := range n.Members {
		if !knownShape(m.Value, typ.Elem()) {
			return false
		}
	}

	return true
}
