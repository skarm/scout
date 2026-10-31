package cli

import (
	"errors"
	"flag"
	"strings"

	"github.com/skarm/scout"
	"github.com/skarm/scout/fetch"
	configfile "github.com/skarm/scout/internal/commands/config"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/review"
)

func bindServices(fs *flag.FlagSet, p *argvPatch) {
	r := &p.values
	fs.BoolVar(&r.grants.Download, "allow-download", r.grants.Download, "allow explicit downloads")

	external := scout.DefaultExternalOptions()

	fs.BoolVar(&r.followExternal, "follow-external", false, "capture bounded external source references with a separate explicit download grant")
	fs.Var(&r.externalOrigins, "external-origin", "allowed exact source origin; repeatable, replaces default origins")
	fs.IntVar(&r.externalDepth, "external-depth", external.MaxDepth, "maximum external reference depth")
	fs.IntVar(&r.externalRequests, "external-max-requests", external.MaxRequests, "maximum external source requests")
	fs.Int64Var(&r.externalBytes, "external-max-bytes", external.MaxBytes, "aggregate external response byte ceiling")
	fs.BoolVar(&r.grants.VulnerabilityNetwork, "allow-vulnerability-network", r.grants.VulnerabilityNetwork, "allow package coordinate queries")
	fs.BoolVar(&r.grants.SourceUpload, "allow-source-upload", r.grants.SourceUpload, "allow captured source upload")
	fs.BoolVar(&r.settings.Scanner.Download.AllowLoopback, "download-allow-loopback", r.settings.Scanner.Download.AllowLoopback, "allow explicit local download server")
	fs.DurationVar(&r.settings.Scanner.Download.Timeout, "download-timeout", r.settings.Scanner.Download.Timeout, "download timeout")
	fs.StringVar(&r.revision, "revision", "", "pinned commit revision")
	fs.StringVar(&r.sha256, "download-sha256", "", "pinned response hash")
	fs.StringVar(&r.settings.ExtraRulesPath, "yara-rules", r.settings.ExtraRulesPath, "trusted additional rules file")
	fs.BoolVar(&p.vulnerabilities, "vuln", p.vulnerabilities, "enable exact vulnerability queries")
	fs.StringVar(&r.settings.OSVCachePath, "osv-cache", r.settings.OSVCachePath, "trusted offline query cache")
	fs.StringVar(&r.settings.Scanner.Vulnerabilities.Endpoint, "osv-endpoint", r.settings.Scanner.Vulnerabilities.Endpoint, "query endpoint")
	fs.BoolVar(&r.settings.Scanner.Vulnerabilities.AllowLoopback, "osv-allow-loopback", r.settings.Scanner.Vulnerabilities.AllowLoopback, "allow explicit local query endpoint")
	fs.IntVar(&r.settings.Scanner.Vulnerabilities.MaxRequests, "osv-max-requests", r.settings.Scanner.Vulnerabilities.MaxRequests, "request ceiling")
	fs.DurationVar(&r.settings.Scanner.Vulnerabilities.MaxCacheAge, "osv-cache-max-age", r.settings.Scanner.Vulnerabilities.MaxCacheAge, "cache maximum age")
	bindReviewer(fs, p)
}

func bindReviewer(fs *flag.FlagSet, p *argvPatch) {
	r := p.values.settings.Reviewer
	fs.BoolVar(&p.semantic, "semantic", p.semantic, "enable explicit provider review")
	fs.BoolVar(&r.Settings.QualityPolicy, "quality-review", r.Settings.QualityPolicy, "include quality review")
	fs.StringVar(&r.Provider.Kind, "llm-provider", r.Provider.Kind, "chat-completions, anthropic, anthropic-proxy or bedrock")
	fs.StringVar(&r.Provider.Endpoint, "llm-endpoint", r.Provider.Endpoint, "explicit review endpoint")
	fs.StringVar(&r.Provider.Model, "llm-model", r.Provider.Model, "explicit model")
	fs.StringVar(&r.Provider.KeyEnv, "llm-api-key-env", r.Provider.KeyEnv, "explicit credential variable")
	fs.StringVar(&r.Provider.Region, "llm-aws-region", r.Provider.Region, "Bedrock region")
	fs.StringVar(&r.Provider.AccessEnv, "llm-aws-access-key-env", r.Provider.AccessEnv, "explicit access key variable")
	fs.StringVar(&r.Provider.SecretEnv, "llm-aws-secret-key-env", r.Provider.SecretEnv, "explicit secret key variable")
	fs.StringVar(&r.Provider.SessionEnv, "llm-aws-session-token-env", r.Provider.SessionEnv, "explicit session variable")
	fs.BoolVar(&r.Provider.AllowLoopback, "llm-allow-loopback", r.Provider.AllowLoopback, "allow explicit local reviewer")
	fs.IntVar(&r.Provider.MaxOutputTokens, "llm-max-output-tokens", r.Provider.MaxOutputTokens, "output token ceiling")
	fs.IntVar(&r.Provider.MaxResponseBytes, "llm-max-response-bytes", r.Provider.MaxResponseBytes, "provider response byte ceiling")
	fs.IntVar(&r.Settings.MaxRequests, "llm-max-requests", r.Settings.MaxRequests, "review request ceiling")
	fs.IntVar(&r.Settings.MaxInputBytes, "llm-max-input-bytes", r.Settings.MaxInputBytes, "serialized request byte ceiling")
	fs.DurationVar(&r.Settings.Timeout, "llm-timeout", r.Settings.Timeout, "review timeout")
}

func (p argvPatch) resolveServices(s *configfile.Settings) error {
	if err := p.resolveDownload(s); err != nil {
		return err
	}

	if err := p.resolveVulnerabilities(s); err != nil {
		return err
	}

	return p.resolveReview(s)
}

func (p argvPatch) resolveDownload(s *configfile.Settings) error {
	v := fetch.DefaultOptions()
	if s.Scanner.Download != nil {
		v = *s.Scanner.Download
	}

	patch := p.values.settings.Scanner.Download
	applyArgument(p.present, "download-allow-loopback", &v.AllowLoopback, patch.AllowLoopback)
	applyArgument(p.present, "download-timeout", &v.Timeout, patch.Timeout)

	if p.values.grants.Download {
		v.Enabled = true
		s.Scanner.Download = &v
	} else if p.values.revision != "" || p.values.sha256 != "" || v.AllowLoopback {
		return errors.New("download options require --allow-download")
	}

	if p.values.followExternal {
		if !v.Enabled {
			return errors.New("--follow-external requires --allow-download")
		}

		ext := scout.DefaultExternalOptions()
		ext.MaxDepth = p.values.externalDepth
		ext.MaxRequests = p.values.externalRequests

		ext.MaxBytes = p.values.externalBytes
		if len(p.values.externalOrigins) > 0 {
			ext.AllowedOrigins = append([]string(nil), p.values.externalOrigins...)
		}

		s.Scanner.External = &ext
	} else {
		for name := range p.present {
			if strings.HasPrefix(name, "external-") {
				return errors.New("external traversal options require --follow-external")
			}
		}
	}

	return nil
}

func (p argvPatch) resolveVulnerabilities(s *configfile.Settings) error {
	enabled := s.Scanner.Vulnerabilities != nil
	if p.present["vuln"] {
		enabled = p.vulnerabilities
	}

	v := osv.DefaultOptions()
	if s.Scanner.Vulnerabilities != nil {
		v = *s.Scanner.Vulnerabilities
	}

	patch := p.values.settings.Scanner.Vulnerabilities
	applyArgument(p.present, "osv-endpoint", &v.Endpoint, patch.Endpoint)
	applyArgument(p.present, "osv-allow-loopback", &v.AllowLoopback, patch.AllowLoopback)
	applyArgument(p.present, "osv-max-requests", &v.MaxRequests, patch.MaxRequests)
	applyArgument(p.present, "osv-cache-max-age", &v.MaxCacheAge, patch.MaxCacheAge)

	s.Scanner.Vulnerabilities = nil
	if enabled || s.OSVCachePath != "" {
		v.Enabled, v.AllowNetwork = true, p.values.grants.VulnerabilityNetwork
		s.Scanner.Vulnerabilities = &v
	} else if p.values.grants.VulnerabilityNetwork {
		return errors.New("vulnerability grant requires an enabled service")
	}

	return nil
}

func (p argvPatch) resolveReview(s *configfile.Settings) error {
	enabled := s.Reviewer != nil
	if p.present["semantic"] {
		enabled = p.semantic
	}

	if !enabled {
		if p.reviewerFlagsPresent() {
			return errors.New("provider options require --semantic")
		}

		s.Reviewer, s.Scanner.Review = nil, nil
	} else {
		reviewer := configfile.Reviewer{Provider: review.DefaultProviderSpec(), Settings: review.DefaultOptions()}
		if s.Reviewer != nil {
			reviewer = *s.Reviewer
		}

		p.applyReviewer(&reviewer)
		reviewer.Settings.Enabled, reviewer.Settings.AllowSourceUpload = true, p.values.grants.SourceUpload
		reviewer.Provider.Timeout = reviewer.Settings.Timeout
		s.Reviewer = &reviewer
	}

	if p.values.grants.SourceUpload && s.Reviewer == nil {
		return errors.New("source-upload grant requires an explicit reviewer")
	}

	return nil
}

func (p argvPatch) applyReviewer(r *configfile.Reviewer) {
	v := p.values.settings.Reviewer
	applyArgument(p.present, "quality-review", &r.Settings.QualityPolicy, v.Settings.QualityPolicy)
	applyArgument(p.present, "llm-provider", &r.Provider.Kind, v.Provider.Kind)
	applyArgument(p.present, "llm-endpoint", &r.Provider.Endpoint, v.Provider.Endpoint)
	applyArgument(p.present, "llm-model", &r.Provider.Model, v.Provider.Model)
	applyArgument(p.present, "llm-api-key-env", &r.Provider.KeyEnv, v.Provider.KeyEnv)
	applyArgument(p.present, "llm-aws-region", &r.Provider.Region, v.Provider.Region)
	applyArgument(p.present, "llm-aws-access-key-env", &r.Provider.AccessEnv, v.Provider.AccessEnv)
	applyArgument(p.present, "llm-aws-secret-key-env", &r.Provider.SecretEnv, v.Provider.SecretEnv)
	applyArgument(p.present, "llm-aws-session-token-env", &r.Provider.SessionEnv, v.Provider.SessionEnv)
	applyArgument(p.present, "llm-allow-loopback", &r.Provider.AllowLoopback, v.Provider.AllowLoopback)
	applyArgument(p.present, "llm-max-output-tokens", &r.Provider.MaxOutputTokens, v.Provider.MaxOutputTokens)
	applyArgument(p.present, "llm-max-response-bytes", &r.Provider.MaxResponseBytes, v.Provider.MaxResponseBytes)
	applyArgument(p.present, "llm-max-requests", &r.Settings.MaxRequests, v.Settings.MaxRequests)
	applyArgument(p.present, "llm-max-input-bytes", &r.Settings.MaxInputBytes, v.Settings.MaxInputBytes)
	applyArgument(p.present, "llm-timeout", &r.Settings.Timeout, v.Settings.Timeout)
}

func (p argvPatch) reviewerFlagsPresent() bool {
	for name := range p.present {
		if strings.HasPrefix(name, "llm-") || name == "quality-review" {
			return true
		}
	}

	return false
}
