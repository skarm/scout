package cli

import (
	"errors"
	"flag"
	"os"
	"strings"

	"github.com/skarm/scout"
	"github.com/skarm/scout/fetch"
	configfile "github.com/skarm/scout/internal/commands/config"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/review"
)

const (
	flagAllowOSVNetwork       = "allow-osv-network"
	flagDownloadAllowLoopback = "download-allow-loopback"
	flagDownloadTimeout       = "download-timeout"
	flagExternalDepth         = "external-depth"
	flagExternalMaxBytes      = "external-max-bytes"
	flagExternalMaxRequests   = "external-max-requests"
	flagExternalOrigin        = "external-origin"
	flagFollowExternal        = "follow-external"
	flagGit                   = "git"
	flagGitAuthOrigin         = "git-auth-origin"
	flagGitAuthUser           = "git-auth-user"
	flagGitTokenEnv           = "git-token-env"   //nolint:gosec // G101: argument name.
	flagLLMAPIKeyEnv          = "llm-api-key-env" //nolint:gosec // G101: argument name.
	flagLLMAWSAccessKeyEnv    = "llm-aws-access-key-env"
	flagLLMAWSRegion          = "llm-aws-region"
	flagLLMAWSSecretKeyEnv    = "llm-aws-secret-key-env"    //nolint:gosec // G101: argument name.
	flagLLMAWSSessionTokenEnv = "llm-aws-session-token-env" //nolint:gosec // G101: argument name.
	flagLLMAllowLoopback      = "llm-allow-loopback"
	flagLLMEndpoint           = "llm-endpoint"
	flagLLMMaxInputBytes      = "llm-max-input-bytes"
	flagLLMMaxOutputTokens    = "llm-max-output-tokens" //nolint:gosec // G101: argument name.
	flagLLMMaxRequests        = "llm-max-requests"
	flagLLMMaxResponseBytes   = "llm-max-response-bytes"
	flagLLMModel              = "llm-model"
	flagLLMProvider           = "llm-provider"
	flagLLMTimeout            = "llm-timeout"
	flagOSV                   = "osv"
	flagOSVAllowLoopback      = "osv-allow-loopback"
	flagOSVCacheMaxAge        = "osv-cache-max-age"
	flagOSVEndpoint           = "osv-endpoint"
	flagOSVMaxRequests        = "osv-max-requests"
	flagOSVSnapshotDir        = "osv-snapshot-dir"
)

const (
	flagAllowDownload     = "allow-download"
	flagQualityReview     = "quality-review"
	flagRulepack          = "rulepack"
	flagRulepackSHA256    = "rulepack-sha256"
	flagAllowSourceUpload = "allow-source-upload"
)

func bindDownloads(fs *flag.FlagSet, r *request) {
	fs.BoolVar(&r.grants.Download, flagAllowDownload, r.grants.Download, "allow explicit downloads")
	fs.BoolVar(&r.settings.Scanner.Download.AllowLoopback, flagDownloadAllowLoopback, r.settings.Scanner.Download.AllowLoopback, "allow explicit local download server")
	fs.DurationVar(&r.settings.Scanner.Download.Timeout, flagDownloadTimeout, r.settings.Scanner.Download.Timeout, "download timeout")
	fs.BoolVar(&r.settings.Scanner.Download.Git, flagGit, r.settings.Scanner.Download.Git, "treat a remote URL as a Git clone URL")
	fs.StringVar(&r.gitAuthOrigin, flagGitAuthOrigin, "", "exact HTTPS origin authorized to receive Git credentials")
	fs.StringVar(&r.gitAuthUser, flagGitAuthUser, "", "Git HTTPS username")
	fs.StringVar(&r.gitTokenEnv, flagGitTokenEnv, "", "environment variable containing a Git HTTPS token")

	external := scout.DefaultExternalOptions()

	fs.BoolVar(&r.followExternal, flagFollowExternal, false, "capture bounded external source references with a separate explicit download grant")
	fs.Var(&r.externalOrigins, flagExternalOrigin, "allowed exact source origin; repeatable, replaces default origins")
	fs.IntVar(&r.externalDepth, flagExternalDepth, external.MaxDepth, "maximum external reference depth")
	fs.IntVar(&r.externalRequests, flagExternalMaxRequests, external.MaxRequests, "maximum external source requests")
	fs.Int64Var(&r.externalBytes, flagExternalMaxBytes, external.MaxBytes, "aggregate external response byte ceiling")
}

func bindServices(fs *flag.FlagSet, p *argvPatch) {
	r := &p.values
	fs.BoolVar(&r.grants.VulnerabilityNetwork, flagAllowOSVNetwork, r.grants.VulnerabilityNetwork, "allow package coordinate queries")
	fs.BoolVar(&r.grants.SourceUpload, flagAllowSourceUpload, r.grants.SourceUpload, "allow captured source upload")
	fs.StringVar(&r.settings.ExtraRulesPath, flagYARA, r.settings.ExtraRulesPath, "trusted additional YARA rules file")
	fs.StringVar(&r.settings.RulepackPath, flagRulepack, r.settings.RulepackPath, "trusted versioned YARA source artifact")
	fs.StringVar(&r.settings.Scanner.Signatures.RulepackSHA256, flagRulepackSHA256, r.settings.Scanner.Signatures.RulepackSHA256, "expected SHA-256 of all rulepack artifact bytes")
	fs.BoolVar(&p.vulnerabilities, flagOSV, p.vulnerabilities, "enable exact OSV queries")
	fs.StringVar(&r.settings.OSVCachePath, flagOSVCache, r.settings.OSVCachePath, "trusted exact-query cache (v1 vulnerabilities; v2 malicious packages)")
	fs.StringVar(&r.settings.OSVSnapshotDir, flagOSVSnapshotDir, r.settings.OSVSnapshotDir, "trusted directory containing Go, npm or PyPI OSV all.zip archives (offline)")
	fs.StringVar(&r.settings.Scanner.Vulnerabilities.Endpoint, flagOSVEndpoint, r.settings.Scanner.Vulnerabilities.Endpoint, "query endpoint")
	fs.BoolVar(&r.settings.Scanner.Vulnerabilities.AllowLoopback, flagOSVAllowLoopback, r.settings.Scanner.Vulnerabilities.AllowLoopback, "allow explicit local query endpoint")
	fs.IntVar(&r.settings.Scanner.Vulnerabilities.MaxRequests, flagOSVMaxRequests, r.settings.Scanner.Vulnerabilities.MaxRequests, "request ceiling")
	fs.DurationVar(&r.settings.Scanner.Vulnerabilities.MaxCacheAge, flagOSVCacheMaxAge, r.settings.Scanner.Vulnerabilities.MaxCacheAge, "cache maximum age")
	bindReviewer(fs, p)
}

func bindReviewer(fs *flag.FlagSet, p *argvPatch) {
	r := p.values.settings.Reviewer
	fs.BoolVar(&p.review, flagReview, p.review, "enable LLM review")
	fs.BoolVar(&r.Settings.QualityPolicy, flagQualityReview, r.Settings.QualityPolicy, "include quality review")
	fs.StringVar(&r.Provider.Kind, flagLLMProvider, r.Provider.Kind, "chat-completions, anthropic, anthropic-proxy or bedrock")
	fs.StringVar(&r.Provider.Endpoint, flagLLMEndpoint, r.Provider.Endpoint, "explicit review endpoint")
	fs.StringVar(&r.Provider.Model, flagLLMModel, r.Provider.Model, "explicit model")
	fs.StringVar(&r.Provider.KeyEnv, flagLLMAPIKeyEnv, r.Provider.KeyEnv, "explicit credential variable")
	fs.StringVar(&r.Provider.Region, flagLLMAWSRegion, r.Provider.Region, "Bedrock region")
	fs.StringVar(&r.Provider.AccessEnv, flagLLMAWSAccessKeyEnv, r.Provider.AccessEnv, "explicit access key variable")
	fs.StringVar(&r.Provider.SecretEnv, flagLLMAWSSecretKeyEnv, r.Provider.SecretEnv, "explicit secret key variable")
	fs.StringVar(&r.Provider.SessionEnv, flagLLMAWSSessionTokenEnv, r.Provider.SessionEnv, "explicit session variable")
	fs.BoolVar(&r.Provider.AllowLoopback, flagLLMAllowLoopback, r.Provider.AllowLoopback, "allow explicit local reviewer")
	fs.IntVar(&r.Provider.MaxOutputTokens, flagLLMMaxOutputTokens, r.Provider.MaxOutputTokens, "output token ceiling")
	fs.IntVar(&r.Provider.MaxResponseBytes, flagLLMMaxResponseBytes, r.Provider.MaxResponseBytes, "provider response byte ceiling")
	fs.IntVar(&r.Settings.MaxRequests, flagLLMMaxRequests, r.Settings.MaxRequests, "review request ceiling")
	fs.IntVar(&r.Settings.MaxInputBytes, flagLLMMaxInputBytes, r.Settings.MaxInputBytes, "serialized request byte ceiling")
	fs.DurationVar(&r.Settings.Timeout, flagLLMTimeout, r.Settings.Timeout, "review timeout")
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
	applyArgument(p.present, flagDownloadAllowLoopback, &v.AllowLoopback, patch.AllowLoopback)
	applyArgument(p.present, flagDownloadTimeout, &v.Timeout, patch.Timeout)
	applyArgument(p.present, flagGit, &v.Git, patch.Git)
	gitAuth := p.present[flagGitAuthOrigin] || p.present[flagGitAuthUser] || p.present[flagGitTokenEnv]

	if p.values.grants.Download {
		if gitAuth {
			credentials, err := p.values.gitCredentials()
			if err != nil {
				return err
			}

			v.GitAuth = credentials
		}

		v.Enabled = true
		s.Scanner.Download = &v
	} else if p.values.revision != "" || p.values.sha256 != "" || v.AllowLoopback || v.Git || gitAuth || p.present[flagDownloadTimeout] {
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

func (r request) gitCredentials() (*fetch.GitCredentials, error) {
	if r.gitAuthOrigin == "" || r.gitAuthUser == "" || r.gitTokenEnv == "" {
		return nil, errors.New("authentication requires --git-auth-origin, --git-auth-user and --git-token-env")
	}

	token, ok := os.LookupEnv(r.gitTokenEnv)
	if !ok || token == "" {
		return nil, errors.New("the Git token environment variable is unset or empty")
	}

	return fetch.NewGitCredentials(r.gitAuthOrigin, r.gitAuthUser, token)
}

func (p argvPatch) resolveVulnerabilities(s *configfile.Settings) error {
	enabled := s.Scanner.Vulnerabilities != nil
	if p.present[flagOSV] {
		enabled = p.vulnerabilities
	}

	v := osv.DefaultOptions()
	if s.Scanner.Vulnerabilities != nil {
		v = *s.Scanner.Vulnerabilities
	}

	patch := p.values.settings.Scanner.Vulnerabilities
	applyArgument(p.present, flagOSVSnapshotDir, &s.OSVSnapshotDir, p.values.settings.OSVSnapshotDir)
	applyArgument(p.present, flagOSVEndpoint, &v.Endpoint, patch.Endpoint)
	applyArgument(p.present, flagOSVAllowLoopback, &v.AllowLoopback, patch.AllowLoopback)
	applyArgument(p.present, flagOSVMaxRequests, &v.MaxRequests, patch.MaxRequests)
	applyArgument(p.present, flagOSVCacheMaxAge, &v.MaxCacheAge, patch.MaxCacheAge)

	s.Scanner.Vulnerabilities = nil
	if s.OSVSnapshotDir != "" && p.values.grants.VulnerabilityNetwork {
		return errors.New("--osv-snapshot-dir requires offline OSV checks")
	}

	if enabled || s.OSVCachePath != "" || s.OSVSnapshotDir != "" {
		v.Enabled, v.AllowNetwork = true, p.values.grants.VulnerabilityNetwork
		s.Scanner.Vulnerabilities = &v
	} else if p.values.grants.VulnerabilityNetwork {
		return errors.New("vulnerability grant requires an enabled service")
	}

	return nil
}

func (p argvPatch) resolveReview(s *configfile.Settings) error {
	enabled := s.Reviewer != nil
	if p.present[flagReview] {
		enabled = p.review
	}

	if !enabled {
		if p.reviewerFlagsPresent() {
			return errors.New("provider options require --review")
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
	applyArgument(p.present, flagQualityReview, &r.Settings.QualityPolicy, v.Settings.QualityPolicy)
	applyArgument(p.present, flagLLMProvider, &r.Provider.Kind, v.Provider.Kind)
	applyArgument(p.present, flagLLMEndpoint, &r.Provider.Endpoint, v.Provider.Endpoint)
	applyArgument(p.present, flagLLMModel, &r.Provider.Model, v.Provider.Model)
	applyArgument(p.present, flagLLMAPIKeyEnv, &r.Provider.KeyEnv, v.Provider.KeyEnv)
	applyArgument(p.present, flagLLMAWSRegion, &r.Provider.Region, v.Provider.Region)
	applyArgument(p.present, flagLLMAWSAccessKeyEnv, &r.Provider.AccessEnv, v.Provider.AccessEnv)
	applyArgument(p.present, flagLLMAWSSecretKeyEnv, &r.Provider.SecretEnv, v.Provider.SecretEnv)
	applyArgument(p.present, flagLLMAWSSessionTokenEnv, &r.Provider.SessionEnv, v.Provider.SessionEnv)
	applyArgument(p.present, flagLLMAllowLoopback, &r.Provider.AllowLoopback, v.Provider.AllowLoopback)
	applyArgument(p.present, flagLLMMaxOutputTokens, &r.Provider.MaxOutputTokens, v.Provider.MaxOutputTokens)
	applyArgument(p.present, flagLLMMaxResponseBytes, &r.Provider.MaxResponseBytes, v.Provider.MaxResponseBytes)
	applyArgument(p.present, flagLLMMaxRequests, &r.Settings.MaxRequests, v.Settings.MaxRequests)
	applyArgument(p.present, flagLLMMaxInputBytes, &r.Settings.MaxInputBytes, v.Settings.MaxInputBytes)
	applyArgument(p.present, flagLLMTimeout, &r.Settings.Timeout, v.Settings.Timeout)
}

func (p argvPatch) reviewerFlagsPresent() bool {
	for name := range p.present {
		if strings.HasPrefix(name, "llm-") || name == flagQualityReview {
			return true
		}
	}

	return false
}
