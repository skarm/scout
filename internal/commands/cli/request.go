package cli

import (
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/skarm/scout"
	"github.com/skarm/scout/fetch"
	configfile "github.com/skarm/scout/internal/commands/config"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

const (
	flagDownloadSHA256 = "download-sha256"
	flagExclude        = "exclude"
	flagRevision       = "revision"
)

const (
	flagAllowBaselineGlobs = "allow-baseline-globs"
	flagBaseline           = "baseline"
	flagChecks             = "checks"
	flagExtractDepth       = "extract-depth"
	flagExtractEntries     = "extract-entries"
	flagExtractObjectBytes = "extract-object-bytes"
	flagExtractObjects     = "extract-objects"
	flagExtractBytes       = "extract-bytes"
	flagFailOn             = "fail-on"
	flagHarness            = "harness"
	flagMaxArchiveBytes    = "max-archive-bytes"
	flagMaxEntries         = "max-entries"
	flagMaxFileBytes       = "max-file-bytes"
	flagMaxFiles           = "max-files"
	flagMaxFindings        = "max-findings"
	flagMaxMatchesPerRule  = "max-matches-per-rule"
	flagMaxOperations      = "max-operations"
	flagMaxRunBytes        = "max-run-bytes"
	flagMaxTargetBytes     = "max-target-bytes"
	flagParserTimeout      = "parser-timeout"
	flagProfile            = "profile"
	flagScope              = "scope"
	flagTargetWorkers      = "target-workers"
	flagTimeout            = "timeout"
	flagWorkers            = "workers"
	flagYARA               = "yara"
)

const (
	flagApprovedSHA256 = "approved-sha256"
	flagMaxChanges     = "max-changes"
	flagPRHead         = "pr-head"
	flagPRPath         = "pr-path"
	flagPRProvider     = "pr-provider"
)

type request struct {
	settings                        configfile.Settings
	format, output                  string
	reports                         repeated
	stdinName                       string
	revision, sha256                string
	targets                         []string
	publicationInputs               []string
	compare                         scout.CompareOptions
	prHead, prPath, prProvider      string
	pr                              report.PRSummary
	approvedSHA256                  string
	configPath                      string
	grants                          configfile.Grants
	followExternal                  bool
	environment                     bool
	harnessExplicit                 bool
	snapshotCandidate, snapshotSave string
	snapshotEmpty                   bool
	snapshotSourceDiff              bool
	externalOrigins                 repeated
	skillExcludes                   repeated
	externalDepth, externalRequests int
	externalBytes                   int64

	gitAuthOrigin, gitAuthUser, gitTokenEnv string
}

// argvPatch is passive typed input. Its populated service/check nodes are flag
// destinations, not a scanner configuration. Only resolve produces settings.
// Presence distinguishes an omitted flag from an explicit false or zero.
type argvPatch struct {
	values                  request
	present                 map[string]bool
	checks                  checkSelection
	review, vulnerabilities bool
}

type stringSetting[T ~string] struct{ value *T }

func parseRequest(command string, args []string, stderr io.Writer) (request, error) {
	return resolveRequest(command, args, stderr, nil)
}

func resolveRequest(command string, args []string, stderr io.Writer, extra func(*flag.FlagSet)) (request, error) {
	patch, err := parseArgv(command, args, stderr, extra)
	if err != nil {
		return patch.values, err
	}

	settings, err := readExplicitSettings(patch.values.configPath, patch.values.grants)
	if err != nil {
		return patch.values, err
	}

	return patch.resolve(settings, os.LookupEnv)
}

func parseArgv(command string, args []string, stderr io.Writer, extra func(*flag.FlagSet)) (argvPatch, error) {
	patch, fs := requestFlagSet(command, stderr, extra)
	if err := parseFlags(fs, args); err != nil {
		return *patch, err
	}

	patch.values.targets = fs.Args()
	fs.Visit(func(f *flag.Flag) { patch.present[canonicalFlagName(f.Name)] = true })

	return *patch, nil
}

// requestFlagSet registers passive flag destinations without reading config,
// credentials or targets. Help uses the same definitions as argument parsing.
func requestFlagSet(command string, stderr io.Writer, extra func(*flag.FlagSet)) (*argvPatch, *flag.FlagSet) {
	settings := configfile.DefaultSettings()
	download, vulnerabilities := fetch.DefaultOptions(), osv.DefaultOptions()
	settings.Scanner.Download, settings.Scanner.Vulnerabilities = &download, &vulnerabilities
	settings.Reviewer = &configfile.Reviewer{Provider: review.DefaultProviderSpec(), Settings: review.DefaultOptions()}
	patch := &argvPatch{
		values:  request{settings: settings},
		present: map[string]bool{},
		checks:  checkSelection{value: allStaticChecks()},
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	bindCommon(fs, &patch.values)
	fs.Var(&patch.checks, flagChecks, "optional `LIST`: python,yaml,toml,yara,patterns or none; subsets require custom")
	bindBudgets(fs, &patch.values.settings.Scanner)
	bindServices(fs, patch)

	switch command {
	case "scan":
		bindScanInputs(fs, &patch.values)
		bindDownloads(fs, &patch.values)
	case "mcp", "config validate":
		bindDownloads(fs, &patch.values)
	}

	if command != "mcp" && command != "config validate" {
		bindReports(fs, &patch.values)
	}

	if extra != nil {
		extra(fs)
	}

	if command == "compare" || command == "snapshot compare" {
		patch.values.compare = scout.DefaultCompareOptions()
		fs.IntVar(&patch.values.compare.MaxChanges, flagMaxChanges, patch.values.compare.MaxChanges, "maximum retained comparison deltas")
	}

	if command == "compare" {
		fs.StringVar(&patch.values.prHead, flagPRHead, "", "candidate revision `OWNER/REPO@SHA` or GitLab project URL followed by @SHA")
		fs.StringVar(&patch.values.prProvider, flagPRProvider, "github", "source link provider: github or gitlab; requires --pr-head")
		fs.StringVar(&patch.values.prPath, flagPRPath, "", "repository-relative directory containing the candidate input; requires --pr-head")
		fs.StringVar(&patch.values.approvedSHA256, flagApprovedSHA256, "", "trusted SHA-256 of the approved comparison candidate snapshot")
	}

	return patch, fs
}

const (
	maxConfigBytes = 256 << 10
)

func readExplicitSettings(path string, grants configfile.Grants) (configfile.Settings, error) {
	data := []byte(`{"schema":"scout.config/v1"}`)

	if path != "" {
		var err error

		data, err = readTrusted(path, nil, maxConfigBytes)
		if err != nil {
			return configfile.Settings{}, errors.New("cannot read operator configuration")
		}
	}

	return configfile.Parse(data, grants)
}

func (p argvPatch) resolve(settings configfile.Settings, lookupEnv func(string) (string, bool)) (request, error) {
	r := p.values

	r.settings = settings
	p.applySettings(&r.settings)
	r.harnessExplicit = p.present[flagHarness]

	if p.present[flagPRHead] || p.present[flagPRPath] || p.present[flagPRProvider] {
		if err := r.configurePR(p.present[flagFormat]); err != nil {
			return r, err
		}
	}

	if p.present[flagApprovedSHA256] {
		if r.approvedSHA256 == "" {
			return r, errors.New("--approved-sha256 requires a nonempty digest")
		}

		r.settings.Policy.ApprovedSnapshotSHA256 = r.approvedSHA256
	}

	if err := p.resolveInspection(&r.settings.Scanner); err != nil {
		return r, err
	}

	r.settings.Policy.FailAt = report.Severity(strings.ToLower(string(r.settings.Policy.FailAt)))
	if err := p.resolveServices(&r.settings); err != nil {
		return r, err
	}

	if err := r.settings.Resolve(lookupEnv); err != nil {
		return r, err
	}

	return r, nil
}

func (r *request) configurePR(explicitFormat bool) error {
	if r.prHead == "" {
		return errors.New("PR summary options require --pr-head")
	}

	var err error

	switch r.prProvider {
	case "github":
		r.pr, err = report.NewPRSummary(r.prHead, r.prPath)
	case "gitlab":
		r.pr, err = report.NewGitLabPRSummary(r.prHead, r.prPath)
	default:
		return errors.New("--pr-provider requires github or gitlab")
	}

	if err != nil {
		return err
	}

	r.compare.IncludeCapabilities = true
	if !explicitFormat {
		r.format = string(report.Markdown)
	}

	return nil
}

func (p argvPatch) applySettings(s *configfile.Settings) {
	v := p.values.settings
	applyArgument(p.present, flagProfile, &s.Scanner.Profile, v.Scanner.Profile)
	applyArgument(p.present, flagBaseline, &s.BaselinePath, v.BaselinePath)
	applyArgument(p.present, flagAllowBaselineGlobs, &s.Policy.AllowGlobs, v.Policy.AllowGlobs)
	applyArgument(p.present, flagScope, &s.Policy.Scope, v.Policy.Scope)

	applyArgument(p.present, flagFailOn, &s.Policy.FailAt, v.Policy.FailAt)

	applyArgument(p.present, flagHarness, &s.Scanner.Harness.Host, v.Scanner.Harness.Host)
	applyArgument(p.present, flagWorkers, &s.Scanner.Concurrency.Workers, v.Scanner.Concurrency.Workers)
	applyArgument(p.present, flagTargetWorkers, &s.Scanner.Concurrency.Targets, v.Scanner.Concurrency.Targets)
	applyArgument(p.present, flagTimeout, &s.Scanner.Limits.Timeout, v.Scanner.Limits.Timeout)
	applyArgument(p.present, flagYARA, &s.ExtraRulesPath, v.ExtraRulesPath)
	applyArgument(p.present, flagRulepack, &s.RulepackPath, v.RulepackPath)
	applyArgument(p.present, flagRulepackSHA256, &s.Scanner.Signatures.RulepackSHA256, v.Scanner.Signatures.RulepackSHA256)
	applyArgument(p.present, flagOSVCache, &s.OSVCachePath, v.OSVCachePath)
	p.applyBudgets(&s.Scanner.Limits)
}

func (p argvPatch) applyBudgets(l *scout.Limits) {
	v := p.values.settings.Scanner.Limits
	applyArgument(p.present, flagMaxFiles, &l.Capture.MaxFiles, v.Capture.MaxFiles)
	applyArgument(p.present, flagMaxEntries, &l.Capture.MaxEntries, v.Capture.MaxEntries)
	applyArgument(p.present, flagMaxFileBytes, &l.Capture.MaxFileBytes, v.Capture.MaxFileBytes)
	applyArgument(p.present, flagMaxTargetBytes, &l.Capture.MaxTotalBytes, v.Capture.MaxTotalBytes)
	applyArgument(p.present, flagMaxArchiveBytes, &l.Capture.MaxArchiveBytes, v.Capture.MaxArchiveBytes)
	applyArgument(p.present, flagMaxRunBytes, &l.MaxCaptureBytes, v.MaxCaptureBytes)
	applyArgument(p.present, flagMaxOperations, &l.Analysis.MaxOperations, v.Analysis.MaxOperations)
	applyArgument(p.present, flagMaxMatchesPerRule, &l.Analysis.MaxMatchesPerRule, v.Analysis.MaxMatchesPerRule)
	applyArgument(p.present, flagParserTimeout, &l.Analysis.ParserTimeout, v.Analysis.ParserTimeout)
	applyArgument(p.present, flagMaxFindings, &l.Retention.MaxFindings, v.Retention.MaxFindings)
	applyArgument(p.present, flagExtractDepth, &l.Extraction.MaxDepth, v.Extraction.MaxDepth)
	applyArgument(p.present, flagExtractObjects, &l.Extraction.MaxObjects, v.Extraction.MaxObjects)
	applyArgument(p.present, flagExtractEntries, &l.Extraction.MaxEntries, v.Extraction.MaxEntries)
	applyArgument(p.present, flagExtractObjectBytes, &l.Extraction.MaxObjectBytes, v.Extraction.MaxObjectBytes)
	applyArgument(p.present, flagExtractBytes, &l.Extraction.MaxTotalBytes, v.Extraction.MaxTotalBytes)
}

func (p argvPatch) resolveInspection(o *scout.Options) error {
	checks := allStaticChecks()

	switch o.Profile {
	case "extended":
		o.Profile = scout.Standard
	case "semantic":
		o.Profile = scout.Review
	case "basic":
		o.Profile = scout.Custom
		checks = scout.Checks{}
	case scout.Custom:
		if o.Checks != nil {
			checks = *o.Checks
		}
	}

	applyArgument(p.present, flagChecks, &checks, p.checks.value)

	o.Checks = nil
	if o.Profile == scout.Custom {
		o.Checks = &checks
	} else if checks != allStaticChecks() {
		return errors.New("named profiles require every check; choose custom for explicit selection")
	}

	return nil
}

func applyArgument[T any](present map[string]bool, name string, destination *T, value T) {
	if present[name] {
		*destination = value
	}
}

func bindCommon(fs *flag.FlagSet, r *request) {
	configSpecified := false

	fs.Func(flagConfig, "explicit operator config `FILE`", func(value string) error {
		if configSpecified || value == "" {
			return errors.New("config requires one explicit path")
		}

		configSpecified, r.configPath = true, value

		return nil
	})
	fs.Var(stringSetting[scout.Profile]{value: &r.settings.Scanner.Profile}, flagProfile, "inspection `PROFILE`: standard, review or custom")
	fs.StringVar(&r.settings.BaselinePath, flagBaseline, r.settings.BaselinePath, "operator approvals `FILE` outside inputs")
	fs.BoolVar(&r.settings.Policy.AllowGlobs, flagAllowBaselineGlobs, r.settings.Policy.AllowGlobs, "permit broad approvals")
	fs.Var(stringSetting[report.Severity]{value: &r.settings.Policy.FailAt}, flagFailOn, "minimum blocking `SEVERITY`: info, low, medium, high or critical")
	fs.Var(stringSetting[policy.ScopePolicy]{value: &r.settings.Policy.Scope}, flagScope, "coverage `POLICY`: conservative (default) or selected")
	fs.StringVar(&r.settings.Scanner.Harness.Host, flagHarness, r.settings.Scanner.Harness.Host, "`HOST` interpretation: auto, claude-code, codex, cursor, copilot-cli, opencode, gemini-cli, openclaw or agent-skills")
	fs.IntVar(&r.settings.Scanner.Concurrency.Workers, flagWorkers, r.settings.Scanner.Concurrency.Workers, "analyzer workers shared across targets (1..32)")
	fs.IntVar(&r.settings.Scanner.Concurrency.Targets, flagTargetWorkers, r.settings.Scanner.Concurrency.Targets, "concurrent targets (1..32)")
	fs.DurationVar(&r.settings.Scanner.Limits.Timeout, flagTimeout, r.settings.Scanner.Limits.Timeout, "whole operation timeout")
}

func bindReports(fs *flag.FlagSet, r *request) {
	fs.StringVar(&r.format, flagFormat, "text", "report `FORMAT`: text, json, sarif or markdown")
	fs.StringVar(&r.output, flagOutput, "", "report `FILE` (atomic replacement; default stdout)")
	fs.Var(&r.reports, flagReport, "additional `FORMAT=PATH`; repeatable")
}

func bindScanInputs(fs *flag.FlagSet, r *request) {
	fs.Func(flagStdin, "read stdin as relative filename `NAME` for format detection and source coordinates", func(name string) error {
		if name == "" {
			return errors.New("stdin requires a relative filename")
		}

		r.stdinName = name

		return nil
	})
	fs.BoolVar(&r.environment, flagEnvironment, false, "treat selected local roots as one agent/project environment")
	fs.Var(&r.skillExcludes, flagExclude, "omit matching files within one local skill root; POSIX-path `GLOB`; repeatable")
	fs.StringVar(&r.revision, flagRevision, "", "full Git commit `SHA` (40 hexadecimal characters)")
	fs.StringVar(&r.sha256, flagDownloadSHA256, "", "pinned response hash")
}

func (s stringSetting[T]) String() string {
	if s.value == nil {
		return ""
	}

	return string(*s.value)
}

func (s stringSetting[T]) Set(value string) error { *s.value = T(value); return nil }
func bindBudgets(fs *flag.FlagSet, o *scout.Options) {
	c := &o.Limits.Capture
	e := &o.Limits.Extraction
	a := &o.Limits.Analysis

	fs.IntVar(&c.MaxFiles, flagMaxFiles, c.MaxFiles, "captured files per target")
	fs.IntVar(&c.MaxEntries, flagMaxEntries, c.MaxEntries, "entries per target")
	fs.Int64Var(&c.MaxFileBytes, flagMaxFileBytes, c.MaxFileBytes, "bytes per file")
	fs.Int64Var(&c.MaxTotalBytes, flagMaxTargetBytes, c.MaxTotalBytes, "captured bytes per target")
	fs.Int64Var(&c.MaxArchiveBytes, flagMaxArchiveBytes, c.MaxArchiveBytes, "compressed bytes per target")
	fs.Int64Var(&o.Limits.MaxCaptureBytes, flagMaxRunBytes, o.Limits.MaxCaptureBytes, "captured bytes across all targets")
	fs.Uint64Var(&a.MaxOperations, flagMaxOperations, a.MaxOperations, "bounded analysis operations across targets")
	fs.IntVar(&a.MaxMatchesPerRule, flagMaxMatchesPerRule, a.MaxMatchesPerRule, "candidate occurrences per rule")
	fs.DurationVar(&a.ParserTimeout, flagParserTimeout, a.ParserTimeout, "parser timeout")
	fs.IntVar(&o.Limits.Retention.MaxFindings, flagMaxFindings, o.Limits.Retention.MaxFindings, "retained findings across the whole run")
	fs.IntVar(&e.MaxDepth, flagExtractDepth, e.MaxDepth, "extraction depth")
	fs.IntVar(&e.MaxObjects, flagExtractObjects, e.MaxObjects, "derived objects per target")
	fs.IntVar(&e.MaxEntries, flagExtractEntries, e.MaxEntries, "extraction entries per target")
	fs.Int64Var(&e.MaxObjectBytes, flagExtractObjectBytes, e.MaxObjectBytes, "bytes per derived object")
	fs.Int64Var(&e.MaxTotalBytes, flagExtractBytes, e.MaxTotalBytes, "extracted bytes per target")
}
