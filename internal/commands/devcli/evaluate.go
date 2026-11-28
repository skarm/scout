package devcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/skarm/scout"
	configfile "github.com/skarm/scout/internal/commands/config"
	"github.com/skarm/scout/internal/dev/evaluation"
)

const (
	flagAllowSourceUpload    = "allow-source-upload"
	flagInputUsdPerMillion   = "input-usd-per-million"
	flagLLMConfig            = "llm-config"
	flagLabelReview          = "label-review"
	flagMaxFPR               = "max-fpr"
	flagMaxIncomplete        = "max-incomplete"
	flagMinRecall            = "min-recall"
	flagOutputUsdPerMillion  = "output-usd-per-million"
	flagProfile              = "profile"
	flagRequireIndependent   = "require-independent"
	flagShellHookRoots       = "shell-hook-roots"
	flagShellHooks           = "shell-hooks"
	flagSplit                = "split"
	flagTrustedLabelReviewer = "trusted-label-reviewer"
)

const (
	maxEvaluationReviewConfigBytes = 256 << 10
	defaultEvaluationTimeout       = 2 * time.Minute
	maxEvaluationTimeout           = 10 * time.Minute
)

type evaluationInvocation struct {
	path, split, llmConfig string
	labelReviewPath        string
	shellHookRootsPath     string
	trustedLabelReviewers  []string
	profile                scout.Profile
	timeout                time.Duration
	allowUpload            bool
	shellHooks             bool
	price                  *evaluation.TokenPrice
	requirements           evaluation.Requirements
}

func evaluate(ctx context.Context, args []string, out, diag io.Writer) int {
	command, err := parseEvaluation(args, diag)
	if err != nil {
		return failure(diag, err)
	}

	call, cancel := context.WithTimeout(ctx, command.timeout)
	defer cancel()

	data, err := readEvaluationFile(call, command.path, evaluation.MaxCorpusBytes)
	if err != nil {
		return failure(diag, err)
	}
	// Reject invalid corpora before constructing providers or reading credentials.
	if _, err := evaluation.Parse(data); err != nil {
		return failure(diag, err)
	}

	if err := call.Err(); err != nil {
		return failure(diag, err)
	}

	labelReview, err := command.labelReview(call, data)
	if err != nil {
		return failure(diag, err)
	}

	opts, err := command.scannerOptions(call)
	if err != nil {
		return failure(diag, err)
	}

	measure := evaluation.Options{Split: command.split, Price: command.price, LabelReview: labelReview, ShellHooks: command.shellHooks}
	if opts.Review != nil {
		measure.Reviewer, err = scout.New(call, opts)
		if err != nil {
			return failure(diag, err)
		}
		defer func() { _ = measure.Reviewer.Close() }()

		opts.Review = nil
		if opts.Profile == scout.Review {
			opts.Profile = scout.Standard
		}
	}

	scanner, err := scout.New(call, opts)
	if err != nil {
		return failure(diag, err)
	}

	defer func() { _ = scanner.Close() }()

	if command.shellHookRootsPath != "" {
		raw, err := readEvaluationFile(call, command.shellHookRootsPath, evaluation.MaxShellHookRootsBytes)
		if err != nil {
			return failure(diag, err)
		}

		roots, err := evaluation.ParseShellHookRoots(raw)
		if err != nil {
			return failure(diag, err)
		}

		measure.ShellHookRoots = &roots

		opts.Harness.ShellHookRoot = roots.ShellHookRoot

		measure.ShellHookRootScanner, err = scout.New(call, opts)
		if err != nil {
			return failure(diag, err)
		}

		defer func() { _ = measure.ShellHookRootScanner.Close() }()
	}

	r, measureErr := evaluation.MeasureWithOptions(call, scanner, data, measure)
	if command.requirements.Enabled() {
		gate := evaluation.Assess(r, command.requirements)
		r.Gate = &gate
	}
	// Preserve completed cases on cancellation; never publish an empty report as
	// a successful measurement.
	if len(r.Results) > 0 {
		if err := json.NewEncoder(out).Encode(r); err != nil {
			return failure(diag, err)
		}
	}

	if measureErr != nil {
		return failure(diag, measureErr)
	}

	if r.Gate != nil && !r.Gate.Passed {
		return 1
	}

	return 0
}

func (c evaluationInvocation) labelReview(ctx context.Context, corpus []byte) (*evaluation.LabelReview, error) {
	if c.labelReviewPath == "" {
		return nil, nil
	}

	raw, err := readEvaluationFile(ctx, c.labelReviewPath, evaluation.MaxLabelReviewBytes)
	if err != nil {
		return nil, err
	}

	return evaluation.ValidateLabelReview(corpus, raw, c.trustedLabelReviewers, time.Now())
}

func (c evaluationInvocation) scannerOptions(ctx context.Context) (scout.Options, error) {
	if c.llmConfig == "" {
		opts := scout.DefaultOptions()

		opts.Profile = c.profile
		if c.profile == scout.Custom {
			opts.Checks = &scout.Checks{}
		}

		return opts, nil
	}

	data, err := readEvaluationFile(ctx, c.llmConfig, maxEvaluationReviewConfigBytes)
	if err != nil {
		return scout.Options{}, err
	}

	settings, err := configfile.Parse(data, configfile.Grants{SourceUpload: c.allowUpload})
	if err != nil {
		return scout.Options{}, err
	}

	if settings.Reviewer == nil || settings.Scanner.Vulnerabilities != nil || settings.BaselinePath != "" || settings.OSVCachePath != "" || settings.ExtraRulesPath != "" || settings.RulepackPath != "" || len(settings.RemotePins) != 0 {
		return scout.Options{}, errors.New("evaluation config requires review and cannot load baselines, extra rules, advisory caches or remote pins")
	}

	if err := ctx.Err(); err != nil {
		return scout.Options{}, err
	}

	if err := settings.Resolve(os.LookupEnv); err != nil {
		return scout.Options{}, err
	}

	return settings.Scanner, nil
}

func parseEvaluation(args []string, diag io.Writer) (evaluationInvocation, error) {
	c := evaluationInvocation{}
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	fs.SetOutput(diag)
	profile := fs.String(flagProfile, string(scout.Standard), "standard or custom (builtins only); mutually exclusive with --llm-config")
	fs.DurationVar(&c.timeout, flagTimeout, defaultEvaluationTimeout, "whole corpus deadline")
	fs.StringVar(&c.split, flagSplit, "", "measure only train, tune or holdout after validating all splits")
	fs.BoolVar(&c.shellHooks, flagShellHooks, false, "report targeted signal metrics for shell_hooks cases labelled for eval and generated-script execution")
	fs.StringVar(&c.shellHookRootsPath, flagShellHookRoots, "", "explicit host, shell-safe plugin path and case IDs to assume for simple hook launches; requires --shell-hooks")
	fs.StringVar(&c.llmConfig, flagLLMConfig, "", "explicit scout.config/v1 with review provider and scanner settings")
	fs.StringVar(&c.labelReviewPath, flagLabelReview, "", "separate scout.corpus-review/v1 decisions bound to the exact corpus SHA-256")
	fs.Func(flagTrustedLabelReviewer, fmt.Sprintf("explicitly trusted reviewer ID for --label-review; repeatable, at most %d", evaluation.MaxTrustedLabelReviewers), func(id string) error {
		if id == "" || len(c.trustedLabelReviewers) >= evaluation.MaxTrustedLabelReviewers {
			return fmt.Errorf("trusted label reviewers require nonempty IDs and at most %d values", evaluation.MaxTrustedLabelReviewers)
		}

		c.trustedLabelReviewers = append(c.trustedLabelReviewers, id)

		return nil
	})
	fs.BoolVar(&c.allowUpload, flagAllowSourceUpload, false, "allow bounded corpus source excerpts to the configured reviewer")
	minRecall := fs.Float64(flagMinRecall, 0, "minimum static signal recall in 0..1; an undefined recall fails")
	maxFPR := fs.Float64(flagMaxFPR, 1, "maximum static false-positive rate in 0..1; an undefined rate fails")
	maxIncomplete := fs.Int(flagMaxIncomplete, 0, "maximum number of incomplete static cases")
	fs.BoolVar(&c.requirements.RequireIndependent, flagRequireIndependent, false, "require validated independent label review from trusted reviewers and an explicitly selected holdout split")
	input := fs.Float64(flagInputUsdPerMillion, 0, "operator-supplied input token price assumption")

	output := fs.Float64(flagOutputUsdPerMillion, 0, "operator-supplied output token price assumption")
	if err := fs.Parse(args); err != nil {
		return c, err
	}

	present := map[string]bool{}

	fs.Visit(func(f *flag.Flag) { present[f.Name] = true })

	if present[flagMinRecall] {
		c.requirements.MinRecall = minRecall
	}

	if present[flagMaxFPR] {
		c.requirements.MaxFalsePositive = maxFPR
	}

	if present[flagMaxIncomplete] {
		c.requirements.MaxIncomplete = maxIncomplete
	}

	if err := c.requirements.Validate(); err != nil {
		return c, err
	}

	if present[flagShellHookRoots] && (!c.shellHooks || c.shellHookRootsPath == "" || c.llmConfig != "") {
		return c, errors.New("--shell-hook-roots requires a file, --shell-hooks and a static profile")
	}

	if (c.labelReviewPath == "") != (len(c.trustedLabelReviewers) == 0) || present[flagLabelReview] && c.labelReviewPath == "" {
		return c, errors.New("--label-review and at least one --trusted-label-reviewer must be supplied together")
	}

	if fs.NArg() != 1 || c.timeout <= 0 || c.timeout > maxEvaluationTimeout {
		return c, errors.New("evaluate requires one corpus and bounded timeout")
	}

	if c.llmConfig != "" && (!c.allowUpload || present[flagProfile]) || c.llmConfig == "" && c.allowUpload {
		return c, errors.New("--llm-config requires --allow-source-upload and supplies its own profile")
	}

	if present[flagInputUsdPerMillion] || present[flagOutputUsdPerMillion] {
		if c.llmConfig == "" || !present[flagInputUsdPerMillion] || !present[flagOutputUsdPerMillion] {
			return c, errors.New("both token prices and --llm-config are required for cost estimation")
		}

		c.price = &evaluation.TokenPrice{InputUSDPerMillion: *input, OutputUSDPerMillion: *output}
	}

	c.path, c.profile = fs.Arg(0), scout.Profile(*profile)

	return c, nil
}

func readEvaluationFile(ctx context.Context, name string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f, err := openInputFile(name)
	if err != nil {
		return nil, errors.New("cannot open evaluation input")
	}

	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("evaluation input must be a bounded regular file")
	}

	data, readErr := io.ReadAll(io.LimitReader(f, limit+1))

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if readErr != nil {
		return nil, errors.New("cannot read evaluation input")
	}

	if int64(len(data)) > limit {
		return nil, errors.New("evaluation input exceeds byte budget")
	}

	return data, nil
}
