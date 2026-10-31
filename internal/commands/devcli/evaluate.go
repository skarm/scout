package devcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/capture/rootfs"
	configfile "github.com/skarm/scout/internal/commands/config"
	"github.com/skarm/scout/internal/dev/evaluation"
)

type evaluationInvocation struct {
	path, split, llmConfig string
	profile                scout.Profile
	timeout                time.Duration
	allowUpload            bool
	price                  *evaluation.TokenPrice
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

	opts, err := command.scannerOptions(call)
	if err != nil {
		return failure(diag, err)
	}

	measure := evaluation.Options{Split: command.split, Price: command.price}
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

	r, measureErr := evaluation.MeasureWithOptions(call, scanner, data, measure)
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

	return 0
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

	data, err := readEvaluationFile(ctx, c.llmConfig, 256<<10)
	if err != nil {
		return scout.Options{}, err
	}

	settings, err := configfile.Parse(data, configfile.Grants{SourceUpload: c.allowUpload})
	if err != nil {
		return scout.Options{}, err
	}

	if settings.Reviewer == nil || settings.Scanner.Vulnerabilities != nil || settings.BaselinePath != "" || settings.OSVCachePath != "" || settings.ExtraRulesPath != "" || len(settings.RemotePins) != 0 {
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
	profile := fs.String("profile", "standard", "standard or custom (builtins only); mutually exclusive with --llm-config")
	fs.DurationVar(&c.timeout, "timeout", 2*time.Minute, "whole corpus deadline")
	fs.StringVar(&c.split, "split", "", "measure only train, tune or holdout after validating all splits")
	fs.StringVar(&c.llmConfig, "llm-config", "", "explicit scout.config/v1 with review provider and scanner settings")
	fs.BoolVar(&c.allowUpload, "allow-source-upload", false, "allow bounded corpus source excerpts to the configured reviewer")
	input := fs.Float64("input-usd-per-million", 0, "operator-supplied input token price assumption")

	output := fs.Float64("output-usd-per-million", 0, "operator-supplied output token price assumption")
	if err := fs.Parse(args); err != nil {
		return c, err
	}

	present := map[string]bool{}

	fs.Visit(func(f *flag.Flag) { present[f.Name] = true })

	if fs.NArg() != 1 || c.timeout <= 0 || c.timeout > 10*time.Minute {
		return c, errors.New("evaluate requires one corpus and bounded timeout")
	}

	if c.llmConfig != "" && (!c.allowUpload || present["profile"]) || c.llmConfig == "" && c.allowUpload {
		return c, errors.New("--llm-config requires --allow-source-upload and supplies its own profile")
	}

	if present["input-usd-per-million"] || present["output-usd-per-million"] {
		if c.llmConfig == "" || !present["input-usd-per-million"] || !present["output-usd-per-million"] {
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
	// Resolve an explicitly selected symlink, then use the same no-follow,
	// nonblocking file access as capture. Streams and devices are not corpora.
	absolute, err := filepath.Abs(name)
	if err != nil {
		return nil, errors.New("invalid evaluation input path")
	}

	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, errors.New("cannot resolve evaluation input")
	}

	root, err := rootfs.Open(filepath.Dir(absolute))
	if err != nil {
		return nil, errors.New("cannot open evaluation input directory")
	}

	defer func() { _ = root.Close() }()

	f, err := root.Open(filepath.Base(absolute))
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
