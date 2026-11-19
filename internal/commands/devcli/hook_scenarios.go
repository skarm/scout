package devcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"slices"
	"time"

	"github.com/skarm/scout/internal/analysis/hookscenario"
	"github.com/skarm/scout/internal/dev/evaluation"
	"github.com/skarm/scout/report"
)

const (
	hookScenarioTimeout = 10 * time.Second
)

func hookScenarios(ctx context.Context, args []string, out, diag io.Writer) int {
	fs := flag.NewFlagSet("hook-scenarios", flag.ContinueOnError)
	fs.SetOutput(diag)
	corpus := fs.String("corpus", "", "pinned expanded Shell hook corpus")

	if err := fs.Parse(args); err != nil {
		return failure(diag, err)
	}

	if *corpus == "" || fs.NArg() != 0 {
		return failure(diag, errors.New("--corpus required"))
	}

	ctx, cancel := context.WithTimeout(ctx, hookScenarioTimeout)
	defer cancel()

	data, err := readEvaluationFile(ctx, *corpus, evaluation.MaxCorpusBytes)
	if err != nil {
		return failure(diag, err)
	}

	result, err := evaluation.AnalyzeHookScenarios(ctx, data)
	if err != nil {
		return failure(diag, err)
	}

	if err := json.NewEncoder(out).Encode(result); err != nil {
		return failure(diag, err)
	}

	if slices.ContainsFunc(result.Scenarios, func(item hookscenario.Result) bool {
		return item.Coverage.Completeness != report.Complete
	}) {
		return 1
	}

	return 0
}
