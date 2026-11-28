package evaluation

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/skarm/scout/internal/dev/hookscenario"
	"github.com/skarm/scout/report"
)

const hookScenarioCorpusHash = "f3799769e8c7f851a2f59db2e8769ef64ee52139b47fdd1a8121d67ef97b40e3"

type HookScenarioReport struct {
	Scope        string                `json:"scope"`
	CorpusSHA256 string                `json:"corpus_sha256"`
	Scenarios    []hookscenario.Result `json:"scenarios"`
}

func (r HookScenarioReport) Complete() bool {
	return !slices.ContainsFunc(r.Scenarios, func(item hookscenario.Result) bool {
		return item.Coverage.Completeness != report.Complete
	})
}

func AnalyzeHookScenarios(ctx context.Context, data []byte) (HookScenarioReport, error) {
	if fmt.Sprintf("%x", sha256.Sum256(data)) != hookScenarioCorpusHash {
		return HookScenarioReport{}, errors.New("scenario corpus SHA-256 mismatch")
	}

	corpus, err := Parse(data)
	if err != nil {
		return HookScenarioReport{}, err
	}

	cases := make(map[string]map[string]string, len(corpus.Cases))
	for _, tc := range corpus.Cases {
		files := make(map[string]string, len(tc.Files))
		for _, file := range tc.Files {
			files[file.Path] = file.Content
		}

		cases[tc.ID] = files
	}

	return HookScenarioReport{
		Scope:        "conditional Bash AST analysis with modeled external responses",
		CorpusSHA256: hookScenarioCorpusHash,
		Scenarios:    hookscenario.Analyze(ctx, cases),
	}, nil
}
