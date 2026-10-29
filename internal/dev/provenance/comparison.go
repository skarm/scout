package provenance

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"regexp"
	"strings"

	"github.com/skarm/scout/internal/textmatch"
)

const comparisonSchema = "scout.replay-comparison/v1"

type adjudication struct {
	Reason string `json:"reason"`
	Test   string `json:"test"`
}

type change struct {
	ID           string        `json:"id"`
	Added        []Observation `json:"added"`
	Removed      []Observation `json:"removed"`
	Adjudication *adjudication `json:"adjudication,omitempty"`
}

type Comparison struct {
	Schema                     string   `json:"schema"`
	Before                     artifact `json:"before"`
	After                      artifact `json:"after"`
	BeforeInputs               int      `json:"before_inputs"`
	AfterInputs                int      `json:"after_inputs"`
	ChangedRows                int      `json:"changed_rows"`
	ExcludedExecutionErrorRows int      `json:"excluded_execution_error_rows"`
	Changes                    []change `json:"changes"`
}

// Compare emits a review candidate. A changed row remains unadjudicated until
// an explicit reason and named regression test are attached to that row.
func Compare(ctx context.Context, root, before, after string) (Comparison, error) {
	root, err := projectRoot(root)
	if err != nil {
		return Comparison{}, err
	}

	if ctx == nil {
		return Comparison{}, errors.New("comparison context required")
	}

	a, err := artifactIdentity(ctx, root, before)
	if err != nil {
		return Comparison{}, err
	}

	b, err := artifactIdentity(ctx, root, after)
	if err != nil {
		return Comparison{}, err
	}

	old, err := readReplay(ctx, root, a, "")
	if err != nil {
		return Comparison{}, err
	}

	next, err := readReplay(ctx, root, b, "")
	if err != nil {
		return Comparison{}, err
	}

	a.UncompressedSHA256, b.UncompressedSHA256 = old.contentSHA256, next.contentSHA256
	comparison, err := compareEvidence(old, next)
	comparison.Before, comparison.After = a, b

	return comparison, err
}

func compareEvidence(before, after replayEvidence) (Comparison, error) {
	result := Comparison{
		Schema:       comparisonSchema,
		BeforeInputs: len(before.ids),
		AfterInputs:  len(after.ids),
		Changes:      []change{},
	}
	if !reflect.DeepEqual(before.ids, after.ids) {
		return result, errors.New("comparison record-ID sets differ")
	}

	for _, id := range after.ids {
		a, b := before.rows[id], after.rows[id]
		if a.error || b.error {
			result.ExcludedExecutionErrorRows++
			continue
		}

		added, removed := observationDelta(a.observations, b.observations)
		if len(added)+len(removed) > 0 {
			result.Changes = append(result.Changes, change{ID: id, Added: added, Removed: removed})
		}
	}

	result.ChangedRows = len(result.Changes)

	return result, nil
}

func observationDelta(before, after []Observation) ([]Observation, []Observation) {
	added, removed := make([]Observation, 0), make([]Observation, 0)

	i, j := 0, 0
	for i < len(before) && j < len(after) {
		a, b := observationKey(before[i]), observationKey(after[j])
		switch {
		case a == b:
			i++
			j++
		case a < b:
			removed = append(removed, before[i])
			i++
		default:
			added = append(added, after[j])
			j++
		}
	}

	return append(added, after[j:]...), append(removed, before[i:]...)
}

func verifyComparisonArtifact(ctx context.Context, root string, artifact, replay artifact, after replayEvidence, currentSources bool) error {
	var supplied Comparison
	if err := readArtifactJSON(ctx, root, artifact, &supplied); err != nil {
		return err
	}

	if supplied.Schema != comparisonSchema || supplied.After != replay {
		return errors.New("comparison does not bind the current replay")
	}

	before, err := readReplay(ctx, root, supplied.Before, "")
	if err != nil {
		return err
	}

	if before.contentSHA256 != supplied.Before.UncompressedSHA256 {
		return errors.New("comparison baseline decoded digest changed")
	}

	actual, err := compareEvidence(before, after)
	if err != nil {
		return err
	}

	actual.Before, actual.After = supplied.Before, supplied.After

	return verifyChanges(root, actual, supplied, currentSources)
}

func verifyChanges(root string, actual, supplied Comparison, currentSources bool) error {
	if len(actual.Changes) != len(supplied.Changes) {
		return errors.New("comparison changed-row inventory differs")
	}

	for i := range supplied.Changes {
		if err := verifyAdjudication(root, supplied.Changes[i], currentSources); err != nil {
			return err
		}

		actual.Changes[i].Adjudication = supplied.Changes[i].Adjudication
	}

	if !reflect.DeepEqual(actual, supplied) {
		return errors.New("comparison observations or accounting changed")
	}

	return nil
}

func verifyAdjudication(root string, change change, currentSources bool) error {
	if change.Adjudication == nil || strings.TrimSpace(change.Adjudication.Reason) == "" {
		return fmt.Errorf("unadjudicated observation change: %s", change.ID)
	}

	path, name, found := strings.Cut(change.Adjudication.Test, ":")
	if !found || !fs.ValidPath(path) || strings.ContainsAny(path, `\:`) || !strings.HasSuffix(path, "_test.go") || !(strings.HasPrefix(name, "Test") && len(name) > 4 && textmatch.Identifier(name, len(name))) {
		return errors.New("adjudication requires repo-relative _test.go:TestName")
	}

	if !currentSources {
		return nil
	}

	data, err := readJSONSource(root, path)
	if err != nil {
		return err
	}

	if !regexp.MustCompile(`func\s+` + regexp.QuoteMeta(name) + `\s*\(`).Match(data) {
		return errors.New("adjudication regression test does not exist")
	}

	return nil
}
func readJSONSource(root, path string) ([]byte, error) { return readJSONFile(root, path) }
