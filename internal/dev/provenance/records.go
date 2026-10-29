package provenance

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/dev/replaywire"
)

const (
	maxRecordBytes        = 64 << 20
	maxDecodedBytes int64 = 1 << 30
	maxRecords            = 65536
)

type Observation struct {
	RuleID string `json:"rule_id"`
	Path   string `json:"path"`
	Start  int    `json:"byte_start"`
	End    int    `json:"byte_end"`
}
type observedRow struct {
	error        bool
	observations []Observation
}
type replayEvidence struct {
	ids           []string
	rows          map[string]observedRow
	summary       summary
	errors        map[string]int
	contentSHA256 string
}
type replayRow = replaywire.Record

func walkJSONL(ctx context.Context, root string, artifact artifact, accept func([]byte) error) (string, error) {
	if err := verifyArtifact(ctx, root, artifact); err != nil {
		return "", err
	}

	file, err := openFile(root, artifact.Path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }() // The input file is read-only; read failures are handled separately.

	var reader io.Reader = contextReader{ctx: ctx, reader: file}
	if strings.HasSuffix(artifact.Path, ".gz") {
		compressed, err := gzip.NewReader(reader)
		if err != nil {
			return "", err
		}
		defer func() { _ = compressed.Close() }() // The gzip reader owns no writer or underlying file.

		reader = compressed
	}

	return scanEvidence(reader, accept)
}

func scanEvidence(reader io.Reader, accept func([]byte) error) (string, error) {
	limited := &io.LimitedReader{R: reader, N: maxDecodedBytes + 1}
	hash := sha256.New()
	lines := bufio.NewScanner(io.TeeReader(limited, hash))
	lines.Buffer(make([]byte, 64<<10), maxRecordBytes+1)

	count := 0
	for lines.Scan() {
		count++
		if count > maxRecords {
			return "", errors.New("evidence record count limit")
		}

		if err := accept(lines.Bytes()); err != nil {
			return "", fmt.Errorf("record %d: %w", count, err)
		}
	}

	if err := lines.Err(); err != nil {
		return "", err
	}

	if limited.N <= 0 {
		return "", errors.New("decoded evidence byte limit")
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readInputIDs(ctx context.Context, root string, input artifact) (replayEvidence, error) {
	evidence := replayEvidence{rows: map[string]observedRow{}}
	_, err := walkJSONL(ctx, root, input, func(data []byte) error {
		var row struct {
			ID    string          `json:"id"`
			Files json.RawMessage `json:"files"`
		}
		if err := decodeStrict(data, &row); err != nil {
			return err
		}

		if err := addID(&evidence, row.ID); err != nil {
			return err
		}

		if len(row.Files) == 0 {
			return errors.New("capture has no files field")
		}

		return nil
	})

	sort.Strings(evidence.ids)

	return evidence, err
}

func readReplay(ctx context.Context, root string, replay artifact, version string) (replayEvidence, error) {
	evidence := replayEvidence{rows: map[string]observedRow{}, errors: map[string]int{}}
	content, err := walkJSONL(ctx, root, replay, func(data []byte) error {
		var row replayRow
		if err := decodeStrict(data, &row); err != nil {
			return err
		}

		if err := row.Validate(version); err != nil {
			return err
		}

		if err := addID(&evidence, row.ID); err != nil {
			return err
		}

		observations := make([]Observation, len(row.Findings))
		for i, finding := range row.Findings {
			observations[i] = Observation{
				RuleID: finding.RuleID,
				Path:   finding.Location.Path,
				Start:  finding.Location.ByteStart,
				End:    finding.Location.ByteEnd,
			}
		}

		sortObservations(observations)
		evidence.rows[row.ID] = observedRow{error: row.Error != "", observations: observations}
		evidence.summary.Inputs++
		evidence.summary.AddOutcome(row)

		if row.Error != "" {
			evidence.errors[row.Error]++
		}

		return nil
	})
	evidence.contentSHA256 = content
	sort.Strings(evidence.ids)

	return evidence, err
}

func addID(evidence *replayEvidence, id string) error {
	if !hexDigest(id, 64) {
		return errors.New("invalid record ID")
	}

	if _, exists := evidence.rows[id]; exists {
		return errors.New("duplicate record ID")
	}

	evidence.ids = append(evidence.ids, id)
	evidence.rows[id] = observedRow{}

	return nil
}

func idsDigest(ids []string) string {
	data, _ := json.Marshal(ids)
	hash := sha256.Sum256(data)

	return hex.EncodeToString(hash[:])
}

func sortObservations(values []Observation) {
	sort.Slice(values, func(i, j int) bool { return observationKey(values[i]) < observationKey(values[j]) })
}

func observationKey(observation Observation) string {
	data, _ := json.Marshal(observation)
	return string(data)
}
