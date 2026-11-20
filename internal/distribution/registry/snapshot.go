package registry

import (
	"encoding/json"
	"errors"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

// MaxSnapshotBytes bounds saved snapshots including the local envelope and
// page receipts, which are additional to the raw response byte budget.
const MaxSnapshotBytes = maxResponseBytes + (32 << 10)

// EncodeSnapshot preserves the JSON record bytes received from the registry.
// Re-escaping a record can grow it beyond the comparison parser's limit.
func EncodeSnapshot(s Snapshot) ([]byte, error) {
	header, err := json.Marshal(struct {
		Schema         string `json:"schema"`
		EndpointSHA256 string `json:"endpoint_sha256"`
		Complete       bool   `json:"complete"`
		Pages          []page `json:"pages"`
	}{s.Schema, s.EndpointSHA256, s.Complete, s.Pages})
	if err != nil {
		return nil, err
	}

	size := len(header) - 1 + len(`,"servers":[]}`) + 1 + max(0, len(s.Servers)-1)

	for _, raw := range s.Servers {
		if len(raw) > jsonconfig.MaxBytes || !json.Valid(raw) {
			return nil, errors.New("invalid registry snapshot record")
		}

		size += len(raw)
		if size > MaxSnapshotBytes {
			return nil, errors.New("registry snapshot exceeds saved byte limit")
		}
	}

	out := make([]byte, 0, size)
	out = append(out, header[:len(header)-1]...)
	out = append(out, `,"servers":[`...)

	for i, raw := range s.Servers {
		if i != 0 {
			out = append(out, ',')
		}

		out = append(out, raw...)
	}

	return append(out, ']', '}', '\n'), nil
}
