package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

// MaxSnapshotBytes bounds saved snapshots including the local envelope and
// page receipts, which are additional to the raw response byte budget.
const MaxSnapshotBytes = maxResponseBytes + snapshotEnvelopeAllowance

const snapshotEnvelopeAllowance = 32 << 10

// DecodeSnapshot reads the saved envelope using exact field names. The server
// records retain their original bytes for the comparison parser.
func DecodeSnapshot(data []byte) (Snapshot, error) {
	var out Snapshot
	if len(data) > MaxSnapshotBytes {
		return out, errors.New("registry snapshot exceeds saved byte limit")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if start, err := decoder.Token(); err != nil || start != json.Delim('{') {
		return out, errors.New("invalid registry snapshot envelope")
	}

	fields := map[string]any{
		"schema": &out.Schema, "endpoint_sha256": &out.EndpointSHA256,
		"complete": &out.Complete, "pages": &out.Pages, "servers": &out.Servers,
	}

	for decoder.More() {
		key, err := decoder.Token()

		name, ok := key.(string)
		if err != nil || !ok || fields[name] == nil {
			return Snapshot{}, errors.New("unknown or repeated registry snapshot field")
		}

		if err := decoder.Decode(fields[name]); err != nil {
			return Snapshot{}, err
		}

		delete(fields, name)
	}

	if _, err := decoder.Token(); err != nil || out.Servers == nil {
		return Snapshot{}, errors.New("registry snapshot requires a servers array")
	}

	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Snapshot{}, errors.New("trailing registry snapshot data")
	}

	return out, nil
}

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
