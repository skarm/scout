package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"math/big"
	"mime"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/netpolicy"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

const (
	fieldArguments       = "arguments"
	fieldCandidate       = "candidate"
	fieldCapabilities    = "capabilities"
	fieldClientInfo      = "clientInfo"
	fieldCursor          = "cursor"
	fieldID              = "id"
	fieldInstructions    = "instructions"
	fieldJSONRPC         = "jsonrpc"
	fieldListChanged     = "listChanged"
	fieldMeta            = "_meta"
	fieldMethod          = "method"
	fieldName            = "name"
	fieldParams          = "params"
	fieldPrevious        = "previous"
	fieldProtocolVersion = "protocolVersion"
	fieldRequestID       = "requestId"
	fieldServerInfo      = "serverInfo"
	fieldTools           = "tools"
	fieldVersion         = "version"
)

const (
	maxMethodBytes        = 128
	maxNumericIDBytes     = 128
	maxStringIDBytes      = 96
	maxClientNameBytes    = 256
	maxClientVersionBytes = 128
	maxAcceptHeaderBytes  = 4096
)

var (
	errInvalidJSON    = errors.New("invalid JSON")
	errInvalidRequest = errors.New("invalid JSON-RPC request")
	errInvalidParams  = errors.New("invalid JSON-RPC parameters")
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	key     requestKey
}

type (
	requestKey struct{ kind, value string }
	rpcError   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
)

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func failure(id json.RawMessage, code int, msg string) response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}

	return response{JSONRPC: jsonRPCVersion, ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func parseRequest(data []byte) (request, error) {
	var r request

	n, err := jsonconfig.Parse(context.Background(), string(data))
	if err != nil {
		if !utf8.Valid(data) || !json.Valid(data) {
			return r, errInvalidJSON
		}

		return r, errInvalidRequest
	}

	if !requestObject(n) {
		return r, errInvalidRequest
	}

	r.JSONRPC, _ = n.Get(fieldJSONRPC).Text()

	r.Method, _ = n.Get(fieldMethod).Text()
	if r.JSONRPC != jsonRPCVersion || r.Method == "" || len(r.Method) > maxMethodBytes {
		return r, errInvalidRequest
	}

	r.ID, r.key, err = requestID(n.Get(fieldID), data)
	if err != nil {
		return r, err
	}

	r.Params, err = requestParams(n.Get(fieldParams), data)

	return r, err
}

func requestObject(n *jsonconfig.Node) bool {
	if n.Kind != jsonconfig.KindObject {
		return false
	}

	for _, field := range n.Members {
		switch field.Key {
		case fieldJSONRPC, fieldID, fieldMethod, fieldParams:
		default:
			return false
		}
	}

	return true
}

// The exact tree owns field spelling, types and source spans. No second JSON
// interpretation may select a different ID or params object.
func requestID(n *jsonconfig.Node, data []byte) (json.RawMessage, requestKey, error) {
	if n == nil {
		return nil, requestKey{}, nil
	}

	if n.Span.End-n.Span.Start > maxNumericIDBytes {
		return nil, requestKey{}, errors.New("invalid request ID")
	}

	key := requestKey{kind: n.Kind, value: n.String}
	switch n.Kind {
	case jsonconfig.KindString:
		if len(n.String) > maxStringIDBytes {
			return nil, requestKey{}, errors.New("invalid request ID")
		}
	case jsonconfig.KindNumber:
		number, ok := integerID(n.String)
		if !ok {
			return nil, requestKey{}, errors.New("invalid request ID")
		}

		key.value = strconv.FormatInt(number, 10)
	default:
		return nil, requestKey{}, errors.New("invalid request ID")
	}

	return bytes.Clone(data[n.Span.Start:n.Span.End]), key, nil
}

const (
	maxIDExponent = 256
)

// JSON integers are values, not a restriction on decimal/exponent spelling.
// Bound the exponent before big.Rat allocation and keep the existing int64 range.
func integerID(raw string) (int64, bool) {
	if value, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return value, true
	}

	mantissa, exponent, hasExponent := strings.Cut(strings.ToLower(raw), "e")
	if hasExponent {
		e, err := strconv.Atoi(exponent)
		if err != nil || e < -maxIDExponent || e > maxIDExponent {
			return 0, strings.Trim(mantissa, "-+.0") == ""
		}
	}

	value, ok := new(big.Rat).SetString(raw)
	if !ok || !value.IsInt() || !value.Num().IsInt64() {
		return 0, false
	}

	return value.Num().Int64(), true
}

func requestParams(n *jsonconfig.Node, data []byte) (json.RawMessage, error) {
	if n == nil {
		return nil, nil
	}

	if n.Kind != jsonconfig.KindObject {
		return nil, errInvalidParams
	}

	if meta := n.Get(fieldMeta); meta != nil && meta.Kind != jsonconfig.KindObject {
		return nil, errInvalidParams
	}

	return bytes.Clone(data[n.Span.Start:n.Span.End]), nil
}

func strictParams(raw []byte, v any, names ...string) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	// encoding/json also matches struct fields without regard to case. RPC
	// parameter names must instead match exactly (JSON-RPC 2.0 section 4.2).
	n, err := jsonconfig.Parse(context.Background(), string(raw))
	if err != nil || n.Kind != jsonconfig.KindObject {
		return errInvalidParams
	}

	for _, field := range n.Members {
		if !slices.Contains(names, field.Key) {
			return errInvalidParams
		}
	}

	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()

	return d.Decode(v)
}

func requestFailure(r request, err error) *response {
	if errors.Is(err, errInvalidJSON) {
		return rpcFailure(nil, rpcParseError, "Invalid JSON")
	}

	if errors.Is(err, errInvalidParams) {
		if len(r.ID) == 0 {
			return nil // A notification never has a JSON-RPC response.
		}

		return rpcFailure(r.ID, rpcInvalidParams, "Invalid parameters")
	}

	return rpcFailure(nil, rpcInvalidRequest, "Invalid JSON-RPC request")
}

func encodeResponse(r *response) []byte {
	data, err := marshalResponse(r)
	if err != nil || len(data) > MaxResponseBytes {
		x := failure(r.ID, rpcServerError, "Report exceeds transport limit; no approval inferred")
		data, _ = json.Marshal(x)
	}

	return append(data, '\n')
}

func marshalResponse(r *response) ([]byte, error) {
	result, ok := r.Result.(toolResult)
	if !ok || result.StructuredContent == nil {
		return json.Marshal(r)
	}

	document, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return nil, err
	}

	result.StructuredContent = json.RawMessage(document)
	wire := *r
	wire.Result = result

	base, err := json.Marshal(wire)
	if err != nil || len(base) > MaxResponseBytes {
		return base, err
	}

	summary, err := json.Marshal(result.Content[0].Text)
	if err != nil || len(document)+2 > MaxResponseBytes-len(base)+len(summary) {
		return base, err
	}

	result.Content[0].Text = string(document)
	wire.Result = result

	withFallback, err := json.Marshal(wire)
	if err != nil || len(withFallback) > MaxResponseBytes {
		return base, err
	}

	return withFallback, nil
}

func validClientInfo(capabilities, info []byte) bool {
	c, e := jsonconfig.Parse(context.Background(), string(capabilities))
	if e != nil || c.Kind != jsonconfig.KindObject {
		return false
	}

	i, e := jsonconfig.Parse(context.Background(), string(info))
	if e != nil || i.Kind != jsonconfig.KindObject {
		return false
	}

	name, ok := i.Get(fieldName).Text()
	version, vok := i.Get(fieldVersion).Text()

	return ok && vok && name != "" && len(name) <= maxClientNameBytes && len(version) <= maxClientVersionBytes
}

// Parse exact media types; a substring such as application/json-bogus is not JSON.
func acceptsJSON(h string) bool {
	if len(h) > maxAcceptHeaderBytes {
		return false
	}

	for entry := range httpFieldList(h) {
		media, params, err := mime.ParseMediaType(strings.TrimSpace(entry))
		if err != nil || media != netpolicy.JSONMediaType {
			continue
		}

		if q, ok := params["q"]; ok && !positiveHTTPQuality(q) {
			continue
		}

		return true
	}

	return false
}

// HTTP list separators inside quoted strings belong to the parameter value.
func httpFieldList(field string) iter.Seq[string] {
	return func(yield func(string) bool) {
		start := 0
		quoted, escaped := false, false

		for i := range len(field) {
			switch {
			case escaped:
				escaped = false
			case quoted && field[i] == '\\':
				escaped = true
			case field[i] == '"':
				quoted = !quoted
			case !quoted && field[i] == ',':
				if !yield(field[start:i]) {
					return
				}

				start = i + 1
			}
		}

		yield(field[start:])
	}
}

// RFC 9110 section 12.4.2 gives weights at most three decimal digits.
func positiveHTTPQuality(q string) bool {
	whole, digits, _ := strings.Cut(q, ".")
	if len(digits) > 3 {
		return false
	}

	switch whole {
	case "1":
		return strings.Trim(digits, "0") == ""
	case "0":
		return strings.Trim(digits, "0123456789") == "" && strings.Trim(digits, "0") != ""
	default:
		return false
	}
}
