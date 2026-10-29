package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
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

	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func parseRequest(data []byte) (request, error) {
	var r request

	n, err := jsonconfig.Parse(context.Background(), string(data))
	if err != nil {
		return r, errors.New("invalid JSON-RPC message")
	}

	if !requestObject(n) {
		return r, errors.New("invalid JSON-RPC request")
	}

	r.JSONRPC, _ = n.Get("jsonrpc").Text()

	r.Method, _ = n.Get("method").Text()
	if r.JSONRPC != "2.0" || r.Method == "" || len(r.Method) > 128 {
		return r, errors.New("invalid JSON-RPC request")
	}

	r.ID, r.key, err = requestID(n.Get("id"), data)
	if err != nil {
		return r, err
	}

	r.Params, err = requestParams(n.Get("params"), data)

	return r, err
}

func requestObject(n *jsonconfig.Node) bool {
	if n.Kind != jsonconfig.KindObject {
		return false
	}

	for _, field := range n.Members {
		switch field.Key {
		case "jsonrpc", "id", "method", "params":
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

	if n.Span.End-n.Span.Start > 128 {
		return nil, requestKey{}, errors.New("invalid request ID")
	}

	key := requestKey{kind: n.Kind, value: n.String}
	switch n.Kind {
	case jsonconfig.KindString:
		if len(n.String) > 96 {
			return nil, requestKey{}, errors.New("invalid request ID")
		}
	case jsonconfig.KindNumber:
		number, err := strconv.ParseInt(n.String, 10, 64)
		if err != nil {
			return nil, requestKey{}, errors.New("invalid request ID")
		}

		key.value = strconv.FormatInt(number, 10)
	default:
		return nil, requestKey{}, errors.New("invalid request ID")
	}

	return bytes.Clone(data[n.Span.Start:n.Span.End]), key, nil
}

func requestParams(n *jsonconfig.Node, data []byte) (json.RawMessage, error) {
	if n == nil {
		return nil, nil
	}

	if n.Kind != jsonconfig.KindObject {
		return nil, errors.New("params must be an object")
	}

	return bytes.Clone(data[n.Span.Start:n.Span.End]), nil
}

func strictParams(raw []byte, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}

	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()

	return d.Decode(v)
}

func encodeResponse(r *response) []byte {
	data, err := json.Marshal(r)
	if err != nil || len(data) > MaxResponseBytes {
		x := failure(r.ID, -32000, "Report exceeds transport limit; no approval inferred")
		data, _ = json.Marshal(x)
	}

	return append(data, '\n')
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

	name, ok := i.Get("name").Text()
	version, vok := i.Get("version").Text()

	return ok && vok && name != "" && len(name) <= 256 && len(version) <= 128
}

// Parse exact media types; a substring such as application/json-bogus is not JSON.
func acceptsJSON(h string) bool {
	if len(h) > 4096 {
		return false
	}

	for entry := range strings.SplitSeq(h, ",") {
		media, params, err := mime.ParseMediaType(strings.TrimSpace(entry))
		if err != nil || media != "application/json" {
			continue
		}

		if q, ok := params["q"]; ok && (q == "0" || q == "0.0" || q == "0.00" || q == "0.000") {
			continue
		}

		return true
	}

	return false
}
