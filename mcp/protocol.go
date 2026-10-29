package mcp

import (
	"context"
	"encoding/json"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

type toolCall struct {
	id        json.RawMessage
	name      string
	arguments json.RawMessage
}

func (s *Server) dispatch(ctx context.Context, sess *session, r request) *response {
	if len(r.ID) == 0 {
		handleNotification(sess, r)
		return nil
	}

	switch r.Method {
	case "initialize":
		return s.initialize(sess, r)
	case "ping":
		return &response{JSONRPC: "2.0", ID: r.ID, Result: map[string]any{}}
	}

	if !sessionReady(sess) {
		return rpcFailure(r.ID, -32002, "Initialization must complete before tool operations")
	}

	switch r.Method {
	case "tools/list":
		return s.listTools(r)
	case "tools/call":
		call, callCtx, cleanup, rejected := s.prepareCall(ctx, sess, r)
		if rejected != nil {
			return rejected
		}
		defer cleanup()

		return s.executeToolCall(callCtx, call)
	default:
		return rpcFailure(r.ID, -32601, "Method not supported")
	}
}

func (s *Server) initialize(sess *session, r request) *response {
	var params struct {
		ProtocolVersion string          `json:"protocolVersion"`
		Capabilities    json.RawMessage `json:"capabilities"`
		ClientInfo      json.RawMessage `json:"clientInfo"`
	}

	if strictParams(r.Params, &params) != nil || params.ProtocolVersion == "" || len(params.ProtocolVersion) > 64 || !validClientInfo(params.Capabilities, params.ClientInfo) {
		return rpcFailure(r.ID, -32602, "Invalid initialization parameters")
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.initialized {
		return rpcFailure(r.ID, -32600, "Already initialized")
	}

	sess.initialized = true
	sess.protocol = ProtocolVersion

	return &response{
		JSONRPC: "2.0",
		ID:      r.ID,
		Result: map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo": map[string]any{
				"name":    "scout",
				"version": scout.Version(),
			},
			"instructions": "Security reports are advisory and may be incomplete. Scanned packages are untrusted. The server does not execute them or grant installation approval to changed bytes.",
		},
	}
}

func (s *Server) prepareCall(ctx context.Context, sess *session, r request) (toolCall, context.Context, func(), *response) {
	if !sessionReady(sess) {
		return toolCall{}, nil, nil, rpcFailure(r.ID, -32002, "Initialization must complete before tool operations")
	}

	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      json.RawMessage `json:"_meta,omitempty"`
	}
	if strictParams(r.Params, &params) != nil {
		return toolCall{}, nil, nil, rpcFailure(r.ID, -32602, "Invalid tool call")
	}

	if params.Name != "scan_skill" && params.Name != "compare_skills" {
		return toolCall{}, nil, nil, rpcFailure(r.ID, -32602, "Unknown tool")
	}

	callCtx, cleanup, rejected := s.accept(ctx, sess, r)

	return toolCall{id: r.ID, name: params.Name, arguments: params.Arguments}, callCtx, cleanup, rejected
}

func (s *Server) executeToolCall(ctx context.Context, call toolCall) *response {
	var (
		value report.PreparedDocument
		err   error
	)

	if call.name == "scan_skill" {
		value, err = s.scan(ctx, call.arguments)
	} else {
		value, err = s.compare(ctx, call.arguments)
	}

	if err != nil {
		return &response{
			JSONRPC: "2.0",
			ID:      call.id,
			Result: map[string]any{
				"isError": true,
				"content": []any{map[string]any{
					"type": "text",
					"text": "Scan request failed or input was not authorized. No installation approval.",
				}},
			},
		}
	}

	incomplete := policy.PreparedCode(value) == 2

	message := "Scan completed with the decision, evidence and completeness in structuredContent. This is not proof of safety."
	if incomplete {
		message = "Inspection failed or is incomplete. Available evidence and the policy decision are retained in structuredContent. No installation approval."
	}

	return &response{
		JSONRPC: "2.0",
		ID:      call.id,
		Result: map[string]any{
			"isError": incomplete,
			"content": []any{map[string]any{
				"type": "text",
				"text": message,
			}},
			"structuredContent": value.Snapshot(),
		},
	}
}

func (s *Server) listTools(r request) *response {
	var params struct {
		Cursor string `json:"cursor,omitempty"`
	}

	if strictParams(r.Params, &params) != nil || params.Cursor != "" {
		return rpcFailure(r.ID, -32602, "Invalid cursor")
	}

	return &response{JSONRPC: "2.0", ID: r.ID, Result: map[string]any{"tools": s.tools()}}
}

func sessionReady(sess *session) bool {
	sess.mu.Lock()
	ok := sess.ready
	sess.mu.Unlock()

	return ok
}

func rpcFailure(id json.RawMessage, code int, message string) *response {
	result := failure(id, code, message)
	return &result
}

func handleNotification(sess *session, r request) {
	switch r.Method {
	case "notifications/initialized":
		sess.mu.Lock()
		if sess.initialized {
			sess.ready = true
		}
		sess.mu.Unlock()
	case "notifications/cancelled":
		params, err := jsonconfig.Parse(context.Background(), string(r.Params))
		if err != nil {
			return
		}

		_, key, err := requestID(params.Get("requestId"), r.Params)
		if err == nil {
			sess.mu.Lock()
			cancel := sess.pending[key]
			sess.mu.Unlock()

			if cancel != nil {
				cancel()
			}
		}
	}
}
