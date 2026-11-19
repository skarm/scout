package mcp

import (
	"context"
	"encoding/json"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

const (
	maxProtocolVersionBytes = 64
)

type toolCall struct {
	id        json.RawMessage
	name      string
	arguments json.RawMessage
}

const (
	jsonRPCVersion    = "2.0"
	methodInitialize  = "initialize"
	methodCallTool    = "tools/call"
	toolScanSkill     = "scan_skill"
	toolCompareSkills = "compare_skills"
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcServerError    = -32000
	rpcNotInitialized = -32002
)

const (
	methodPing      = "ping"
	methodListTools = "tools/list"
)

type toolResult struct {
	IsError           bool        `json:"isError"`
	Content           [1]toolText `json:"content"`
	StructuredContent any         `json:"structuredContent,omitempty"`
}

type toolText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (s *Server) dispatch(ctx context.Context, sess *session, r request) *response {
	if len(r.ID) == 0 {
		handleNotification(sess, r)
		return nil
	}

	switch r.Method {
	case methodInitialize:
		return s.initialize(sess, r)
	case methodPing:
		return &response{JSONRPC: jsonRPCVersion, ID: r.ID, Result: map[string]any{}}
	}

	if !sessionReady(sess) {
		return rpcFailure(r.ID, rpcNotInitialized, "Initialization must complete before tool operations")
	}

	switch r.Method {
	case methodListTools:
		return s.listTools(r)
	case methodCallTool:
		call, callCtx, cleanup, rejected := s.prepareCall(ctx, sess, r)
		if rejected != nil {
			return rejected
		}
		defer cleanup()

		return s.executeToolCall(callCtx, call)
	default:
		return rpcFailure(r.ID, rpcMethodNotFound, "Method not supported")
	}
}

func (s *Server) initialize(sess *session, r request) *response {
	var params struct {
		ProtocolVersion string          `json:"protocolVersion"`
		Capabilities    json.RawMessage `json:"capabilities"`
		ClientInfo      json.RawMessage `json:"clientInfo"`
		Meta            json.RawMessage `json:"_meta,omitempty"`
	}

	if strictParams(r.Params, &params, "protocolVersion", "capabilities", "clientInfo", fieldMeta) != nil || params.ProtocolVersion == "" || len(params.ProtocolVersion) > maxProtocolVersionBytes || !validClientInfo(params.Capabilities, params.ClientInfo) {
		return rpcFailure(r.ID, rpcInvalidParams, "Invalid initialization parameters")
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.initialized || sess.closed {
		return rpcFailure(r.ID, rpcInvalidRequest, "Already initialized")
	}

	sess.initialized = true
	sess.protocol = ProtocolVersion

	return &response{
		JSONRPC: jsonRPCVersion,
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
		return toolCall{}, nil, nil, rpcFailure(r.ID, rpcNotInitialized, "Initialization must complete before tool operations")
	}

	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      json.RawMessage `json:"_meta,omitempty"`
	}
	if strictParams(r.Params, &params, fieldName, "arguments", fieldMeta) != nil {
		return toolCall{}, nil, nil, rpcFailure(r.ID, rpcInvalidParams, "Invalid tool call")
	}

	if params.Name != toolScanSkill && params.Name != toolCompareSkills {
		return toolCall{}, nil, nil, rpcFailure(r.ID, rpcInvalidParams, "Unknown tool")
	}

	callCtx, cleanup, rejected := s.accept(ctx, sess, r)

	return toolCall{id: r.ID, name: params.Name, arguments: params.Arguments}, callCtx, cleanup, rejected
}

func (s *Server) executeToolCall(ctx context.Context, call toolCall) *response {
	var (
		value report.PreparedDocument
		err   error
	)

	if call.name == toolScanSkill {
		value, err = s.scan(ctx, call.arguments)
	} else {
		value, err = s.compare(ctx, call.arguments)
	}

	if err != nil {
		return &response{
			JSONRPC: jsonRPCVersion,
			ID:      call.id,
			Result: toolResult{
				IsError: true,
				Content: [1]toolText{{Type: "text", Text: "Scan request failed or input was not authorized. No installation approval."}},
			},
		}
	}

	incomplete := policy.PreparedCode(value) == 2

	message := "Scan completed with the decision, evidence and completeness in structuredContent. This is not proof of safety."
	if incomplete {
		message = "Inspection failed or is incomplete. Available evidence and the policy decision are retained in structuredContent. No installation approval."
	}

	return &response{
		JSONRPC: jsonRPCVersion,
		ID:      call.id,
		Result: toolResult{
			IsError:           incomplete,
			Content:           [1]toolText{{Type: "text", Text: message}},
			StructuredContent: value.Snapshot(),
		},
	}
}

func (s *Server) listTools(r request) *response {
	var params struct {
		Cursor string          `json:"cursor,omitempty"`
		Meta   json.RawMessage `json:"_meta,omitempty"`
	}

	if strictParams(r.Params, &params, "cursor", fieldMeta) != nil || params.Cursor != "" {
		return rpcFailure(r.ID, rpcInvalidParams, "Invalid cursor")
	}

	return &response{JSONRPC: jsonRPCVersion, ID: r.ID, Result: map[string]any{"tools": s.tools()}}
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
		if sess.initialized && !sess.closed {
			sess.ready = true
		}
		sess.mu.Unlock()
	case "notifications/cancelled":
		params, err := jsonconfig.Parse(context.Background(), string(r.Params))
		if err != nil {
			return
		}

		_, key, err := requestID(params.Get(fieldRequestID), r.Params)
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
