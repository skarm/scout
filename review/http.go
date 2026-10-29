package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/scout/internal/netpolicy"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/knowledge"
)

// HTTPOptions selects one operator-approved Chat Completions compatible endpoint.
// No provider discovery, redirects, ambient proxy, CLI authentication or fallback.
// HTTP is allowed only to literal loopback addresses with explicit AllowLoopback.
// Even a local service may forward data elsewhere; vet the service separately.
type HTTPOptions struct {
	// Endpoint is the operator-selected Chat Completions endpoint.
	Endpoint string
	// Model is the requested model name sent in the HTTP envelope.
	Model string
	// APIKey is the optional bearer credential sent to Endpoint.
	APIKey string
	// AllowLoopback permits loopback destinations and plain HTTP to numeric
	// loopback addresses.
	AllowLoopback bool
	// Timeout bounds each HTTP request and its connection establishment.
	Timeout time.Duration
	// MaxOutputTokens sets the provider request's maximum output token count.
	MaxOutputTokens int
	// MaxResponseBytes bounds accepted response bytes.
	MaxResponseBytes int
	RootCAs          *x509.CertPool // optional explicitly trusted CA pool, cloned by constructor
}

// HTTPProvider implements the tool-free Chat Completions transport configured
// by NewHTTP.
type HTTPProvider struct {
	endpoint string
	key      string
	model    string
	client   *http.Client
	tokens   int
	maxBytes int
	identity Identity
}

// TransportError carries a bounded transport code and optional HTTP status
// without raw response text.
type TransportError struct {
	// Code is a stable machine-readable condition identifier.
	Code string
	// Status is the HTTP response status when Code is http_status; otherwise it is zero.
	Status int
}

type chatEnvelope struct {
	Model       string          `json:"model"`
	Fingerprint string          `json:"system_fingerprint"`
	Error       json.RawMessage `json:"error"`
	Choices     []chatChoice    `json:"choices"`
	Usage       *struct {
		Input  *int64 `json:"prompt_tokens"`
		Output *int64 `json:"completion_tokens"`
	} `json:"usage"`
}

type chatChoice struct {
	Index   int    `json:"index"`
	Finish  string `json:"finish_reason"`
	Message struct {
		Role     string          `json:"role"`
		Content  *string         `json:"content"`
		Refusal  *string         `json:"refusal"`
		Tools    json.RawMessage `json:"tool_calls"`
		Function json.RawMessage `json:"function_call"`
	} `json:"message"`
}

// NewHTTP validates an explicit endpoint and creates a bounded Chat
// Completions transport without sending a request.
func NewHTTP(o HTTPOptions) (*HTTPProvider, error) {
	u, err := validateHTTPOptions(o)
	if err != nil {
		return nil, err
	}

	return newHTTPProvider(o, u)
}

// ErrorCode intentionally never returns arbitrary provider or network error text.
func ErrorCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}

	if e, ok := errors.AsType[*TransportError](err); ok {
		switch e.Code {
		case "http_status":
			if e.Status >= 100 && e.Status <= 599 {
				return "http_status_" + strconv.Itoa(e.Status)
			}
		case "redirect_refused", "http_failed", "dns_failed", "connection_failed", "address_not_permitted", "content_type", "content_encoding", "response_limit", "response_read_failed", "invalid_envelope", "ambiguous_envelope", "provider_error", "unexpected_choices", "incomplete_response", "refused", "tool_call_refused", "metadata_limit", "invalid_usage":
			return "transport_" + e.Code
		}
	}

	return "provider_failed"
}

// Identity returns the requested configuration identity without credentials or
// the raw endpoint.
func (p *HTTPProvider) Identity() Identity { return p.identity }

// Complete sends one bounded review request under ctx and returns a tool-free
// completion. It rejects incomplete or ambiguous envelopes.
func (p *HTTPProvider) Complete(ctx context.Context, payload []byte) (Completion, error) {
	if ctx == nil {
		return Completion{}, transportError("nil_context")
	}

	if err := ctx.Err(); err != nil {
		return Completion{}, err
	}

	if len(payload) > MaxRequestBytes || !json.Valid(payload) {
		return Completion{}, transportError("invalid_request")
	}

	system, err := PromptForRequest(ctx, payload)
	if err != nil {
		return Completion{}, err
	}

	body, err := json.Marshal(map[string]any{
		"model":                 p.model,
		"store":                 false,
		"stream":                false,
		"n":                     1,
		"tools":                 []any{},
		"tool_choice":           "none",
		"max_completion_tokens": p.tokens,
		"messages": []map[string]string{{"role": "system", "content": system}, {
			"role":    "user",
			"content": string(payload),
		}},
		"response_format": map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "scout_review_v4",
				"strict": true,
				"schema": ResponseSchema(),
			},
		},
	})
	if err != nil {
		return Completion{}, transportError("request_encoding_failed")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return Completion{}, transportError("request_failed")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if p.key != "" {
		req.Header.Set("Authorization", "Bearer "+p.key)
	}

	return p.completeChatRequest(ctx, req)
}

func (p *HTTPProvider) completeChatRequest(ctx context.Context, req *http.Request) (Completion, error) {
	raw, err := p.readResponse(ctx, req)
	if err != nil {
		return Completion{}, err
	}

	return decodeChatCompletion(ctx, raw)
}

// ValidateMetadata applies the shared passive provider metadata contract.
// Output byte limits are selected separately by each caller.
func (c Completion) ValidateMetadata() error {
	if len(c.Model) > 256 || len(c.Fingerprint) > 256 {
		return transportError("metadata_limit")
	}

	if c.InputTokens < -1 || c.OutputTokens < -1 || c.InputTokens > 1<<40 || c.OutputTokens > 1<<40 {
		return transportError("invalid_usage")
	}

	return nil
}

func setCompletionUsage(c *Completion, input, output *int64) {
	if input != nil {
		c.InputTokens = *input
	}

	if output != nil {
		c.OutputTokens = *output
	}
}

// Error returns a stable transport error code and optional status without
// provider response text.
func (e *TransportError) Error() string { return "semantic transport: " + e.Code }

func (e chatEnvelope) completion() (Completion, error) {
	if len(e.Error) > 0 && string(e.Error) != "null" {
		return Completion{}, transportError("provider_error")
	}

	if len(e.Choices) != 1 || e.Choices[0].Index != 0 {
		return Completion{}, transportError("unexpected_choices")
	}

	choice := e.Choices[0]
	if err := choice.validate(); err != nil {
		return Completion{}, err
	}

	c := Completion{
		Output:       []byte(*choice.Message.Content),
		Model:        e.Model,
		Fingerprint:  e.Fingerprint,
		InputTokens:  -1,
		OutputTokens: -1,
	}

	if e.Usage != nil {
		setCompletionUsage(&c, e.Usage.Input, e.Usage.Output)
	}

	return c, c.ValidateMetadata()
}

func (c chatChoice) validate() error {
	if c.Finish != "stop" || c.Message.Role != "assistant" || c.Message.Content == nil {
		return transportError("incomplete_response")
	}

	if c.Message.Refusal != nil && *c.Message.Refusal != "" {
		return transportError("refused")
	}

	for _, v := range []json.RawMessage{c.Message.Tools, c.Message.Function} {
		if !slices.Contains([]string{"", "null", "[]"}, string(v)) {
			return transportError("tool_call_refused")
		}
	}

	return nil
}

func validateHTTPOptions(o HTTPOptions) (*url.URL, error) {
	if err := validateRanges([]optionRange{
		{value: int64(o.Timeout), min: 1, max: int64(2 * time.Minute), message: "invalid_timeout"},
		{value: int64(o.MaxOutputTokens), min: 128, max: 8192, message: "invalid_output_token_budget"},
		{value: int64(o.MaxResponseBytes), min: 1024, max: jsonconfig.MaxBytes, message: "invalid_response_budget"},
	}); err != nil {
		return nil, transportError(err.Error())
	}

	if len(o.Endpoint) > 2048 || !credentialBytes(o.APIKey, 0) {
		return nil, transportError("invalid_endpoint_or_authentication")
	}

	u, err := netpolicy.ParseURL(o.Endpoint, netpolicy.URLPolicy{
		MaxBytes:      2048,
		AllowLoopback: o.AllowLoopback,
		RequirePath:   true,
	})

	if e, ok := errors.AsType[*netpolicy.Error](err); ok {
		if e.Code == "invalid_url" || e.Code == "invalid_port" {
			return nil, transportError("invalid_endpoint")
		}

		return nil, transportError(e.Code)
	}

	return u, err
}

func newHTTPProvider(o HTTPOptions, u *url.URL) (*HTTPProvider, error) {
	settings, _ := json.Marshal(struct {
		Model, Endpoint, Prompt, Schema string
		Tokens, Bytes                   int
		Loopback                        bool
		Timeout                         time.Duration
	}{
		Model:    o.Model,
		Endpoint: u.String(),
		Prompt:   knowledge.Inventory().SHA256,
		Schema:   hashBytes([]byte(responseSchema)),
		Tokens:   o.MaxOutputTokens,
		Bytes:    o.MaxResponseBytes,
		Loopback: o.AllowLoopback,
		Timeout:  o.Timeout,
	})

	identity := Identity{
		Provider:       "chat-completions-json",
		Model:          o.Model,
		EndpointSHA256: hashBytes([]byte(u.String())),
		SettingsSHA256: hashBytes(settings),
	}
	if err := identity.Validate(); err != nil {
		return nil, err
	}

	tr := netpolicy.Transport(o.Timeout, o.AllowLoopback, o.RootCAs)
	client := &http.Client{
		Timeout:       o.Timeout,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return transportError("redirect_refused") },
	}

	return &HTTPProvider{
		endpoint: u.String(),
		key:      o.APIKey,
		model:    o.Model,
		client:   client,
		tokens:   o.MaxOutputTokens,
		maxBytes: o.MaxResponseBytes,
		identity: identity,
	}, nil
}

func decodeChatCompletion(ctx context.Context, raw []byte) (Completion, error) {
	// Reject duplicate/ambiguous JSON and malformed Unicode in the HTTP envelope.
	root, parseErr := jsonconfig.Parse(ctx, string(raw))
	if parseErr != nil {
		return Completion{}, transportError("invalid_envelope")
	}
	// encoding/json accepts case-insensitive field aliases. Disallow ambiguous
	// protocol fields even when their spellings differ only by case.
	if chatEnvelopeAliases(root) {
		return Completion{}, transportError("ambiguous_envelope")
	}

	var envelope chatEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Completion{}, transportError("invalid_envelope")
	}

	c, err := envelope.completion()
	if err != nil {
		return Completion{}, err
	}

	if err := ctx.Err(); err != nil {
		return Completion{}, err
	}

	return c, nil
}

func chatEnvelopeAliases(root *jsonconfig.Node) bool {
	if aliases(root, "model", "system_fingerprint", "error", "choices", "usage") {
		return true
	}

	if choices := root.Get("choices"); choices != nil {
		for _, choice := range choices.Elements {
			if aliases(choice, "index", "finish_reason", "message") || aliases(choice.Get("message"), "role", "content", "refusal", "tool_calls", "function_call") {
				return true
			}
		}
	}

	return aliases(root.Get("usage"), "prompt_tokens", "completion_tokens")
}

func transportError(code string) error { return &TransportError{Code: code} }
func hashBytes(b []byte) string        { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func aliases(n *jsonconfig.Node, keys ...string) bool {
	if n == nil {
		return false
	}

	for _, m := range n.Members {
		for _, k := range keys {
			if m.Key != k && strings.EqualFold(m.Key, k) {
				return true
			}
		}
	}

	return false
}
