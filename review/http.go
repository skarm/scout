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

const (
	codeInvalidEndpoint                 = "invalid_endpoint"
	codeInvalidEndpointOrAuthentication = "invalid_endpoint_or_authentication"
)

const (
	roleSystem     = "system"
	chatFinishStop = "stop"
)

const (
	minProviderOutputTokens       = 128
	minProviderResponseBytes      = 1024
	maxCompletionModelBytes       = 256
	maxCompletionFingerprintBytes = 256
	unknownTokenCount             = -1
	maxReportedTokens             = 1 << 40
	maxProviderOutputTokens       = 8192
)

const chatResponseSchemaName = "scout_review_v4"

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

const (
	codeNilContext            = "nil_context"
	codeRequestEncodingFailed = "request_encoding_failed"
	codeRequestFailed         = "request_failed"
	codeAmbiguousEnvelope     = "ambiguous_envelope"
	codeContentEncoding       = "content_encoding"
	codeContentType           = "content_type"
	codeHTTPFailed            = "http_failed"
	codeHTTPStatus            = "http_status"
	codeIncompleteResponse    = "incomplete_response"
	codeInvalidEnvelope       = "invalid_envelope"
	codeInvalidRequest        = "invalid_request"
	codeInvalidUsage          = "invalid_usage"
	codeMetadataLimit         = "metadata_limit"
	codeProviderError         = "provider_error"
	codeRedirectRefused       = "redirect_refused"
	codeRefused               = "refused"
	codeResponseLimit         = "response_limit"
	codeResponseReadFailed    = "response_read_failed"
	codeToolCallRefused       = "tool_call_refused"
	codeUnexpectedChoices     = "unexpected_choices"
)

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
const maxHTTPStatusCode = 599

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
		case codeHTTPStatus:
			if e.Status >= http.StatusContinue && e.Status <= maxHTTPStatusCode {
				return "http_status_" + strconv.Itoa(e.Status)
			}
		case codeRedirectRefused, codeHTTPFailed, netpolicy.CodeDNSFailed, netpolicy.CodeConnectionFailed, netpolicy.CodeAddressNotPermitted, codeContentType, codeContentEncoding, codeResponseLimit, codeResponseReadFailed, codeInvalidEnvelope, codeAmbiguousEnvelope, codeProviderError, codeUnexpectedChoices, codeIncompleteResponse, codeRefused, codeToolCallRefused, codeMetadataLimit, codeInvalidUsage:
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
		return Completion{}, transportError(codeNilContext)
	}

	if err := ctx.Err(); err != nil {
		return Completion{}, err
	}

	if len(payload) > MaxRequestBytes || !json.Valid(payload) {
		return Completion{}, transportError(codeInvalidRequest)
	}

	system, err := PromptForRequest(ctx, payload)
	if err != nil {
		return Completion{}, err
	}

	body, err := json.Marshal(map[string]any{
		fieldModel:              p.model,
		"store":                 false,
		"stream":                false,
		"n":                     1,
		"tools":                 []any{},
		"tool_choice":           "none",
		"max_completion_tokens": p.tokens,
		fieldMessages: []map[string]string{{fieldRole: roleSystem, fieldContent: system}, {
			fieldRole:    roleUser,
			fieldContent: string(payload),
		}},
		"response_format": map[string]any{
			fieldType: "json_schema",
			"json_schema": map[string]any{
				"name":   chatResponseSchemaName,
				"strict": true,
				"schema": ResponseSchema(),
			},
		},
	})
	if err != nil {
		return Completion{}, transportError(codeRequestEncodingFailed)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return Completion{}, transportError(codeRequestFailed)
	}

	req.Header.Set(netpolicy.HeaderContentType, netpolicy.JSONMediaType)
	req.Header.Set(netpolicy.HeaderAccept, netpolicy.JSONMediaType)

	if p.key != "" {
		req.Header.Set(netpolicy.HeaderAuthorization, netpolicy.BearerScheme+" "+p.key)
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
	if len(c.Model) > maxCompletionModelBytes || len(c.Fingerprint) > maxCompletionFingerprintBytes {
		return transportError(codeMetadataLimit)
	}

	if c.InputTokens < unknownTokenCount || c.OutputTokens < unknownTokenCount || c.InputTokens > maxReportedTokens || c.OutputTokens > maxReportedTokens {
		return transportError(codeInvalidUsage)
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
		return Completion{}, transportError(codeProviderError)
	}

	if len(e.Choices) != 1 || e.Choices[0].Index != 0 {
		return Completion{}, transportError(codeUnexpectedChoices)
	}

	choice := e.Choices[0]
	if err := choice.validate(); err != nil {
		return Completion{}, err
	}

	c := Completion{
		Output:       []byte(*choice.Message.Content),
		Model:        e.Model,
		Fingerprint:  e.Fingerprint,
		InputTokens:  unknownTokenCount,
		OutputTokens: unknownTokenCount,
	}

	if e.Usage != nil {
		setCompletionUsage(&c, e.Usage.Input, e.Usage.Output)
	}

	return c, c.ValidateMetadata()
}

func (c chatChoice) validate() error {
	if c.Finish != chatFinishStop || c.Message.Role != roleAssistant || c.Message.Content == nil {
		return transportError(codeIncompleteResponse)
	}

	if c.Message.Refusal != nil && *c.Message.Refusal != "" {
		return transportError(codeRefused)
	}

	for _, v := range []json.RawMessage{c.Message.Tools, c.Message.Function} {
		if !slices.Contains([]string{"", "null", "[]"}, string(v)) {
			return transportError(codeToolCallRefused)
		}
	}

	return nil
}

func validateHTTPOptions(o HTTPOptions) (*url.URL, error) {
	if err := validateRanges([]optionRange{
		{value: int64(o.Timeout), min: 1, max: int64(MaxReviewTimeout), message: "invalid_timeout"},
		{value: int64(o.MaxOutputTokens), min: minProviderOutputTokens, max: maxProviderOutputTokens, message: "invalid_output_token_budget"},
		{value: int64(o.MaxResponseBytes), min: minProviderResponseBytes, max: jsonconfig.MaxBytes, message: "invalid_response_budget"},
	}); err != nil {
		return nil, transportError(err.Error())
	}

	if len(o.Endpoint) > maxProviderEndpointBytes || !credentialBytes(o.APIKey, 0) {
		return nil, transportError(codeInvalidEndpointOrAuthentication)
	}

	u, err := netpolicy.ParseURL(o.Endpoint, netpolicy.URLPolicy{
		MaxBytes:      maxProviderEndpointBytes,
		AllowLoopback: o.AllowLoopback,
		RequirePath:   true,
	})

	if e, ok := errors.AsType[*netpolicy.Error](err); ok {
		if e.Code == netpolicy.CodeInvalidURL || e.Code == netpolicy.CodeInvalidPort {
			return nil, transportError(codeInvalidEndpoint)
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
		CheckRedirect: func(*http.Request, []*http.Request) error { return transportError(codeRedirectRefused) },
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
		return Completion{}, reviewJSONError(parseErr, transportError(codeInvalidEnvelope))
	}
	// encoding/json accepts case-insensitive field aliases. Disallow ambiguous
	// protocol fields even when their spellings differ only by case.
	if chatEnvelopeAliases(root) {
		return Completion{}, transportError(codeAmbiguousEnvelope)
	}

	var envelope chatEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Completion{}, transportError(codeInvalidEnvelope)
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
	if aliases(root, fieldModel, fieldSystemFingerprint, fieldError, fieldChoices, fieldUsage) {
		return true
	}

	if choices := root.Get(fieldChoices); choices != nil {
		for _, choice := range choices.Elements {
			if aliases(choice, fieldIndex, fieldFinishReason, fieldMessage) || aliases(choice.Get(fieldMessage), fieldRole, fieldContent, fieldRefusal, fieldToolCalls, fieldFunctionCall) {
				return true
			}
		}
	}

	return aliases(root.Get(fieldUsage), fieldPromptTokens, fieldCompletionTokens)
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
