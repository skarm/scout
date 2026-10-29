package review

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/textmatch"
)

// MessagesOptions selects the native Anthropic Messages protocol or its explicit
// Vertex rawPredict/Bedrock InvokeModel forms. Credentials are caller-owned, not
// discovered from an SDK default chain, metadata service, home or artifact.
type MessagesOptions struct {
	HTTPOptions
	Transport string // anthropic, anthropic-proxy (Vertex), bedrock
	// Region is the AWS region used to sign Bedrock requests.
	Region string
	// AccessKeyID is the explicitly supplied AWS access key ID.
	AccessKeyID string
	// SecretAccessKey is the explicitly supplied AWS signing secret.
	SecretAccessKey string
	// SessionToken is the optional AWS session credential.
	SessionToken string
}

// MessagesProvider implements the explicitly selected Anthropic, Vertex or
// Bedrock Messages transport.
type MessagesProvider struct {
	base     *HTTPProvider
	options  MessagesOptions
	identity Identity
}

// NewMessages validates an explicit Messages transport and its credentials
// without sending a request.
func NewMessages(o MessagesOptions) (*MessagesProvider, error) {
	if o.Transport == "" {
		o.Transport = ProviderAnthropic
	}

	switch o.Transport {
	case ProviderAnthropic, ProviderAnthropicProxy, ProviderBedrock:
	default:
		return nil, transportError("unsupported_messages_transport")
	}

	base, e := NewHTTP(o.HTTPOptions)
	if e != nil {
		return nil, e
	}

	if err := o.validateCredentials(); err != nil {
		return nil, err
	}

	id := base.identity
	id.Provider = o.Transport + "-messages-json"
	id.SettingsSHA256 = hashBytes([]byte(id.SettingsSHA256 + "\x00" + o.Transport + "\x00" + o.Region + "\x00messages-envelope-v1"))

	return &MessagesProvider{base: base, options: o, identity: id}, nil
}

// Identity returns the requested Messages transport identity without
// credentials or the raw endpoint.
func (p *MessagesProvider) Identity() Identity { return p.identity }

// Complete sends one bounded Messages request under ctx. It rejects tool
// responses and incomplete or ambiguous envelopes.
func (p *MessagesProvider) Complete(ctx context.Context, payload []byte) (Completion, error) {
	if ctx == nil {
		return Completion{}, transportError("nil_context")
	}

	if ctx.Err() != nil {
		return Completion{}, ctx.Err()
	}

	if len(payload) > MaxRequestBytes || !json.Valid(payload) {
		return Completion{}, transportError("invalid_request")
	}
	// No tool definitions. Native JSON mode availability differs by model, so the
	// protocol schema is in the trusted system message and validated locally.
	// No fence stripping, output repair, model fallback or forced tool invocation.
	system, err := PromptForRequest(ctx, payload)
	if err != nil {
		return Completion{}, err
	}

	system += "\nRequired JSON response schema (trusted protocol):\n" + responseSchema

	req, err := p.request(ctx, payload, system)
	if err != nil {
		return Completion{}, err
	}

	raw, e := p.base.readResponse(ctx, req)
	if e != nil {
		return Completion{}, e
	}

	return decodeMessagesCompletion(ctx, raw)
}

func (p *MessagesProvider) request(ctx context.Context, payload []byte, system string) (*http.Request, error) {
	body := map[string]any{
		"max_tokens": p.base.tokens,
		"system":     system,
		"messages": []any{map[string]any{
			"role": "user",
			"content": []any{map[string]string{
				"type": "text",
				"text": string(payload),
			}},
		}},
	}
	switch p.options.Transport {
	case ProviderAnthropic:
		body["model"] = p.base.model
	case ProviderAnthropicProxy:
		body["anthropic_version"] = "vertex-2023-10-16"
	case ProviderBedrock:
		body["anthropic_version"] = "bedrock-2023-05-31"
	}

	raw, e := json.Marshal(body)
	if e != nil {
		return nil, transportError("request_encoding_failed")
	}

	req, e := http.NewRequestWithContext(ctx, http.MethodPost, p.base.endpoint, bytes.NewReader(raw))
	if e != nil {
		return nil, transportError("request_failed")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	p.authenticate(req, raw)

	return req, nil
}

func (p *MessagesProvider) authenticate(req *http.Request, raw []byte) {
	switch p.options.Transport {
	case ProviderAnthropic:
		req.Header.Set("Anthropic-Version", "2023-06-01")

		if p.base.key != "" {
			req.Header.Set("X-Api-Key", p.base.key)
		}
	case ProviderAnthropicProxy:
		if p.base.key != "" {
			req.Header.Set("Authorization", "Bearer "+p.base.key)
		}
	case ProviderBedrock:
		signBedrock(req, raw, p.options, time.Now())
	}
}

func (o MessagesOptions) validateCredentials() error {
	if o.Transport != ProviderBedrock {
		if slices.ContainsFunc([]string{o.Region, o.AccessKeyID, o.SecretAccessKey, o.SessionToken}, func(value string) bool { return value != "" }) {
			return transportError("unexpected_aws_credentials")
		}

		return nil
	}

	if o.APIKey != "" || !validAWSRegion(o.Region) || !(len(o.AccessKeyID) >= 8 && textmatch.Token(o.AccessKeyID, 128, "")) || !credentialBytes(o.SecretAccessKey, 8) || !credentialBytes(o.SessionToken, 0) {
		return transportError("invalid_bedrock_credentials")
	}

	u, _ := url.Parse(o.Endpoint)
	if u.Path != "/model/"+o.Model+"/invoke" {
		return transportError("bedrock_model_path_mismatch")
	}

	return nil
}

func readMessagesUsage(c *Completion, raw []byte, usage *jsonconfig.Node) error {
	if usage != nil {
		if aliases(usage, "input_tokens", "output_tokens") {
			return transportError("ambiguous_envelope")
		}

		var u struct {
			Input  *int64 `json:"input_tokens"`
			Output *int64 `json:"output_tokens"`
		}
		if json.Unmarshal(raw[usage.Span.Start:usage.Span.End], &u) != nil {
			return transportError("invalid_usage")
		}

		setCompletionUsage(c, u.Input, u.Output)

		return c.ValidateMetadata()
	}

	return nil
}

func validAWSRegion(s string) bool {
	if len(s) < 6 || s[0] < 'a' || s[0] > 'z' || s[1] < 'a' || s[1] > 'z' || s[2] != '-' {
		return false
	}

	groups, letters := 0, 0

	for i := 3; i < len(s); i++ {
		b := s[i]
		if b == '-' {
			if letters == 0 || groups == 3 {
				return false
			}

			groups++
			letters = 0

			continue
		}

		if b >= '0' && b <= '9' {
			return i == len(s)-1 && groups > 0 && letters == 0
		}

		if b < 'a' || b > 'z' {
			return false
		}

		letters++
	}

	return false
}

func decodeMessagesCompletion(ctx context.Context, raw []byte) (Completion, error) {
	root, e := jsonconfig.Parse(ctx, string(raw))
	if e != nil {
		return Completion{}, transportError("invalid_envelope")
	}

	if aliases(root, "type", "role", "content", "stop_reason", "model", "usage", "error") {
		return Completion{}, transportError("ambiguous_envelope")
	}

	typ, _ := root.Get("type").Text()
	role, _ := root.Get("role").Text()

	stop, _ := root.Get("stop_reason").Text()
	if typ != "message" || role != "assistant" || stop != "end_turn" {
		return Completion{}, transportError("incomplete_response")
	}

	output, err := messagesText(root.Get("content"))
	if err != nil {
		return Completion{}, err
	}

	model, _ := root.Get("model").Text()

	c := Completion{Output: []byte(output), Model: model, InputTokens: -1, OutputTokens: -1}

	if err := c.ValidateMetadata(); err != nil {
		return Completion{}, err
	}

	if err := readMessagesUsage(&c, raw, root.Get("usage")); err != nil {
		return Completion{}, err
	}

	return c, ctx.Err()
}

func awsEncode(s string, slash bool) string {
	const digits = "0123456789ABCDEF"

	var b strings.Builder

	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~", rune(c)) || slash && c == '/' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(digits[c>>4])
			b.WriteByte(digits[c&15])
		}
	}

	return b.String()
}

func hmac256(k []byte, s string) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte(s))

	return m.Sum(nil)
}

// Strict no-query/no-RawPath POST endpoints are validated by NewHTTP. Signing
// supports only regional Bedrock InvokeModel, not generic AWS/S3/SigV4a.
const bedrockSigningService = "bedrock"

func signBedrock(req *http.Request, payload []byte, o MessagesOptions, now time.Time) {
	stamp := now.UTC().Format("20060102T150405Z")
	date := stamp[:8]
	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", hashBytes(payload))

	if o.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", o.SessionToken)
	}

	headers := map[string]string{
		"host":                 req.URL.Host,
		"content-type":         req.Header.Get("Content-Type"),
		"x-amz-date":           stamp,
		"x-amz-content-sha256": hashBytes(payload),
	}
	if o.SessionToken != "" {
		headers["x-amz-security-token"] = o.SessionToken
	}

	if v := req.Header.Get("Accept"); v != "" {
		headers["accept"] = v
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	var canonical strings.Builder
	for _, k := range keys {
		canonical.WriteString(k + ":" + strings.Join(strings.Fields(headers[k]), " ") + "\n")
	}

	signed := strings.Join(keys, ";")

	uri := awsEncode(req.URL.Path, true)
	if uri == "" {
		uri = "/"
	}

	request := req.Method + "\n" + uri + "\n\n" + canonical.String() + "\n" + signed + "\n" + hashBytes(payload)
	scope := date + "/" + o.Region + "/" + bedrockSigningService + "/aws4_request"
	text := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hashBytes([]byte(request))
	k := hmac256([]byte("AWS4"+o.SecretAccessKey), date)
	k = hmac256(k, o.Region)
	k = hmac256(k, bedrockSigningService)
	k = hmac256(k, "aws4_request")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+o.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(hmac256(k, text)))
}

func messagesText(content *jsonconfig.Node) (string, error) {
	if content == nil || content.Kind != jsonconfig.KindArray || len(content.Elements) == 0 || len(content.Elements) > 16 {
		return "", transportError("invalid_envelope")
	}

	var output strings.Builder

	for _, n := range content.Elements {
		if aliases(n, "type", "text") {
			return "", transportError("ambiguous_envelope")
		}

		t, _ := n.Get("type").Text()

		s, ok := n.Get("text").Text()
		if t != "text" || !ok {
			return "", transportError("tool_call_refused")
		}

		output.WriteString(s)
	}

	return output.String(), nil
}
