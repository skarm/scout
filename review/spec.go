package review

import (
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/skarm/scout/internal/textmatch"
)

// ProviderSpec is operator configuration before credentials are resolved. It is
// safe to copy and patch; it never contains credentials or an HTTP client.
type ProviderSpec struct {
	// Kind selects chat-completions, anthropic, anthropic-proxy or bedrock.
	Kind string
	// Endpoint is the operator-selected service URL.
	Endpoint string
	// Model is the requested model name.
	Model string
	// KeyEnv names the environment variable from which Build reads the transport
	// API key.
	KeyEnv string
	// Region is the AWS region used for Bedrock requests.
	Region string
	// AccessEnv names the environment variable containing the AWS access key ID.
	AccessEnv string
	// SecretEnv names the environment variable containing the AWS signing secret.
	SecretEnv string
	// SessionEnv optionally names the environment variable containing the AWS
	// session token.
	SessionEnv string
	// AllowLoopback permits explicit loopback endpoints; private non-loopback
	// destinations remain subject to network policy.
	AllowLoopback bool
	// Timeout bounds each provider request, within the caller's context deadline.
	Timeout time.Duration
	// MaxOutputTokens sets the requested completion token ceiling.
	MaxOutputTokens int
	// MaxResponseBytes limits accepted HTTP response bytes.
	MaxResponseBytes int
}

// DefaultProviderSpec returns credential-free Chat Completions defaults with
// bounded response and timeout settings.
func DefaultProviderSpec() ProviderSpec {
	return ProviderSpec{
		Kind:             ProviderChatCompletions,
		Timeout:          DefaultOptions().Timeout,
		MaxOutputTokens:  2048,
		MaxResponseBytes: DefaultOptions().MaxResponseBytes,
	}
}

// Validate checks the passive specification without reading the environment or
// making a network request. Build reads only the named environment variables.
func (s ProviderSpec) Validate() error {
	if err := (Identity{Provider: s.Kind, Model: s.Model}).Validate(); err != nil {
		return err
	}

	if _, err := validateHTTPOptions(s.httpOptions()); err != nil {
		return err
	}

	switch s.Kind {
	case ProviderChatCompletions, ProviderAnthropic, ProviderAnthropicProxy:
		if slices.ContainsFunc([]string{s.Region, s.AccessEnv, s.SecretEnv, s.SessionEnv}, func(value string) bool { return value != "" }) {
			return errors.New("AWS options require Bedrock")
		}

		if s.KeyEnv != "" && !environmentName(s.KeyEnv) {
			return errors.New("invalid credential environment name")
		}

		return nil
	case ProviderBedrock:
		return s.validateBedrock()
	default:
		return errors.New("unsupported review provider")
	}
}

// Build validates the specification and resolves only its named credentials
// through lookup. It constructs a provider without sending a request.
func (s ProviderSpec) Build(lookup func(string) (string, bool)) (Provider, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	h := s.httpOptions()
	if s.KeyEnv != "" {
		key, err := readCredential(s.KeyEnv, lookup)
		if err != nil {
			return nil, err
		}

		h.APIKey = key
	}

	if s.Kind == ProviderChatCompletions {
		return NewHTTP(h)
	}

	o := MessagesOptions{HTTPOptions: h, Transport: s.Kind, Region: s.Region}
	if s.Kind == ProviderBedrock {
		if err := s.credentials(&o, lookup); err != nil {
			return nil, err
		}
	}

	return NewMessages(o)
}

func (s ProviderSpec) validateBedrock() error {
	if s.KeyEnv != "" || !validAWSRegion(s.Region) || !environmentName(s.AccessEnv) || !environmentName(s.SecretEnv) {
		return errors.New("a region and explicit AWS credential variables are required for Bedrock")
	}

	if s.SessionEnv != "" && !environmentName(s.SessionEnv) {
		return errors.New("invalid credential environment name")
	}

	u, _ := url.Parse(s.Endpoint) // validated by Validate before this method
	if u.Path != "/model/"+s.Model+"/invoke" {
		return transportError("bedrock_model_path_mismatch")
	}

	return nil
}

func (s ProviderSpec) httpOptions() HTTPOptions {
	return HTTPOptions{
		Endpoint:         s.Endpoint,
		Model:            s.Model,
		AllowLoopback:    s.AllowLoopback,
		Timeout:          s.Timeout,
		MaxOutputTokens:  s.MaxOutputTokens,
		MaxResponseBytes: s.MaxResponseBytes,
	}
}

func (s ProviderSpec) credentials(o *MessagesOptions, lookup func(string) (string, bool)) error {
	var err error
	if o.AccessKeyID, err = readCredential(s.AccessEnv, lookup); err != nil {
		return err
	}

	if o.SecretAccessKey, err = readCredential(s.SecretEnv, lookup); err != nil {
		return err
	}

	if s.SessionEnv != "" {
		o.SessionToken, err = readCredential(s.SessionEnv, lookup)
	}

	return err
}

func environmentName(name string) bool { return textmatch.Identifier(name, 128) }

func readCredential(name string, lookup func(string) (string, bool)) (string, error) {
	if !environmentName(name) || lookup == nil {
		return "", errors.New("explicit credential variable is unavailable")
	}

	value, ok := lookup(name)
	if !ok || !credentialBytes(value, 1) {
		return "", errors.New("explicit credential is empty or invalid")
	}

	return value, nil
}

func credentialBytes(value string, minimum int) bool {
	return len(value) >= minimum && len(value) <= 8192 && !strings.ContainsAny(value, "\r\n\x00")
}
