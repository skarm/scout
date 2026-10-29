package review

import (
	"context"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/knowledge"
)

// PromptForMode returns trusted compiled instructions for mode or an error if
// the mode is unsupported.
func PromptForMode(mode string) (string, error) { return knowledge.Prompt(mode) }

// PromptDigest returns the lowercase hexadecimal SHA-256 digest of the
// supplied prompt text.
func PromptDigest(prompt string) string { return knowledge.Hash([]byte(prompt)) }

// PromptForRequest verifies task/prompt identity before egress. It reads no
// artifact configuration. Content is sent only as the untrusted user message;
// no interpolation of excerpt or manifest text into these trusted instructions.
func PromptForRequest(ctx context.Context, payload []byte) (string, error) {
	if len(payload) > MaxRequestBytes {
		return "", transportError("invalid_request")
	}

	root, e := jsonconfig.Parse(ctx, string(payload))
	if e != nil || root.Kind != jsonconfig.KindObject {
		return "", transportError("invalid_request")
	}

	identity := make(map[string]string, 4)

	for _, field := range []string{"schema_version", "prompt_version", "mode", "prompt_sha256"} {
		value, ok := root.Get(field).Text()
		if !ok {
			return "", transportError("request_prompt_identity")
		}

		identity[field] = value
	}

	if identity["schema_version"] != ProtocolVersion || identity["prompt_version"] != PromptVersion {
		return "", transportError("request_prompt_identity")
	}

	p, e := knowledge.Prompt(identity["mode"])
	if e != nil || PromptDigest(p) != identity["prompt_sha256"] {
		return "", transportError("request_prompt_identity")
	}

	return p, nil
}
