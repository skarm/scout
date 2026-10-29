package review

// Provider identifiers select the operator-configured transport.
const (
	// ProviderChatCompletions identifies chat-completions.
	// Part of the supported Go API for callers outside this repository.
	//goland:noinspection GoUnnecessarilyExportedIdentifiers
	ProviderChatCompletions = "chat-completions"
	// ProviderAnthropic identifies anthropic.
	// Part of the supported Go API for callers outside this repository.
	//goland:noinspection GoUnnecessarilyExportedIdentifiers
	ProviderAnthropic = "anthropic"
	// ProviderAnthropicProxy identifies anthropic-proxy.
	// Part of the supported Go API for callers outside this repository.
	//goland:noinspection GoUnnecessarilyExportedIdentifiers
	ProviderAnthropicProxy = "anthropic-proxy"
	// ProviderBedrock identifies bedrock.
	ProviderBedrock = "bedrock"
)
