package knowledge

const (
	categoryToolPoisoning   = "tool_poisoning"
	categoryPromptInjection = "prompt_injection"
	categoryIntentMismatch  = "intent_mismatch"
	categoryQualityPolicy   = "quality_policy"
)

//nolint:gochecknoglobals // The compiled reason catalog is immutable; exported lists are copied.
var reasons = [...]Reason{
	{
		Name:       "tool_description_code_mismatch",
		Category:   categoryToolPoisoning,
		Mode:       ModeToolConsistency,
		UpstreamID: "NV-TP4",
	},
	{Name: "instruction_override", Category: categoryPromptInjection},
	{Name: "secret_transfer", Category: "data_exfiltration"},
	{Name: "unapproved_execution", Category: "execution"},
	{Name: "persistent_agent_change", Category: "persistence"},
	{Name: "reviewer_manipulation", Category: categoryPromptInjection},
	{Name: "untrusted_dependency", Category: "supply_chain"},
	{Name: "permission_expansion", Category: "permissions"},
	{Name: categoryToolPoisoning, Category: categoryToolPoisoning},
	{Name: "purpose_capability_mismatch", Category: categoryIntentMismatch},
	{Name: "semantic_prompt_injection", Category: categoryPromptInjection, Mode: ModeDiscovery, UpstreamID: "SSD-1"},
	{Name: "paraphrased_attack", Category: categoryPromptInjection, Mode: ModeDiscovery, UpstreamID: "SSD-2"},
	{Name: "natural_language_exfiltration", Category: "data_exfiltration", Mode: ModeDiscovery, UpstreamID: "SSD-3"},
	{Name: "gradual_deception", Category: categoryPromptInjection, Mode: ModeDiscovery, UpstreamID: "SSD-4"},
	{Name: "description_behavior_mismatch", Category: categoryIntentMismatch, Mode: ModeIntent, UpstreamID: "SDI-1"},
	{Name: "context_inappropriate_capability", Category: categoryIntentMismatch, Mode: ModeIntent, UpstreamID: "SDI-2"},
	{Name: "declared_scope_creep", Category: "permissions", Mode: ModeIntent, UpstreamID: "SDI-3"},
	{Name: "intent_code_divergence", Category: categoryIntentMismatch, Mode: ModeIntent, UpstreamID: "SDI-4"},
	{Name: "quality_vague_triggers", Category: categoryQualityPolicy, Mode: ModeQuality, UpstreamID: "SQP-1"},
	{Name: "quality_missing_warnings", Category: categoryQualityPolicy, Mode: ModeQuality, UpstreamID: "SQP-2"},
	{Name: "quality_language_policy", Category: categoryQualityPolicy, Mode: ModeQuality, UpstreamID: "SQP-3"},
}

// Reason binds one compiled semantic reason to its category, task and adapted
// upstream identity. Empty Mode preserves the original general-purpose reasons.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type Reason struct {
	// Name is the accepted semantic reason code.
	Name string
	// Category is the concern category assigned to this reason.
	Category string
	// Mode restricts the reason to one review stage; empty means no mode
	// restriction.
	Mode string
	// UpstreamID is the adapted upstream taxonomy identity, when registered.
	UpstreamID string
}

// LookupReason resolves a compiled reason or knowledge topic without accepting
// model-defined taxonomy.
func LookupReason(name string) (Reason, bool) {
	for _, reason := range reasons {
		if reason.Name == name {
			return reason, true
		}
	}

	if topic, ok := TopicForReason(name); ok {
		return Reason{Name: name, Category: topic.Category, Mode: ModeDiscovery}, true
	}

	return Reason{}, false
}

// Reasons returns all compiled semantic reasons, including curated knowledge
// topic reasons.
func Reasons() []string {
	out := make([]string, 0, len(reasons)+len(curated.topics))
	for _, reason := range reasons {
		out = append(out, reason.Name)
	}

	return append(out, ReviewReasons()...)
}
