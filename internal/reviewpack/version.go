// Package reviewpack defines compatibility labels for compiled review materials.
// Asset and prompt digests identify their exact contents.
package reviewpack

// These independent labels are inherited from the preview. Their suffixes do
// not attest to a verified sequence of releases. Keep protocol/schema versions
// separate: a content edit changes its digest without necessarily changing a
// compatibility label.
const (
	// KnowledgeVersion labels the compiled guidance contract.
	KnowledgeVersion = "scout-curated-review-v4"
	// InstructionsVersion labels the semantic instruction contract.
	InstructionsVersion = "scout-curated-review-instructions-v4"
	// TransferVersion labels the exported reviewer bundle contract.
	TransferVersion = "scout-reviewer-transfer-v4"
)
