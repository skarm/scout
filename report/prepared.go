package report

import (
	"errors"
	"io"
)

// PreparedDocument owns a verified immutable snapshot. Its zero value is
// invalid. Repeated output formats reuse this snapshot without rehashing it.
type PreparedDocument struct{ document *Document }

// Prepare validates the document and takes an independent snapshot for
// repeated rendering. Later caller mutations cannot change the prepared
// result.
func Prepare(document Document) (PreparedDocument, error) {
	document, err := document.validated()
	if err != nil {
		return PreparedDocument{}, err
	}

	snapshot := copyReport(document)

	return PreparedDocument{document: &snapshot}, nil
}

// Valid reports whether preparation succeeded. The zero value is invalid.
func (p PreparedDocument) Valid() bool { return p.document != nil }

// Snapshot returns an independent copy of the prepared document, or a zero
// document if p is invalid.
func (p PreparedDocument) Snapshot() Document {
	if p.document == nil {
		return Document{}
	}

	return copyReport(*p.document)
}

// State returns the prepared run state, or Unknown if p is invalid.
func (p PreparedDocument) State() State {
	if p.document == nil {
		return Unknown
	}

	return p.document.Run.State
}

// Decision returns the prepared policy decision, or an empty decision if p is
// invalid.
func (p PreparedDocument) Decision() Decision {
	if p.document == nil {
		return ""
	}

	return p.document.Evaluation.Decision
}

// Operation returns the prepared operation, or an empty operation if p is
// invalid.
func (p PreparedDocument) Operation() Operation {
	if p.document == nil {
		return ""
	}

	return p.document.Operation
}

// PolicyDigest returns the bound policy digest, or an empty string if p is
// invalid.
func (p PreparedDocument) PolicyDigest() string {
	if p.document == nil {
		return ""
	}

	return p.document.Evaluation.PolicyDigest
}

// ValidComparisonRoles reports whether the prepared targets have the required
// before and after roles.
func (p PreparedDocument) ValidComparisonRoles() bool {
	if p.document == nil {
		return false
	}

	targets := p.document.Run.Targets

	return len(targets) == 2 && targets[0].Role == "before" && targets[1].Role == "after"
}

// Write renders the prepared snapshot in format. An invalid zero value,
// unsupported format or writer failure returns an error. It does not close w.
func (p PreparedDocument) Write(w io.Writer, format Format) error {
	if p.document == nil {
		return errors.New("unprepared report")
	}

	return writePrepared(w, format, *p.document)
}
