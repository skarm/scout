// Package check defines the immutable contract implemented by trusted analyzers.
package check

import (
	"context"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/report"
)

// ShellEval marks an observed eval command in a shell finding.
const ShellEval = "shell_eval"

// ShellCommandText marks command text passed to a modeled shell execution sink.
const ShellCommandText = "shell_command_text"

// ShellPackageScript marks a shell command supplied by a package script.
const ShellPackageScript = "shell_package_script"

// ShellHostEnvironment marks a write to a host-sourced shell environment file.
const ShellHostEnvironment = "shell_host_environment"

// ShellHostUpdatedInput marks shell command text returned in hook output.
const ShellHostUpdatedInput = "shell_host_updated_input"

// Match refers to original file bytes. Bounds are half-open. No source text is
// returned, preventing accidental credential disclosure through reports.
type Match struct {
	// Start is the inclusive byte offset in the original captured file.
	Start int
	// End is the exclusive byte offset in the original captured file.
	End int
	// Trace records source-bound steps supporting the matched behavior.
	Trace []Trace
	// Related records supporting spans from other captured objects.
	Related []report.SourceRef
	// A trusted analyzer may lower severity from its descriptor's maximum.
	Severity report.Severity
	// InactiveForSurface marks an observation that must not establish an active
	// capability for surface-composition checks.
	InactiveForSurface bool
	// Scanner-owned context labels, validated by the report boundary.
	ContextSignals []string
}

// Trace records one evidence-flow step in original file byte coordinates.
type Trace struct {
	// Role identifies this step's contribution to the observed flow.
	Role string
	// Start is the inclusive byte offset of this flow step.
	Start int
	// End is the exclusive byte offset of this flow step.
	End int
}

// Result retains valid matches independently of a check's error or truncation
// state.
type Result struct {
	// Valid matches remain usable even when Find also returns an error.
	Matches []Match
	// Truncated reports a retention or analysis limit; existing matches remain
	// available.
	Truncated bool
}

// Analyzer implementations are trusted scanner code, NOT sandboxed plugins.
// They must be immutable, concurrency-safe and cooperate with cancellation.
type Analyzer interface {
	// Rule returns an immutable check descriptor with a stable identity and
	// version.
	Rule() report.Rule
	// AppliesTo reports whether the check selects a prepared file.
	AppliesTo(document.File) bool
	// Find returns bounded matches under the supplied context and retention limit.
	// Valid matches may accompany an error.
	Find(context.Context, document.File, int) (Result, error)
}
