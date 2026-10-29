package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Format selects a report representation. Each format renders the same
// validated document.
type Format string

const (
	// Text selects the terminal text representation.
	Text Format = "text"
	// JSON selects the versioned JSON document representation.
	JSON Format = "json"
	// SARIF selects the SARIF representation with Scout document properties.
	SARIF Format = "sarif"
	// Markdown selects the Markdown representation.
	Markdown Format = "markdown"
)

type documentSARIF struct {
	sarif
	Properties sarifDocumentProperties `json:"properties"`
}

type sarifDocumentProperties struct {
	Schema     string       `json:"schema"`
	Operation  Operation    `json:"operation"`
	RunState   State        `json:"runState"`
	RunDigest  string       `json:"runDigest,omitempty"`
	Evaluation *Evaluation  `json:"evaluation"`
	Problems   []Problem    `json:"problems,omitempty"`
	Comparison *UpdateDelta `json:"comparison,omitempty"`
}

type failureDocument struct {
	Schema     string      `json:"schema"`
	Operation  Operation   `json:"operation"`
	Run        *Run        `json:"run"`
	Evaluation *Evaluation `json:"evaluation"`
	Problems   []Problem   `json:"problems"`
}

// ParseFormat parses a supported output format name or returns an error.
func ParseFormat(value string) (Format, error) {
	switch Format(value) {
	case Text, JSON, SARIF, Markdown:
		return Format(value), nil
	default:
		return "", errors.New("unsupported report format")
	}
}

// Write validates the run/evaluation binding before emitting bytes.
// Machine JSON preserves the sealed run. Other formats project its evaluation
// onto temporary analysis values without changing the evidence or source run.
func Write(w io.Writer, format Format, document Document) error {
	prepared, err := Prepare(document)
	if err != nil {
		return err
	}

	return prepared.Write(w, format)
}

// WriteFailure reports a preflight failure without inventing a completed run.
// Message is replaced with scanner-owned text: callers pass stable problem
// codes and identifiers, not a provider's potentially sensitive error string.
func WriteFailure(w io.Writer, format Format, operation Operation, problem Problem) error {
	if w == nil {
		return errors.New("nil report writer")
	}

	if err := validateFailure(operation, problem); err != nil {
		return err
	}

	problem.Message = "Scout could not start the requested operation."

	var (
		out bytes.Buffer
		err error
	)

	switch format {
	case JSON:
		err = writeJSON(&out, failureDocument{
			Schema:    DocumentSchema,
			Operation: operation,
			Problems:  []Problem{problem},
		})
	case SARIF:
		err = writeJSON(&out, failureToSARIF(operation, problem))
	case Text, Markdown:
		failureText(&out, format, operation, problem)
	default:
		return errors.New("unsupported report format")
	}

	if err != nil {
		return err
	}

	return writeDocumentBytes(w, out.Bytes())
}

func writePrepared(w io.Writer, format Format, document Document) error {
	if w == nil {
		return errors.New("nil report writer")
	}

	if format == JSON {
		return writeEncodedDocument(w, document)
	}

	if format == SARIF {
		return writeEncodedDocument(w, documentToSARIF(document))
	}

	var (
		out bytes.Buffer
		err error
	)

	switch format {
	case Text:
		err = documentText(&out, document, false)
	case Markdown:
		err = documentText(&out, document, true)
	default:
		return errors.New("unsupported report format")
	}

	if err != nil {
		return err
	}

	return writeDocumentBytes(w, out.Bytes())
}

func writeEncodedDocument(w io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}

	return writeDocumentBytes(w, append(data, '\n'))
}

func documentToSARIF(document Document) documentSARIF {
	result := documentSARIF{sarif: toSARIF(Analysis{}, document.Evaluation), Properties: sarifDocumentProperties{
		Schema:     DocumentSchema,
		Operation:  document.Operation,
		RunState:   document.Run.State,
		RunDigest:  document.Run.Digest,
		Evaluation: &document.Evaluation,
		Problems:   document.Run.Problems,
		Comparison: document.Run.Comparison,
	}}

	result.Runs = make([]run, 0, len(document.Run.Targets))
	for _, target := range document.Run.Targets {
		analysis := documentAnalysis(document, target)

		part := toSARIF(analysis, targetEvaluation(document, target))
		for _, item := range part.Runs {
			item.Properties["runState"] = document.Run.State
			item.Properties["runDigest"] = document.Run.Digest
			item.Properties["targetID"] = target.ID
			item.Properties["targetIndex"] = target.Index
			item.Properties["targetRole"] = target.Role

			item.Properties["targetLabel"] = target.Label
			for i := range item.Invocations {
				item.Invocations[i].ExecutionSuccessful = document.Run.State == RunComplete && target.State == RunComplete && analysis.Coverage.Completeness == Complete
			}

			result.Runs = append(result.Runs, item)
		}
	}

	return result
}

func documentAnalysis(document Document, target TargetResult) Analysis {
	analysis := target.Analysis
	analysis.EngineVersion = document.Run.Engine.Version

	return analysis
}

func targetEvaluation(document Document, target TargetResult) Evaluation {
	evaluation := document.Evaluation
	approvals := make([]Suppression, 0)

	for _, approval := range document.Evaluation.Suppressed {
		if approval.TargetID == target.ID {
			approvals = append(approvals, approval)
		}
	}

	evaluation.Suppressed = approvals

	return evaluation
}

func documentText(out *bytes.Buffer, document Document, md bool) error {
	quote := strconv.QuoteToASCII
	if md {
		quote = mdCode

		out.WriteString("# Scout report\n\n")
	}

	_, _ = fmt.Fprintf(out, "Operation: %s; state: %s; decision: %s.\n\n", quote(string(document.Operation)), quote(string(document.Run.State)), quote(string(document.Evaluation.Decision)))
	_, _ = fmt.Fprintf(out, "Run digest: %s.\n\n", quote(document.Run.Digest))
	_, _ = fmt.Fprintf(out, "Decision reasons: %s.\n\n", quote(strings.Join(document.Evaluation.Reasons, ", ")))

	for _, problem := range document.Run.Problems {
		_, _ = fmt.Fprintf(out, "Problem: %s; phase: %s; target: %s; object: %s.\n\n", quote(problem.Code), quote(problem.Phase), quote(problem.TargetID), quote(problem.ObjectID))
	}

	if document.Run.Comparison != nil {
		writeComparison(out, *document.Run.Comparison, md)
	}

	for _, target := range document.Run.Targets {
		writeTargetHeading(out, target, md)

		analysis := documentAnalysis(document, target)
		if md {
			if err := markdown(out, analysis, targetEvaluation(document, target)); err != nil {
				return err
			}
		} else {
			analysis.EngineVersion = strconv.QuoteToASCII(analysis.EngineVersion)

			analysis.Profile = strconv.QuoteToASCII(analysis.Profile)
			if err := terminal(out, analysis, targetEvaluation(document, target)); err != nil {
				return err
			}
		}
	}

	return nil
}

func writeComparison(out *bytes.Buffer, delta UpdateDelta, md bool) {
	quote := strconv.QuoteToASCII
	if md {
		quote = mdCode
	}

	_, _ = fmt.Fprintf(out, "Comparison: %s; unchanged snapshot: %t; files: %d; components: %d; dependencies: %d; findings: %d; manifest signals: %d; omitted: %d.\n\n",
		quote(string(delta.Completeness)), delta.SameSnapshot, delta.Counts.FileChanges, delta.Counts.ComponentChanges, delta.Counts.DependencyChanges, delta.Counts.FindingChanges, delta.Counts.ManifestSignals, delta.OmittedChanges)

	for _, change := range delta.Files {
		name := change.Address.Root
		if change.After != nil {
			name = change.After.Path
		} else if change.Before != nil {
			name = change.Before.Path
		}

		_, _ = fmt.Fprintf(out, "File %s: %s.\n\n", quote(name), quote(change.Change))
	}

	for _, signal := range delta.ManifestSignals {
		_, _ = fmt.Fprintf(out, "Manifest signal %s (%s): %s; %s.\n\n", quote(signal.RuleID), quote(string(signal.Severity)), quote(signal.Field), quote(signal.Change))
	}

	for _, change := range delta.Findings {
		_, _ = fmt.Fprintf(out, "Finding %s: %s.\n\n", quote(change.RuleID), quote(change.Change))
	}

	for _, issue := range delta.Issues {
		_, _ = fmt.Fprintf(out, "Comparison gap: %s.\n\n", quote(issue))
	}
}

func writeTargetHeading(out *bytes.Buffer, target TargetResult, md bool) {
	quote, prefix := strconv.QuoteToASCII, ""
	if md {
		quote, prefix = mdCode, "## "
	}

	label := target.Label
	if label == "" {
		label = target.ID
	}

	_, _ = fmt.Fprintf(out, "%sTarget %d: %s; state: %s; role: %s.\n\n", prefix, target.Index, quote(label), quote(string(target.State)), quote(target.Role))
}

func validateFailure(operation Operation, problem Problem) error {
	if operation != ScanOperation && operation != CompareOperation {
		return errors.New("unknown failure operation")
	}

	if !problemCode(problem.Code) || (problem.Phase != "" && !problemCode(problem.Phase)) {
		return errors.New("invalid failure code or phase")
	}

	return nil
}

func failureToSARIF(operation Operation, problem Problem) documentSARIF {
	log := documentSARIF{sarif: toSARIF(Analysis{}, Evaluation{}), Properties: sarifDocumentProperties{
		Schema: DocumentSchema, Operation: operation, RunState: RunFailed, Problems: []Problem{problem},
	}}
	log.Runs = []run{{
		Tool:       tool{Driver: driver{Name: "scout", Rules: []rule{}}},
		ColumnKind: "unicodeCodePoints",
		Results:    []result{},
		Invocations: []invocation{{
			ExecutionSuccessful: false,
			ToolExecutionNotifications: []notification{{
				Level:   "error",
				Message: message{Text: problem.Message + " Code: " + problem.Code},
			}},
		}},
		Properties: map[string]any{"runState": RunFailed, "problems": []Problem{problem}},
	}}

	return log
}

func failureText(out *bytes.Buffer, format Format, operation Operation, problem Problem) {
	quote := strconv.QuoteToASCII
	if format == Markdown {
		quote = mdCode

		out.WriteString("# Scout could not start the requested operation\n\n")
	}

	_, _ = fmt.Fprintf(out, "Scout operation %s failed: %s; phase: %s.\n\n", quote(string(operation)), quote(problem.Code), quote(problem.Phase))
	_, _ = fmt.Fprintf(out, "Target: %s; object: %s.\n", quote(problem.TargetID), quote(problem.ObjectID))
}

func problemCode(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}

	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}

	return true
}

func writeDocumentBytes(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}

	return err
}
