// Package extract derives bounded, virtual analysis objects from captured bytes.
// It never writes files, follows paths, launches programs, or uses the network.
package extract

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/filetype"
	"github.com/skarm/scout/report"
)

var (
	errBudget = errors.New("extraction budget exceeded")
	errFormat = errors.New("unsupported or malformed representation")
)

const (
	jsonStringsExtractorID = "json-strings"
	fallbackObjectName     = "content.bin"
)

//nolint:gochecknoglobals // Read-only format dispatch and encoding grammar shared by extraction runs.
var formatExtractors = map[string]struct {
	id  string
	run func(*operation) error
}{
	"zip": {id: report.ExtractorZIP32, run: extractZIP},
	"jar": {id: report.ExtractorZIP32, run: extractZIP},
	"whl": {id: report.ExtractorZIP32, run: extractZIP},
	"nupkg": {
		id:  report.ExtractorZIP32,
		run: extractZIP,
	},
	"ooxml": {
		id:  report.ExtractorZIP32,
		run: extractZIP,
	},
	"opendocument": {
		id:  report.ExtractorZIP32,
		run: extractZIP,
	},
	"gzip": {id: "gzip", run: extractGZIP},
	"gz":   {id: "gzip", run: extractGZIP},
	"tgz":  {id: "gzip", run: extractGZIP},
	"tar": {
		id:  report.ExtractorTar,
		run: extractTAR,
	},
	"png": {
		id:  "png-text",
		run: extractPNG,
	},
}

// Result owns only derived files. Original snapshot identity is never rewritten.
type Result struct {
	Files       []artifact.File
	Report      report.ExtractionReport
	Diagnostics []report.Diagnostic
	// HookNamespacesIncomplete records loss that may hide package members.
	HookNamespacesIncomplete bool
}

type queued struct {
	file  artifact.File
	depth int
}
type builder struct {
	ctx         context.Context
	limits      report.ExtractionLimits
	result      Result
	queue       []queued
	diagnostics map[diagnosticKey]struct{}
}
type diagnosticKey struct{ path, code string }

type operation struct {
	role    string
	b       *builder
	parent  queued
	step    int
	ordinal int
	// Set only after reading a complete JSON stream whose skipped tokens
	// have no supported decoder that could produce an archive namespace.
	skippedNonContainers bool
	skipped              bool
}

type contextReader struct {
	ctx interface{ Err() error }
	r   io.Reader
}

// Expand runs deterministic breadth-first extraction with budgets shared by ALL
// roots. Checks on original bytes remain the responsibility of the scan engine.
func Expand(ctx context.Context, files []artifact.File, limits report.ExtractionLimits) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("nil extraction context")
	}

	if err := limits.Validate(); err != nil {
		return Result{}, err
	}

	b := builder{ctx: ctx, limits: limits, result: Result{
		Files: []artifact.File{}, Diagnostics: []report.Diagnostic{},
		Report: report.ExtractionReport{
			Limits:  limits,
			Skipped: []report.SkippedObject{},
			Skills:  []string{},
			Objects: []report.DerivedObject{},
			Steps:   []report.ExtractionStep{},
		},
	}}

	roots := append([]artifact.File(nil), files...)
	sort.Slice(roots, func(i, j int) bool { return roots[i].Metadata().Path < roots[j].Metadata().Path })

	for _, file := range roots {
		b.queue = append(b.queue, queued{file: file})
	}

	for i := 0; i < len(b.queue); i++ {
		if err := ctx.Err(); err != nil {
			return b.result, err
		}

		parent := b.queue[i]
		b.expand(parent)
	}

	return b.result, ctx.Err()
}

func (b *builder) expand(parent queued) {
	meta, text := parent.file.Metadata(), parent.file.Content()
	candidates := extractionCandidatesFor(meta.Path, text, meta.Executable)

	// Dispatch is static and trusted. Format hints select attempts, not trust.
	if extractor, ok := formatExtractors[candidates.format]; ok {
		b.run(parent, extractor.id, extractor.run)
	}

	if candidates.utf16 {
		b.run(parent, "utf16-bom", extractUTF16)
	}
	// Explicit data URIs are searched in every byte stream, not just text files.
	// Whole-file Base64 is a bounded candidate, not an accusation of malice.
	if candidates.json {
		b.run(parent, jsonStringsExtractorID, extractJSON)

		if omsCandidate(meta.Path, text) {
			b.run(parent, "oms-certificate-claims", extractOMSCertificates)
		}
	}

	if candidates.base64 {
		b.run(parent, "base64", extractBase64)
	}
}

type extractionCandidates struct {
	format              string
	utf16, json, base64 bool
}

func extractionCandidatesFor(name, text string, executable bool) extractionCandidates {
	return extractionCandidates{
		format: filetype.Inspect(name, text, executable).Format,
		utf16:  strings.HasPrefix(text, "\xff\xfe") || strings.HasPrefix(text, "\xfe\xff"),
		json:   jsonCandidate(name, text),
		base64: base64Candidate(name, text),
	}
}

func (b *builder) run(parent queued, id string, fn func(*operation) error) {
	version := "1"
	if id == jsonStringsExtractorID {
		version = "2"
	}

	b.result.Report.Steps = append(b.result.Report.Steps, report.ExtractionStep{
		ParentPath: parent.file.Metadata().Path, ExtractorID: id, Version: version, Status: report.OutcomeCompleted,
	})
	op := operation{role: "decoded", b: b, parent: parent, step: len(b.result.Report.Steps) - 1}

	defer func() {
		if recover() != nil {
			b.result.Report.Steps[op.step].Status = report.OutcomeFailed
			op.issue("extractor_panic", "A trusted extractor failed; original bytes and previously validated children are retained. Panic details are withheld.")
		}

		if !op.skippedNonContainers && (op.skipped ||
			archiveContainersUnverified(id, b.result.Report.Steps[op.step].Status)) {
			b.result.HookNamespacesIncomplete = true
		}
	}()

	var err error

	if parent.depth >= b.limits.MaxDepth {
		op.issue("extraction_depth_limit", "Extraction depth exhausted; deeper representations were not inspected.")

		err = errBudget
	} else if b.ctx.Err() != nil {
		err = b.ctx.Err()
	} else {
		err = fn(&op)
	}

	if err != nil {
		switch {
		case errors.Is(err, errBudget):
			b.result.Report.Steps[op.step].Status = "budget_exceeded"
			op.issue("extraction_budget_exceeded", "An extraction budget was exhausted; output prefixes are not treated as complete objects.")
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			b.result.Report.Steps[op.step].Status = report.OutcomeCancelled
			op.issue("extraction_cancelled", "Extraction was cancelled; previously validated objects are retained.")
		default:
			b.result.Report.Steps[op.step].Status = report.OutcomeFailed
			op.issue("extraction_invalid_or_unsupported", "The representation is malformed, ambiguous, encrypted or unsupported; original bytes and previously validated children remain available.")
		}
	}
	// Successful decoding is not full format/behavior coverage. This is explicit
	// even for a text-looking child with no other diagnostic.
	op.issue("extraction_scope_limited", "Only supported representations were extracted. This does not establish complete container, encoding or behavior coverage.")
}

func archiveContainersUnverified(extractorID, status string) bool {
	if status == "budget_exceeded" {
		// A budget can stop an extractor before it identifies a skipped
		// value. The unread tail may still contain a nested archive.
		return true
	}

	return status != report.OutcomeCompleted && (extractorID == report.ExtractorZIP32 || extractorID == report.ExtractorTar || extractorID == "gzip")
}

// A plain synthetic JSON token cannot be a named package member. It can
// affect package coverage if a chained extractor could expose an archive.
func mayDecodeContainer(text string) bool {
	candidates := extractionCandidatesFor("json-string.txt", text, false)

	_, format := formatExtractors[candidates.format]

	return format || candidates.utf16 || candidates.json || candidates.base64
}

func (o *operation) issue(code, message string) {
	p := o.parent.file.Metadata().Path
	key := diagnosticKey{path: p, code: code}

	if o.b.diagnostics == nil {
		o.b.diagnostics = make(map[diagnosticKey]struct{})
	}

	if _, seen := o.b.diagnostics[key]; seen {
		return
	}

	o.b.diagnostics[key] = struct{}{}
	o.b.result.Diagnostics = append(o.b.result.Diagnostics, report.Diagnostic{
		Code:         code,
		Path:         p,
		Message:      message,
		AffectsScope: true,
	})
}

func (o *operation) entry() error {
	if err := o.b.ctx.Err(); err != nil {
		return err
	}

	if o.b.result.Report.EntriesVisited >= o.b.limits.MaxEntries {
		return errBudget
	}

	o.b.result.Report.EntriesVisited++

	return nil
}

func (o *operation) budget() (int64, error) {
	if err := o.b.ctx.Err(); err != nil {
		return 0, err
	}

	if len(o.b.result.Files) >= o.b.limits.MaxObjects {
		return 0, errBudget
	}

	n := min(o.b.limits.MaxObjectBytes, o.b.limits.MaxTotalBytes-o.b.result.Report.BytesProduced)
	if n < 0 {
		return 0, errBudget
	}

	return n, nil
}

// emit only publishes a child after EOF and successful integrity checks by the
// reader. Failed, discarded reads consume the aggregate budget too. A single
// lookahead byte is permitted to distinguish EOF from limit exhaustion.
func (o *operation) emit(name string, r io.Reader, expected int64, executable bool, region *report.ByteRange) error {
	return o.emitValidated(name, r, expected, executable, region, nil)
}

func (o *operation) emitValidated(name string, r io.Reader, expected int64, executable bool, region *report.ByteRange, valid func([]byte) bool) (err error) {
	ordinal := o.ordinal
	o.ordinal++

	defer func() {
		if err != nil {
			reason := extractionFailureReason(err)
			o.recordSkip(name, reason, expected, ordinal)
		}
	}()

	data, err := o.readOutput(r, expected)
	if err != nil {
		return err
	}

	if valid != nil && !valid(data) {
		return errFormat
	}

	if region != nil && (region.Start < 0 || region.End < region.Start || region.End > len(o.parent.file.Content())) {
		return errFormat
	}

	o.publish(name, data, executable, region, ordinal)

	return nil
}

func (o *operation) readOutput(r io.Reader, expected int64) ([]byte, error) {
	budget, err := o.budget()
	if err != nil {
		return nil, err
	}

	if expected > budget {
		return nil, errBudget
	}

	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: o.b.ctx, r: r}, budget+1))

	o.b.result.Report.BytesProduced += int64(len(data))
	if int64(len(data)) > budget {
		return nil, errBudget
	}

	if err != nil {
		return nil, err
	}

	if err = o.b.ctx.Err(); err != nil {
		return nil, err
	}

	if expected >= 0 && int64(len(data)) != expected {
		return nil, errFormat
	}

	return data, nil
}

func (o *operation) publish(name string, data []byte, executable bool, region *report.ByteRange, ordinal int) {
	parent := o.parent.file.Metadata()
	descriptor := o.b.result.Report.Steps[o.step]
	hashInput, _ := json.Marshal([]any{"scout-derived-v1", parent.Path, parent.SHA256, descriptor.ExtractorID, descriptor.Version, ordinal, name, artifact.Hash(data)})
	id := artifact.Hash(hashInput)
	// URI namespace cannot collide with portable captured paths (':' is refused).
	// Names remain metadata; no path obtained from an artifact is ever opened.
	base := path.Base(name)
	if base == "." || base == "/" || base == "" {
		base = fallbackObjectName
	}

	virtual := (&url.URL{Scheme: report.ObjectScheme, Host: id, Path: "/" + base}).String()
	file := artifact.NewFile(virtual, data, executable)
	// JSON token labels are not filename claims. Preserve this fact through
	// decoding, but restore actual member names when opening an archive.
	if o.role != report.DerivedRoleArchiveMember && (o.parent.file.GeneratedName() || descriptor.ExtractorID == jsonStringsExtractorID) {
		file = file.WithGeneratedName()
	}

	o.b.result.Files = append(o.b.result.Files, file)
	o.b.queue = append(o.b.queue, queued{file: file, depth: o.parent.depth + 1})

	o.b.result.Report.Objects = append(o.b.result.Report.Objects, report.DerivedObject{
		Role: o.role, ID: id, File: file.Metadata(), ParentPath: parent.Path, ParentSHA256: parent.SHA256,
		ExtractorID: descriptor.ExtractorID, ExtractorVersion: descriptor.Version, Depth: o.parent.depth + 1,
		Ordinal: ordinal, MemberName: name, ParentRange: region, CoordinateSpace: "derived-bytes",
	})
	if path.Base(name) == artifact.SkillManifest {
		o.b.result.Report.Skills = append(o.b.result.Report.Skills, virtual)
	}

	o.b.result.Report.Steps[o.step].Objects++
}

func (o *operation) text(name, text string, region *report.ByteRange) error {
	return o.emit(name, strings.NewReader(text), int64(len(text)), false, region)
}

func (o *operation) recordSkip(name, reason string, size int64, ordinal int) {
	o.skipped = true

	// Emit attempts originate from charged entries. Bound metadata as well in
	// case a future extractor violates that trusted contract.
	if len(o.b.result.Report.Skipped) >= o.b.limits.MaxEntries {
		o.issue("extraction_skipped_metadata_limit", "Additional unextracted objects could not be inventoried within the metadata budget.")
		return
	}

	step := &o.b.result.Report.Steps[o.step]
	if step.Status == report.OutcomeCompleted {
		step.Status = report.OutcomePartial
	}

	o.b.result.Report.Skipped = append(o.b.result.Report.Skipped, report.SkippedObject{
		Role: o.role, ParentPath: o.parent.file.Metadata().Path, ExtractorID: step.ExtractorID,
		MemberName: name, DeclaredSize: size, Ordinal: ordinal, Reason: reason,
	})
}

func (o *operation) skipMember(name, reason string, size int64) {
	ordinal := o.ordinal
	o.ordinal++
	o.recordSkip(name, reason, size, ordinal)
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	return r.r.Read(p)
}

// inheritedName preserves useful language suffixes without trusting directory
// components. Gzip file names are data, never extraction destinations.
func inheritedName(parent, suffix string) string {
	if u, err := url.Parse(parent); err == nil && u.Scheme == report.ObjectScheme {
		parent = u.Path
	}

	n := path.Base(parent)
	if strings.EqualFold(path.Ext(n), suffix) {
		n = n[:len(n)-len(suffix)]
	}

	if n == "" || n == "." {
		n = fallbackObjectName
	}

	return n
}

func extractionFailureReason(err error) string {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled"
	case errors.Is(err, errBudget):
		return "budget_exceeded"
	default:
		return "invalid_or_incomplete"
	}
}
