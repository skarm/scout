package scout

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/analysis/bundle"
	"github.com/skarm/scout/internal/analysis/engine"
	"github.com/skarm/scout/internal/analysis/environment"
	"github.com/skarm/scout/internal/analysis/semantic"
	"github.com/skarm/scout/internal/analysis/update"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/capture/external"
	"github.com/skarm/scout/internal/capture/ingest"
	"github.com/skarm/scout/internal/syntax/filetype"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

// Scan inspects one target and returns a sealed run. ErrIncomplete preserves
// available observations; preflight failures may return no run.
func (s *Scanner) Scan(ctx context.Context, target Target) (report.Run, error) {
	return s.ScanMany(ctx, []Target{target})
}

// ScanMany scans targets concurrently and retains results in input order.
// Targets share aggregate budgets. ErrIncomplete preserves the available run
// and observations.
func (s *Scanner) ScanMany(ctx context.Context, targets []Target) (report.Run, error) {
	return s.execute(ctx, targets, report.ScanOperation, CompareOptions{})
}

// Compare rescans before and after under the same configuration and returns
// both analyses with a bounded delta. Both targets must be local paths.
func (s *Scanner) Compare(ctx context.Context, before, after Target, options CompareOptions) (report.Run, error) {
	if err := (report.UpdateOptions{MaxChanges: options.MaxChanges}).Validate(); err != nil {
		return report.Run{}, &Error{Code: "invalid_comparison_options", Cause: ErrInvalidInput}
	}

	if !before.IsLocal() || !after.IsLocal() {
		return report.Run{}, &Error{Code: "comparison_requires_local_inputs", Cause: ErrInvalidInput}
	}

	return s.execute(ctx, []Target{before, after}, report.CompareOperation, options)
}

func (s *Scanner) execute(ctx context.Context, targets []Target, operation report.Operation, comparison CompareOptions) (report.Run, error) {
	return s.executeWithin(ctx, targets, operation, comparison, false)
}

func (s *Scanner) executeWithin(ctx context.Context, targets []Target, operation report.Operation, comparison CompareOptions, joint bool) (report.Run, error) {
	if err := s.validateTargets(ctx, targets); err != nil {
		return report.Run{}, err
	}

	if err := s.admit(); err != nil {
		return report.Run{}, err
	}
	defer s.active.Done()

	call, cancel := context.WithTimeout(ctx, s.options.Limits.Timeout)
	defer cancel()

	var surfaces []bundle.Surface
	if joint {
		surfaces = make([]bundle.Surface, len(targets))
	}

	run, targetErrors := s.inspectTargets(call, targets, operation, surfaces)
	consolidateTargets(&run, targetErrors, s.options.Limits.Retention.MaxFindings)

	if joint {
		observations := environment.Build(call, surfaces, run.Targets, s.options.Limits.Retention.MaxFindings, s.options.Limits.Analysis.MaxOperations/8)

		run.Environment = &observations
		if observations.Completeness != report.Complete {
			if run.State != report.RunCancelled {
				run.State = report.RunIncomplete
			}

			run.Problems = append(run.Problems, report.Problem{Code: "environment_incomplete", Phase: "environment", Message: "Selected environment relationships were not completely inspected."})
			targetErrors = append(targetErrors, ErrIncomplete)
		}
	}

	if operation == report.CompareOperation {
		targetErrors = append(targetErrors, buildComparison(call, &run, comparison))
	}

	return sealExecution(call, run, targetErrors)
}

// Validation is complete before admission or any caller-owned reader is read.
func (s *Scanner) validateTargets(ctx context.Context, targets []Target) error {
	if s == nil {
		return ErrClosed
	}

	if ctx == nil || len(targets) == 0 || len(targets) > 32 {
		return &Error{Code: "invalid_request", Cause: ErrInvalidInput}
	}

	for _, target := range targets {
		if err := target.validate(); err != nil {
			return &Error{Code: "invalid_target", Cause: errors.Join(ErrInvalidInput, err)}
		}

		if target.kind == readerTarget {
			if err := ingest.ValidatePath(target.name, s.options.Limits.Capture.MaxPathBytes, s.options.Limits.Capture.MaxDepth); err != nil {
				return &Error{Code: "invalid_reader_name", Cause: errors.Join(ErrInvalidInput, err)}
			}
		}
	}

	return nil
}

// Workers own disjoint result positions; completion order cannot reorder them.
// One slot pool bounds analyzer execution across every target in this run.
func (s *Scanner) inspectTargets(ctx context.Context, targets []Target, operation report.Operation, surfaces []bundle.Surface) (report.Run, []error) {
	run := report.Run{
		Operation: operation,
		State:     report.RunComplete,
		Engine:    s.identity,
		Plan:      s.InspectionPlan(),
		Targets:   make([]report.TargetResult, len(targets)),
		Problems:  []report.Problem{},
	}
	errorsByTarget := make([]error, len(targets))
	slots := make(chan struct{}, s.options.Concurrency.Workers)

	jobs := make(chan int, len(targets))
	for i := range targets {
		jobs <- i
	}

	close(jobs)

	var workers sync.WaitGroup
	for w := 0; w < min(len(targets), s.options.Concurrency.Targets); w++ {
		workers.Go(func() {
			for i := range jobs {
				options := s.targetOptions(i, len(targets), operation)

				var surface *bundle.Surface
				if surfaces != nil {
					surface = &surfaces[i]
					options.Limits.Analysis.MaxOperations -= (options.Limits.Analysis.MaxOperations + 7) / 8
				}

				result, err := s.scanTarget(ctx, targets[i], i, options, slots, surface)
				if operation == report.CompareOperation {
					if i == 0 {
						result.Role = "before"
					} else {
						result.Role = "after"
					}
				}

				run.Targets[i], errorsByTarget[i] = result, err
			}
		})
	}

	workers.Wait()

	return run, errorsByTarget
}

func (s *Scanner) targetOptions(index, count int, operation report.Operation) targetSettings {
	o := cloneOptions(s.options)

	if operation == report.CompareOperation {
		index = count - 1
	} // both sides receive the same conservative quota

	quota := targetQuota{index: index, count: count}
	quota.applyLimits(&o.Limits)

	if o.External != nil {
		o.External.MaxRequests = int(quota.allocate(int64(o.External.MaxRequests)))
		o.External.MaxBytes = quota.allocate(o.External.MaxBytes)
	}

	settings := targetSettings{Options: o}
	settings.allocateServices(quota)

	return settings
}

func (s *Scanner) scanTarget(ctx context.Context, target Target, index int, options targetSettings, slots chan struct{}, surface *bundle.Surface) (report.TargetResult, error) {
	result := report.TargetResult{
		ID:    fmt.Sprintf("target-%d", index),
		Index: index,
		Label: target.name,
		State: report.RunFailed,
	}
	if err := ctx.Err(); err != nil {
		result.State = report.RunCancelled
		return result, err
	}

	if !options.hasAnalysisBudget() {
		return result, ErrIncomplete
	}

	snapshot, source, captureErr := capture(ctx, target, options.Options)

	var closure *report.ExternalClosure

	if captureErr == nil && options.External != nil {
		if options.External.MaxRequests < 1 || options.External.MaxBytes < 1 {
			captureErr = errors.New("external traversal quota exhausted")
		} else {
			var externalErr error

			snapshot, closure, externalErr = external.Expand(ctx, snapshot, options.External.internal(), *options.Download, options.captureLimits())
			captureErr = errors.Join(captureErr, externalErr)
		}
	}

	engineOptions := s.engineOptions(options, slots)
	engineOptions.Environment = surface
	analysis, runErr := s.engine.Run(ctx, snapshot, engineOptions)

	analysis.External = closure
	if closure != nil {
		analysis.Limitations = append(analysis.Limitations, "External traversal covers bounded literal absolute source URLs on operator-approved origins. Dynamic URLs, package-manager resolution and references hidden in opaque containers are not a complete installation closure.")
	}

	s.describeAnalysis(&analysis, source, captureErr)
	result.Analysis = analysis
	result.State = targetState(ctx.Err(), captureErr, analysis.Coverage.Completeness)

	return result, errors.Join(captureErr, runErr)
}

func (s *Scanner) engineOptions(options targetSettings, slots chan struct{}) engine.RunOptions {
	settings := engine.RunOptions{
		Engine:             s.identity,
		Profile:            string(options.Profile),
		Limits:             options.captureLimits(),
		Extraction:         options.Limits.Extraction,
		Harness:            options.Harness,
		Vulnerabilities:    osv.DefaultOptions(),
		Semantic:           review.DefaultOptions(),
		SignatureRuntime:   s.signatures,
		Slots:              slots,
		MaxOperations:      options.Limits.Analysis.MaxOperations,
		MatchLimit:         options.Limits.Analysis.MaxMatchesPerRule,
		SemanticQuota:      options.semanticQuota,
		VulnerabilityQuota: options.vulnerabilityQuota,
	}

	if options.Vulnerabilities != nil {
		settings.Vulnerabilities = *options.Vulnerabilities
	}

	if options.Review != nil {
		settings.Semantic = options.Review.Settings
		settings.Provider = options.Review.Provider
	}

	return settings
}

func (s *Scanner) describeAnalysis(analysis *report.Analysis, source *fetch.Provenance, captureErr error) {
	analysis.Source = source
	analysis.Inspection = s.InspectionPlan()
	analysis.SchemaVersion = report.AnalysisSchema
	analysis.EngineVersion = s.identity.Version
	analysis.RulepackDigest = s.identity.RulepackDigest
	analysis.Profile = s.plan.Name

	if captureErr != nil {
		analysis.Coverage.Completeness = report.Failed
		analysis.Diagnostics = append(analysis.Diagnostics, report.Diagnostic{
			Code:         "ingest_failed",
			Message:      "Input capture failed; any obtained evidence is retained.",
			AffectsScope: true,
		})
	}
}

// Shared retention can make a formerly complete target incomplete. Collect
// target problems only after that reduction, retaining every sibling result.
func consolidateTargets(run *report.Run, targetErrors []error, findingsLimit int) {
	retainRunFindings(run, findingsLimit)

	for i, target := range run.Targets {
		if target.State != report.RunComplete {
			switch {
			case target.State == report.RunCancelled:
				run.State = report.RunCancelled
			case run.State != report.RunCancelled:
				run.State = report.RunIncomplete
			}

			run.Problems = append(run.Problems, report.Problem{
				Code:     problemCode(target.State),
				Phase:    "scan",
				TargetID: target.ID,
				Message:  "Target inspection did not complete.",
			})

			if targetErrors[i] == nil {
				targetErrors[i] = ErrIncomplete
			}
		}
	}
}

func buildComparison(ctx context.Context, run *report.Run, options CompareOptions) error {
	changes, err := update.Build(ctx, run.Targets[0].Analysis, run.Targets[1].Analysis, report.UpdateOptions{MaxChanges: options.MaxChanges})

	run.Comparison = &changes
	if err != nil || changes.Completeness != report.Complete {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			run.State = report.RunCancelled
		case run.State != report.RunCancelled:
			run.State = report.RunIncomplete
		}

		run.Problems = append(run.Problems, report.Problem{
			Code:    "comparison_incomplete",
			Phase:   "compare",
			Message: "Comparison did not complete.",
		})

		return errors.Join(ErrIncomplete, err)
	}

	return nil
}

func sealExecution(ctx context.Context, run report.Run, targetErrors []error) (report.Run, error) {
	sealed, err := report.SealRun(run)
	if err != nil {
		return run, &Error{Code: "invalid_execution_result", Cause: errors.Join(ErrIncomplete, err)}
	}
	// Observe cancellation once after finalization. State and returned error use
	// the same observation; a deadline expiring during hashing cannot become an
	// apparently complete, policy-allowing run with a context error beside it.
	contextErr := ctx.Err()
	if contextErr != nil && sealed.State != report.RunCancelled {
		run.State = report.RunCancelled
		run.Problems = append(run.Problems, report.Problem{
			Code:    "cancelled",
			Phase:   "finalize",
			Message: "Execution was cancelled during finalization.",
		})

		sealed, err = report.SealRun(run)
		if err != nil {
			return run, &Error{Code: "invalid_execution_result", Cause: errors.Join(ErrIncomplete, contextErr, err)}
		}
	}

	combined := errors.Join(errors.Join(targetErrors...), contextErr)
	if sealed.State != report.RunComplete {
		combined = errors.Join(ErrIncomplete, combined)
	}

	return sealed, combined
}

func problemCode(state report.State) string {
	switch state {
	case report.RunCancelled:
		return "cancelled"
	case report.RunFailed:
		return "capture_failed"
	default:
		return "inspection_incomplete"
	}
}

type targetQuota struct{ index, count int }

func (q targetQuota) allocate(total int64) int64 {
	share := total / int64(q.count)
	if int64(q.index) < total%int64(q.count) {
		share++
	}

	return share
}

func (q targetQuota) applyLimits(limits *Limits) {
	c := &limits.Capture
	c.MaxTotalBytes = min(c.MaxTotalBytes, q.allocate(limits.MaxCaptureBytes))
	c.MaxFileBytes = min(c.MaxFileBytes, c.MaxTotalBytes)
	c.MaxArchiveBytes = min(c.MaxArchiveBytes, c.MaxTotalBytes)
	c.MaxFiles = min(c.MaxFiles, int(q.allocate(int64(limits.MaxCaptureFiles))))
	c.MaxEntries = min(c.MaxEntries, int(q.allocate(int64(limits.MaxCaptureEntries))))
	e := &limits.Extraction
	e.MaxTotalBytes = min(e.MaxTotalBytes, q.allocate(limits.MaxExtractedBytes))
	e.MaxObjectBytes = min(e.MaxObjectBytes, e.MaxTotalBytes)
	//nolint:gosec // G115: Options.Validate bounds MaxOperations to 1..1<<40 before allocating target quotas.
	limits.Analysis.MaxOperations = uint64(q.allocate(int64(limits.Analysis.MaxOperations)))
}

type targetSettings struct {
	Options
	semanticQuota      *semantic.Quota
	vulnerabilityQuota *int
}

func (o *targetSettings) allocateServices(quota targetQuota) {
	requests := int(quota.allocate(int64(o.Limits.MaxServiceRequests)))

	services := 0
	if o.Review != nil {
		services++
	}

	if o.Vulnerabilities != nil {
		services++
	}

	if o.External != nil {
		services++
	}

	requests /= max(1, services)
	if o.External != nil {
		o.External.MaxRequests = min(o.External.MaxRequests, requests)
	}

	if o.Review != nil {
		o.semanticQuota = &semantic.Quota{
			Requests:   min(o.Review.Settings.MaxRequests, requests),
			InputBytes: int(quota.allocate(int64(o.Review.Settings.MaxInputBytes))),
		}
	}

	if o.Vulnerabilities != nil {
		v := min(o.Vulnerabilities.MaxRequests, requests)
		o.vulnerabilityQuota = &v
	}
}

func (o *targetSettings) hasAnalysisBudget() bool {
	return o.Limits.Capture.MaxFiles > 0 && o.Limits.Capture.MaxTotalBytes > 0 && o.Limits.Extraction.MaxTotalBytes > 0 && o.Limits.Analysis.MaxOperations > 0
}

func targetState(contextErr, captureErr error, completeness report.Completeness) report.State {
	switch {
	case contextErr != nil:
		return report.RunCancelled
	case captureErr != nil || completeness == report.Failed:
		return report.RunFailed
	case completeness != report.Complete:
		return report.RunIncomplete
	default:
		return report.RunComplete
	}
}

func capture(ctx context.Context, target Target, options Options) (artifact.Snapshot, *fetch.Provenance, error) {
	switch target.kind {
	case pathTarget:
		snapshot, err := ingest.Read(ctx, target.name, options.captureLimits())
		return snapshot, nil, err
	case readerTarget:
		return captureReader(ctx, target, options.Limits.Capture)
	case remoteTarget:
		return captureRemote(ctx, target, options)
	default:
		return artifact.Snapshot{}, nil, ErrInvalidInput
	}
}

func captureReader(ctx context.Context, target Target, c CaptureLimits) (artifact.Snapshot, *fetch.Provenance, error) {
	if err := ingest.ValidatePath(target.name, c.MaxPathBytes, c.MaxDepth); err != nil {
		return artifact.Snapshot{}, nil, err
	}

	limit := min(c.MaxTotalBytes, max(c.MaxFileBytes, c.MaxArchiveBytes))

	data, readErr := io.ReadAll(io.LimitReader(captureInput{ctx: ctx, input: target.input}, limit+1))

	if int64(len(data)) > limit {
		return artifact.Snapshot{}, nil, errors.New("input byte budget exceeded")
	}

	allowed := c.MaxFileBytes
	if filetype.Inspect(target.name, string(data), false).Category == "archive" {
		allowed = c.MaxArchiveBytes
	}

	if int64(len(data)) > allowed {
		return artifact.Snapshot{}, nil, errors.New("input file budget exceeded")
	}

	return artifact.New("memory", []artifact.File{artifact.NewFile(target.name, data, false)}, nil, nil, readErr == nil), nil, readErr
}

type captureInput struct {
	ctx   context.Context
	input ContextReader
}

func (r captureInput) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	n, err := r.input.ReadContext(r.ctx, p)
	if stopped := r.ctx.Err(); stopped != nil {
		return n, stopped
	}

	return n, err
}

func captureRemote(ctx context.Context, target Target, options Options) (artifact.Snapshot, *fetch.Provenance, error) {
	if options.Download == nil || !options.Download.Enabled {
		return artifact.Snapshot{}, nil, errors.New("download permission required")
	}

	download := *options.Download
	download.Revision = target.pin.Revision
	download.ExpectedSHA256 = target.pin.SHA256
	download.MaxBytes = min(download.MaxBytes, options.Limits.Capture.MaxArchiveBytes, options.Limits.Capture.MaxTotalBytes)

	payload, err := fetch.Get(ctx, target.name, download)
	if err != nil {
		return artifact.Snapshot{}, &payload.Source, err
	}

	if int64(len(payload.Data)) > options.Limits.Capture.MaxFileBytes && filetype.Inspect(payload.Name, string(payload.Data), false).Category != "archive" {
		payload.Source.Status = "rejected_file_budget"
		return artifact.Snapshot{}, &payload.Source, errors.New("remote file budget exceeded")
	}

	return artifact.New("remote", []artifact.File{artifact.NewFile(payload.Name, payload.Data, false)}, nil, nil, true), &payload.Source, nil
}
