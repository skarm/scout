package report

// Outcome values describe individual work items, independently of run state,
// completeness and policy decisions. They remain untyped for existing string fields.
const (
	// OutcomeCompleted means the selected work finished.
	OutcomeCompleted = "completed"
	// OutcomePartial means only part of the selected work finished.
	OutcomePartial = "partial"
	// OutcomeFailed means the selected work failed.
	OutcomeFailed = "failed"
	// OutcomeCancelled means the work stopped after context cancellation.
	OutcomeCancelled = "cancelled"
	// OutcomeNotApplicable means the check does not apply to the selected input.
	OutcomeNotApplicable = "not_applicable"
	// OutcomeUnsupported means the selected capability is not implemented.
	OutcomeUnsupported = "unsupported"
	// OutcomeDisabled means optional work was explicitly not selected.
	OutcomeDisabled = "disabled"
	// OutcomeNotRun means planned work has not been executed.
	OutcomeNotRun = "not_run"
	// OutcomeMissing means a planned task has no recorded result.
	OutcomeMissing = "missing"
	// OutcomeCached uses a previously captured exact-coordinate result.
	OutcomeCached = "cached"
	// OutcomeDeadline means the work exceeded its execution deadline.
	OutcomeDeadline = "deadline"
)
