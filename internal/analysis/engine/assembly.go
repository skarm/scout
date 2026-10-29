package engine

import (
	"sort"

	"github.com/skarm/scout/internal/analysis/dependencies"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/harness"
	"github.com/skarm/scout/internal/analysis/languages/golang"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/analysis/metadata"
	"github.com/skarm/scout/internal/analysis/semantic"
	"github.com/skarm/scout/internal/capture/extract"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
)

func (run *execution) buildAnalysis() {
	run.analysis = report.Analysis{
		Knowledge:      knowledge.Inventory(),
		SchemaVersion:  report.AnalysisSchema,
		EngineVersion:  run.options.Engine.Version,
		RulepackDigest: run.options.Engine.RulepackDigest,
		Dependencies:   dependencies.Collect(run.ctx, run.documents),
		Metadata:       metadata.Collect(run.ctx, run.documents, run.options.Harness.Host),
		Components:     run.graph,
		Profile:        run.options.Profile,
		Artifact:       run.snapshot.Metadata(),
		Limits:         run.options.Limits,
		Extraction:     run.expanded.Report,
		Rules:          report.CloneRules(run.engine.rules),
		AnalysisLimits: report.AnalysisLimits{
			GoFlowOperations:     golang.MaxGoFlowOperations,
			GoFlowBindings:       golang.MaxGoFlowBindings,
			AgentJSONBytes:       jsonconfig.MaxBytes,
			AgentJSONNodes:       jsonconfig.MaxNodes,
			AgentJSONDepth:       jsonconfig.MaxDepth,
			AgentJSONScanBytes:   parse.MaxScanBytes,
			ShellUnitBytes:       shellsyntax.MaxBytes,
			ShellScanBytes:       parse.MaxScanBytes,
			ShellParserDepth:     shellsyntax.MaxDepth,
			ShellParserNodes:     shellsyntax.MaxNodes,
			ShellOperations:      shell.MaxShellOperations,
			ShellBindings:        shell.MaxShellBindings,
			ShellTraceTransforms: shell.MaxShellTraceSteps,
			JSONNestingDepth:     extract.MaxJSONDepth,
			DocumentRegions:      document.MaxRegions,
			SourceSegments:       document.MaxSourceSegments,
			UnitsPerFile:         document.MaxRegions,
			EmbeddedUnitBytes:    document.MaxUnitBytes,
			GoUnitBytes:          document.MaxUnitBytes,
			GoScanBytes:          document.MaxScanBytes,
			ConstantOperations:   golang.MaxConstantOperations,
			ConstantStringBytes:  golang.MaxStaticStringBytes,
		},
		Findings:    []report.Finding{},
		Diagnostics: append(append([]report.Diagnostic{}, run.snapshot.Diagnostics()...), run.expanded.Diagnostics...),
		Coverage: report.Coverage{
			Completeness:    report.Complete,
			CapturedFiles:   run.capturedCount,
			AnalyzedObjects: len(run.files),
			Checks:          []report.Check{},
		},
		Limitations: []string{
			"Skills and harness plugin static MVP: instruction signals, selected agent/MCP JSON configuration risks, and supporting Go/Shell checks; not a general SAST or install attestation.",
			"Versioned Claude/Codex layout subsets, no runtime-loader compatibility claim. Optional semantic review is advisory; install attestation is not implemented.",
			"All captured byte streams receive raw literal checks. NUL, invalid UTF-8, hidden paths and names do not exempt content.",
			"Language/signature hints are non-authoritative. Go AST, bounded SQL tokens and Shell syntax are built in. Native builds include JavaScript/TypeScript Tree-sitter syntax and bounded local flow; core builds retain explicit gaps. Optional Python syntax uses Tree-sitter and a limited analysis IR, not CPython AST. PowerShell has no AST backend.",
			"Markdown is one embedded container, not the scan boundary. Its envelope parser is not full CommonMark; optional real YAML/TOML parsers preserve explicitly stated limitations.",
			"Bounded ZIP32/GZIP/basic-TAR, PNG text metadata, JSON string tokens, BOM UTF-16 and selected Base64 extraction; originals are retained. No PDF/Office semantics, OCR, pixel/steganographic analysis or arbitrary encodings.",
			"Derived findings use virtual object coordinates, not fabricated offsets inside compressed parents. Provenance links are in the extraction graph.",
			"Shell coverage is a documented subset, NOT complete POSIX/Bash. Optional Python analysis remains bounded intra-scope. No general cross-file/type analysis, MCP execution or universal Unicode normalization.",
			"Agent configuration findings describe supported declarations, not effective host permissions. A pinned package version is not verified integrity or absence of vulnerabilities. YAML/TOML syntax requires explicit parser configuration; effective loader precedence and all host versions remain unverified.",
			"Surface hints and Markdown fences never grant trust or suppress findings. Literal examples and negations can require review.",
			"Source excerpts and credential values are omitted; file paths and content hashes may still be sensitive.",
			"Capture is immutable after reading but is not an atomic filesystem snapshot; mounts, hard links and hostile same-user writers require external isolation.",
		},
	}
	if run.analysis.Metadata.Completeness != report.Complete {
		run.analysis.Diagnostics = append(run.analysis.Diagnostics, report.Diagnostic{
			Code:         "metadata_contract_partial",
			Message:      "Metadata syntax/schema review is incomplete; see metadata files and their issue codes.",
			AffectsScope: true,
		})
	}

	for _, issue := range run.graph.Issues {
		run.analysis.Diagnostics = append(run.analysis.Diagnostics, report.Diagnostic{
			Code:         issue.Code,
			Path:         issue.Path,
			Message:      "Harness component interpretation is incomplete; see component graph for the bounded declaration and its status.",
			AffectsScope: true,
		})
	}

	for i, outcome := range run.results {
		run.ledger.CompleteAnalyzer(run.engine.rules[i].ID, run.inputs, outcome.fileChecks)
	}
}

func (run *execution) complete() (report.Analysis, error) {
	r := &run.analysis
	if !run.snapshot.Complete() {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
			Code:         "capture_incomplete",
			Message:      "Capture did not read every selected input.",
			AffectsScope: true,
		})
	}

	run.fileIndex = initializeFileCoverage(r, run.documents)

	return run.finalize()
}

func (run *execution) finalize() (report.Analysis, error) {
	r := &run.analysis
	for _, o := range run.results {
		for i, check := range o.fileChecks {
			fc := &r.Coverage.Files[run.fileIndex[run.documents[i].Artifact().Metadata().Path]]

			fc.Checks = append(fc.Checks, check)
			if check.Status != report.OutcomeCompleted && check.Status != report.OutcomeNotApplicable {
				fc.Gaps = append(fc.Gaps, check.AnalyzerID+":"+check.Status)
			}
		}

		r.Coverage.Checks = append(r.Coverage.Checks, o.check)
		r.Diagnostics = append(r.Diagnostics, o.diagnostics...)
	}

	vulnerabilities := run.options.Vulnerabilities
	if run.options.VulnerabilityQuota != nil {
		vulnerabilities.MaxRequests = *run.options.VulnerabilityQuota
	}

	applyVulnerabilities(run.ctx, r, run.documents, vulnerabilities, run.collector)
	applySignatures(run.ctx, r, run.documents, run.engine.signatures, run.options.SignatureRuntime, run.collector, run.fileIndex)
	run.collector.finish(r, run.fileIndex)

	return run.finish()
}

func (run *execution) finish() (report.Analysis, error) {
	r := &run.analysis
	if harness.Enrich(r.Findings, r.Components) {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
			Code:         "finding_context_limit",
			Message:      "Additional component contexts exceeded the per-finding budget.",
			AffectsScope: true,
		})
	}

	sortFileCoverage(r.Coverage.Files)

	r.Semantic = semantic.RunWithin(run.ctx, run.files, r.Components, r.Findings, r.Artifact.SnapshotSHA256, run.options.Semantic, run.options.Provider, r.Extraction, run.options.SemanticQuota)
	if run.options.Semantic.Enabled {
		semanticFileCoverage(r)
		run.ledger.CompleteSemantic(r.Semantic.Completeness)

		if r.Semantic.Completeness != report.Complete {
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
				Code:         "semantic_incomplete",
				Message:      "Requested semantic tasks failed, were limited, or lack context; source-free task outcomes are in the semantic report.",
				AffectsScope: true,
			})
		}

		r.Limitations = append(r.Limitations, "Semantic responses are evidence-linked model opinions, not proof of correctness. They cannot erase static findings; proposals require review rather than automatic trust. Only text is sent, with explicit consent and no automatic secret redaction.", "Semantic context and request budgets are byte-based, not a guarantee of provider token fit or cost. A complete semantic task means a valid response was received, not that all threats were detected.")
	}

	r.Validation = run.ledger.Finalize()
	if r.Validation.Completeness != report.Complete {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
			Code:         "validation_plan_incomplete",
			Message:      "Required planned tasks are unsupported, failed, missing or limited; no automatic admission.",
			AffectsScope: true,
		})
	}

	if run.ctx.Err() != nil {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
			Code:         "cancelled",
			Message:      "Scan was cancelled or timed out.",
			AffectsScope: true,
		})
	}

	sort.Slice(r.Rules, func(i, j int) bool { return r.Rules[i].ID < r.Rules[j].ID })
	sort.Slice(r.Coverage.Checks, func(i, j int) bool { return r.Coverage.Checks[i].AnalyzerID < r.Coverage.Checks[j].AnalyzerID })
	sort.Slice(r.Diagnostics, func(i, j int) bool {
		a, b := r.Diagnostics[i], r.Diagnostics[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}

		if a.Code != b.Code {
			return a.Code < b.Code
		}

		return a.Message < b.Message
	})
	reduceCoverage(run.ctx, r)

	return *r, run.ctx.Err()
}
