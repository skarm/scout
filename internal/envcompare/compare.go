// Package envcompare compares captured environments and renders the resulting report.
package envcompare

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/capture/envsnapshot"
	"github.com/skarm/scout/internal/capture/ingest"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

// Input pairs a snapshot with the materialized path of each root ID.
type Input struct {
	Snapshot envsnapshot.Snapshot
	Paths    map[string]string
}

type Options struct {
	Scan          scout.CompareOptions
	IncludeSource bool
}

type environmentRootChange struct {
	ID          string                       `json:"id"`
	Change      string                       `json:"change"`
	Report      report.Document              `json:"report"`
	Directories []environmentDirectoryChange `json:"directories,omitempty"`
	BeforePath  string                       `json:"before_path,omitempty"`
	AfterPath   string                       `json:"after_path,omitempty"`
	Content     []snapshotContentChange      `json:"content_changes,omitempty"`
}

type environmentDirectoryChange struct {
	Path   string `json:"path"`
	Change string `json:"change"`
}

// ComparisonSchema identifies the environment comparison report format.
const ComparisonSchema = "scout.environment-comparison/v1"

// Comparison is the versioned environment comparison report.
type Comparison struct {
	Schema              string                       `json:"schema"`
	Before              string                       `json:"before_sha256"`
	After               string                       `json:"after_sha256"`
	Decision            report.Decision              `json:"decision"`
	Code                int                          `json:"exit_code"`
	Roots               []environmentRootChange      `json:"roots"`
	Environment         *report.Document             `json:"environment,omitempty"`
	PreviousEnvironment *report.Document             `json:"previous_environment,omitempty"`
	Relationships       environmentRelationshipDelta `json:"relationships"`
}

// NamedTargets builds scan targets in stable root ID order.
func NamedTargets(paths map[string]string) []scout.Target {
	ids := slices.Sorted(maps.Keys(paths))

	targets := make([]scout.Target, 0, len(ids))
	for _, id := range ids {
		targets = append(targets, scout.Path(paths[id]))
	}

	return targets
}

func sortedUnion[A, B any](a map[string]A, b map[string]B) []string {
	keys := make([]string, 0, len(a))
	for key := range a {
		keys = append(keys, key)
	}

	for key := range b {
		if _, exists := a[key]; !exists {
			keys = append(keys, key)
		}
	}

	slices.Sort(keys)

	return keys
}

// Compare rescans both snapshots with the current scanner and policy, and
// computes their root, relationship and content changes.
func Compare(ctx context.Context, scanner *scout.Scanner, gate *policy.Gate, previousInput, candidateInput Input, options Options) (Comparison, error) {
	before, after := previousInput.Snapshot, candidateInput.Snapshot
	old, current := previousInput.Paths, candidateInput.Paths
	ctx = ingest.WithStableInputs(ctx, old, current)

	result := Comparison{Schema: ComparisonSchema, Before: before.Digest, After: after.Digest, Decision: report.Allow, Roots: []environmentRootChange{}}

	for _, id := range sortedUnion(old, current) {
		previous, candidate := old[id], current[id]
		change := report.SnapshotChangeUnchanged

		var run report.Run

		switch {
		case previous == "":
			change = report.SnapshotChangeAdded
			run, _ = scanner.Scan(ctx, scout.Path(candidate))
		case candidate == "":
			change = report.SnapshotChangeRemoved
			run, _ = scanner.Scan(ctx, scout.Path(previous))
		default:
			run, _ = scanner.Compare(ctx, scout.Path(previous), scout.Path(candidate), options.Scan)
		}

		prepared, err := report.Prepare(report.NewDocument(run, gate.Evaluate(run, time.Now().UTC())))
		if err != nil {
			return result, errors.New("environment comparison did not produce a valid report")
		}

		priorRoot, nextRoot := before.Root(id), after.Root(id)
		if change == report.SnapshotChangeUnchanged && !priorRoot.SameContent(nextRoot) {
			change = report.SnapshotChangeModified
		}

		if change == report.SnapshotChangeRemoved {
			// Findings in removed content are historical evidence, not candidate blockers.
			if prepared.State() != report.RunComplete {
				result.Code = 2
			}
		} else {
			result.addDecision(prepared)
		}

		root := environmentRootChange{ID: id, Change: change, Report: prepared.Snapshot()}
		if change != report.SnapshotChangeUnchanged {
			root.Directories = directoryChanges(priorRoot, nextRoot)

			if result.Decision == report.Allow {
				result.Decision = report.Review
			}

			result.Code = max(1, result.Code)
		}

		result.Roots = append(result.Roots, root)
	}

	previous, err := scanSnapshotEnvironment(ctx, scanner, gate, old)
	if err != nil {
		return result, err
	}

	next, err := scanSnapshotEnvironment(ctx, scanner, gate, current)
	if err != nil {
		return result, err
	}

	if previous.Valid() {
		doc := previous.Snapshot()
		result.PreviousEnvironment = &doc
	}

	if next.Valid() {
		doc := next.Snapshot()
		result.Environment = &doc
		result.addDecision(next)
	}

	result.Relationships = compareRelationships(result.PreviousEnvironment, result.Environment, old, current, options.Scan.MaxChanges)
	if result.Relationships.Completeness != report.Complete {
		result.Code = 2
		if result.Decision == report.Allow {
			result.Decision = report.Review
		}
	}

	result.describeContent(before, after, options.IncludeSource)

	return result, nil
}

func (r *Comparison) addDecision(p report.PreparedDocument) {
	r.Code = max(r.Code, policy.PreparedCode(p))
	if p.Decision() == report.Block || r.Decision == report.Allow && p.Decision() == report.Review {
		r.Decision = p.Decision()
	}
}

func directoryChanges(before, after envsnapshot.Root) []environmentDirectoryChange {
	directories := func(root envsnapshot.Root) map[string]struct{} {
		paths := map[string]struct{}{}

		for _, entry := range root.Entries {
			if entry.Directory {
				paths[entry.Path] = struct{}{}
			}
		}

		return paths
	}
	old, current := directories(before), directories(after)

	var changes []environmentDirectoryChange

	for _, path := range sortedUnion(old, current) {
		_, existed := old[path]
		_, exists := current[path]

		if existed == exists {
			continue
		}

		change := report.SnapshotChangeAdded
		if !exists {
			change = report.SnapshotChangeRemoved
		}

		changes = append(changes, environmentDirectoryChange{Path: path, Change: change})
	}

	return changes
}

func scanSnapshotEnvironment(ctx context.Context, scanner *scout.Scanner, gate *policy.Gate, paths map[string]string) (report.PreparedDocument, error) {
	if len(paths) == 0 {
		return report.PreparedDocument{}, nil
	}

	run, _ := scanner.ScanEnvironment(ctx, NamedTargets(paths))

	prepared, err := report.Prepare(report.NewDocument(run, gate.Evaluate(run, time.Now().UTC())))
	if err != nil {
		return report.PreparedDocument{}, errors.New("environment analysis did not produce a valid report")
	}

	return prepared, nil
}
