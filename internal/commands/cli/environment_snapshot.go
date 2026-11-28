package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/capture/envsnapshot"
	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/internal/envcompare"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

const (
	flagCandidate     = "candidate"
	flagEmpty         = "empty"
	flagRoot          = "root"
	flagSaveCandidate = "save-candidate"
	flagSourceDiff    = "source-diff"
)

const (
	maxSavedJSONNodes = 4_000_000
	maxSavedJSONDepth = 64
)

type environmentCheckpoint struct {
	Snapshot   envsnapshot.Snapshot `json:"snapshot"`
	Inspection report.Document      `json:"inspection"`
	Discovery  *checkpointDiscovery `json:"discovery,omitempty"`
}

func environmentSnapshotCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "inspect" {
		return inspectEnvironmentSnapshot(ctx, args[1:], stdout, stderr)
	}

	if len(args) == 0 || args[0] != "create" && args[0] != "compare" {
		return usageError(stderr, "snapshot requires create, compare or inspect")
	}

	mode := args[0]

	r, snapshotPath, inputs, err := parseSnapshotRequest(mode, args[1:], stderr, "", nil)
	if err != nil {
		return requestError(err, stderr)
	}

	return executeEnvironmentSnapshot(ctx, mode, r, snapshotPath, inputs, nil, stdout, stderr)
}

func executeEnvironmentSnapshot(ctx context.Context, mode string, r request, snapshotPath string, inputs map[string]string, selection *checkpointDiscovery, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(ctx, r.settings.Scanner.Limits.Timeout)
	defer cancel()

	before, err := resolveSnapshotSelection(ctx, mode, snapshotPath, &r, inputs, selection)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	checkpointOutput, outputs, err := r.snapshotDestinations(mode, snapshotPath)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if err = r.loadTrusted(ctx); err != nil {
		return usageError(stderr, err.Error())
	}

	if r.snapshotSave != "" && len(before.inputs) == 0 {
		return usageError(stderr, "--save-candidate requires at least one current root")
	}

	if before.candidate == nil {
		captured, err := envsnapshot.Capture(ctx, before.inputs)
		if err != nil {
			return r.publishCaptureFailure(ctx, mode, outputs, err, stdout, stderr)
		}

		before.candidate = &captured
	}

	return r.inspectSnapshotPair(ctx, mode, before, checkpointOutput, outputs, stdout, stderr)
}

func (r *request) snapshotDestinations(mode, snapshotPath string) (string, []destination, error) {
	var checkpointOutput string

	if mode == "create" {
		checkpointOutput = snapshotPath
	} else {
		r.publicationInputs = append(r.publicationInputs, snapshotPath)
		checkpointOutput = r.snapshotSave
	}

	if checkpointOutput != "" {
		resolved, err := output.Validate(checkpointOutput, r.protectedInputs())
		if err != nil {
			return "", nil, fmt.Errorf("invalid snapshot destination: %w", err)
		}

		if _, err = os.Lstat(resolved); !errors.Is(err, os.ErrNotExist) {
			return "", nil, errors.New("snapshot destination must be a new file")
		}

		checkpointOutput = resolved
		r.publicationInputs = append(r.publicationInputs, checkpointOutput)
	}

	outputs, err := r.outputs()

	return checkpointOutput, outputs, err
}

func (r *request) inspectSnapshotPair(ctx context.Context, mode string, selected snapshotSelection, checkpointOutput string, outputs []destination, stdout, stderr io.Writer) int {
	current := *selected.candidate

	temporary, err := os.MkdirTemp("", "scout-environment-*")
	if err != nil {
		return usageError(stderr, "cannot create private environment workspace")
	}

	defer func() { _ = os.RemoveAll(temporary) }()

	currentDir := filepath.Join(temporary, "current")
	if err = os.Mkdir(currentDir, 0o700); err != nil {
		return 2
	}

	currentPaths, err := current.Materialize(ctx, currentDir)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	gate, err := policy.New(r.settings.Policy)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	scanner, err := scout.New(ctx, r.settings.Scanner)
	if err != nil {
		return usageError(stderr, "scanner initialization failed: "+err.Error())
	}

	defer func() { _ = scanner.Close() }()

	if mode == "create" {
		return r.createEnvironmentSnapshot(ctx, checkpointOutput, current, currentPaths, scanner, gate, outputs, selected.selection, stdout, stderr)
	}

	previousDir := filepath.Join(temporary, "previous")
	if err = os.Mkdir(previousDir, 0o700); err != nil {
		return 2
	}

	previousPaths, err := selected.checkpoint.Snapshot.Materialize(ctx, previousDir)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	result, err := envcompare.Compare(ctx, scanner, gate,
		envcompare.Input{Snapshot: selected.checkpoint.Snapshot, Paths: previousPaths},
		envcompare.Input{Snapshot: current, Paths: currentPaths},
		envcompare.Options{Scan: r.compare, IncludeSource: r.snapshotSourceDiff},
	)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if checkpointOutput != "" {
		// Reuse the joint candidate inspection from this run and the bytes that
		// produced it. No rediscovery, filesystem capture or rescan is needed.
		if err := writeEnvironmentCheckpoint(ctx, checkpointOutput, environmentCheckpoint{
			Snapshot: current, Inspection: *result.Environment, Discovery: selected.selection,
		}); err != nil {
			return usageError(stderr, err.Error())
		}
	}

	publish, stop := context.WithTimeout(context.WithoutCancel(ctx), reportPublicationTimeout)
	defer stop()

	if err = r.publishOutputs(publish, outputs, stdout, result.Write); err != nil {
		return usageError(stderr, "cannot publish environment comparison")
	}

	return result.Code
}

func readEnvironmentCheckpoint(path string, inputs []string) (environmentCheckpoint, error) {
	var checkpoint environmentCheckpoint

	data, err := readTrusted(path, inputs, envsnapshot.MaxBytes)
	if err != nil {
		return checkpoint, fmt.Errorf("cannot read environment snapshot %q: %w", path, err)
	}

	err = decodeCheckpoint(data, &checkpoint)

	return checkpoint, err
}

func decodeCheckpoint(data []byte, dst *environmentCheckpoint) error {
	// Token validation prevents duplicate keys from silently replacing evidence.
	if err := uniqueJSON(data); err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid environment snapshot JSON")
	}

	if err := dst.Snapshot.Validate(); err != nil {
		return err
	}

	if len(dst.Snapshot.Roots) == 0 {
		return errors.New("saved environment must contain at least one root")
	}

	if err := dst.Inspection.Validate(); err != nil {
		return errors.New("invalid saved inspection report")
	}

	if dst.Inspection.Operation != report.ScanOperation || dst.Inspection.Run.Environment == nil || len(dst.Inspection.Run.Targets) != len(dst.Snapshot.Roots) {
		return errors.New("saved inspection does not describe an environment scan")
	}

	for i, target := range dst.Inspection.Run.Targets {
		root := dst.Snapshot.Roots[i]
		if !inspectionMatchesRoot(target.Analysis.Artifact, root) {
			return fmt.Errorf("saved inspection does not match captured files for root %q", root.ID)
		}
	}

	return nil
}

// A partial inspection may lack files, but every file it says it captured
// must correspond to the stored bytes in its target's root.
func inspectionMatchesRoot(inventory report.Artifact, root envsnapshot.Root) bool {
	kind := "file"
	if root.Directory {
		kind = "directory"
	}

	if inventory.SourceKind != "" && inventory.SourceKind != kind {
		return false
	}

	files := make(map[string]envsnapshot.Entry, len(root.Entries))
	for _, entry := range root.Entries {
		if !entry.Directory {
			files[entry.Path] = entry
		}
	}

	for _, file := range inventory.Files {
		if file.Status != report.CaptureCaptured {
			continue
		}

		entry, ok := files[file.Path]
		if !ok || file.SHA256 != entry.SHA256 || file.Size != int64(len(entry.Data)) || file.Executable != (entry.Executable != 0) {
			return false
		}

		delete(files, file.Path)
	}

	return !inventory.InventoryComplete || len(files) == 0
}

func uniqueJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	nodes := 0

	var value func(int) error

	value = func(depth int) error {
		nodes++
		if depth > maxSavedJSONDepth || nodes > maxSavedJSONNodes {
			return errors.New("saved JSON structural limit")
		}

		token, err := dec.Token()
		if err != nil {
			return err
		}

		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}

		if delim != '{' && delim != '[' {
			return errors.New("unexpected JSON delimiter")
		}

		keys := map[string]bool{}

		for dec.More() {
			if delim == '{' {
				key, err := dec.Token()
				if err != nil {
					return err
				}

				name, ok := key.(string)

				name = strings.ToLower(name)
				if !ok || keys[name] {
					return errors.New("duplicate saved JSON key")
				}

				keys[name] = true
			}

			if err := value(depth + 1); err != nil {
				return err
			}
		}

		_, err = dec.Token()

		return err
	}
	if err := value(0); err != nil {
		return err
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing saved JSON")
	}

	return nil
}

func parseSnapshotRequest(mode string, args []string, stderr io.Writer, snapshotPath string, discovered map[string]string) (request, string, map[string]string, error) {
	var (
		candidate string
		save      string
		roots     repeated
		empty     bool
		diff      bool
	)

	r, err := resolveRequest("snapshot "+mode, args, stderr, func(fs *flag.FlagSet) {
		if discovered != nil {
			return
		}

		fs.StringVar(&snapshotPath, flagSnapshot, "", "required environment snapshot path (create never replaces it)")
		fs.Var(&roots, flagRoot, "named local root ID=PATH; repeat for the complete selected environment")

		if mode == "compare" {
			fs.BoolVar(&empty, flagEmpty, false, "explicitly compare against an empty environment")
			fs.BoolVar(&diff, flagSourceDiff, false, "include bounded source excerpts in change reports; may contain secrets")
			fs.StringVar(&candidate, flagCandidate, "", "compare with a second saved environment snapshot")
			fs.StringVar(&save, flagSaveCandidate, "", "save the checked current bytes to a new snapshot file")
		}
	})
	if err != nil {
		return r, "", nil, err
	}

	if snapshotPath == "" || len(r.targets) != 0 {
		return r, "", nil, errors.New("snapshot requires --snapshot and uses named local --root inputs")
	}

	inputs := discovered
	if inputs == nil {
		inputs, err = parseSnapshotRoots(&r, roots)
		if err != nil {
			return r, "", nil, err
		}
	} else {
		for _, id := range slices.Sorted(maps.Keys(inputs)) {
			r.targets = append(r.targets, inputs[id])
		}
	}

	if len(inputs) > scout.MaxScanTargets || len(inputs) == 0 && mode != "compare" || empty && len(inputs) != 0 {
		return r, "", nil, fmt.Errorf("select 1..%d named roots for creation; compare can reuse the saved selection", scout.MaxScanTargets)
	}

	if candidate != "" && (len(inputs) != 0 || empty || save != "") {
		return r, "", nil, errors.New("--candidate cannot be combined with --root, --empty or --save-candidate")
	}

	if save != "" && empty {
		return r, "", nil, errors.New("--save-candidate requires at least one current root")
	}

	if mode == "compare" {
		if err := (report.UpdateOptions{MaxChanges: r.compare.MaxChanges}).Validate(); err != nil {
			return r, "", nil, err
		}
	}

	r.snapshotCandidate = candidate
	r.snapshotSave = save
	r.snapshotEmpty = empty
	r.snapshotSourceDiff = diff

	return r, snapshotPath, inputs, nil
}

func parseSnapshotRoots(r *request, roots []string) (map[string]string, error) {
	inputs := map[string]string{}

	for _, entry := range roots {
		id, path, ok := strings.Cut(entry, "=")
		if !ok || !envsnapshot.ValidID(id) || path == "" {
			return nil, errors.New("root must be ID=PATH with a portable lowercase ID")
		}

		if _, exists := inputs[id]; exists {
			return nil, errors.New("duplicate root ID")
		}

		inputs[id] = path
		r.targets = append(r.targets, path)
	}

	return inputs, nil
}

func (r *request) createEnvironmentSnapshot(ctx context.Context, snapshotPath string, current envsnapshot.Snapshot, currentPaths map[string]string, scanner *scout.Scanner, gate *policy.Gate, outputs []destination, selection *checkpointDiscovery, stdout, stderr io.Writer) int {
	run, scanErr := scanner.ScanEnvironment(ctx, envcompare.NamedTargets(currentPaths))
	if scanErr != nil {
		_, _ = fmt.Fprintln(stderr, "inspection incomplete:", scanErr)
	}

	if run.Digest == "" {
		return 2
	}

	prepared, prepErr := report.Prepare(report.NewDocument(run, gate.Evaluate(run, time.Now().UTC())))
	if prepErr != nil {
		return usageError(stderr, "cannot prepare snapshot inspection")
	}

	if err := writeEnvironmentCheckpoint(ctx, snapshotPath, environmentCheckpoint{
		Snapshot: current, Inspection: prepared.Snapshot(), Discovery: selection,
	}); err != nil {
		return usageError(stderr, err.Error())
	}

	publish, stop := context.WithTimeout(context.WithoutCancel(ctx), reportPublicationTimeout)
	defer stop()

	if err := r.publish(publish, outputs, prepared, stdout); err != nil {
		_, _ = fmt.Fprintln(stderr, "report publication failed:", err)
		return 2
	}

	return policy.PreparedCode(prepared)
}

func writeEnvironmentCheckpoint(ctx context.Context, path string, checkpoint environmentCheckpoint) error {
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return fmt.Errorf("cannot encode environment snapshot: %w", err)
	}

	if len(data) > envsnapshot.MaxBytes {
		return fmt.Errorf("snapshot output is %d bytes, exceeding the %d-byte limit", len(data), envsnapshot.MaxBytes)
	}

	// Use the same reader for validation before publishing either kind of snapshot.
	var reopened environmentCheckpoint
	if err := decodeCheckpoint(data, &reopened); err != nil {
		return fmt.Errorf("generated snapshot cannot be reopened: %w", err)
	}

	publish, stop := context.WithTimeout(context.WithoutCancel(ctx), reportPublicationTimeout)
	defer stop()

	if err := output.CreateNew(publish, path, func(w io.Writer) error { _, e := w.Write(data); return e }); err != nil {
		return fmt.Errorf("cannot publish environment snapshot: %w", err)
	}

	return nil
}
