package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/capture/envsnapshot"
	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

const maxSnapshotJSONNodes = 4_000_000

type environmentCheckpoint struct {
	Snapshot   envsnapshot.Snapshot `json:"snapshot"`
	Inspection report.Document      `json:"inspection"`
	Discovery  *checkpointDiscovery `json:"discovery,omitempty"`
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

type environmentComparison struct {
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

func environmentSnapshotCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "inspect" {
		return inspectEnvironmentSnapshot(ctx, args[1:], stdout, stderr)
	}

	if len(args) == 0 || args[0] != "create" && args[0] != "compare" {
		return usageError(stderr, "snapshot requires create, compare or inspect")
	}

	mode := args[0]

	r, snapshotPath, inputs, err := parseSnapshotRequest(mode, args[1:], stderr)
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

	if err = r.loadTrusted(); err != nil {
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
	if err != nil {
		return "", nil, err
	}

	return checkpointOutput, outputs, validateSnapshotOutputs(mode, outputs)
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

	result, err := compareEnvironment(ctx, scanner, gate, selected.checkpoint.Snapshot, current, previousPaths, currentPaths, r.compare)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	result.describeContent(selected.checkpoint.Snapshot, current, r.snapshotSourceDiff)

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

	if err = r.publishOutputs(publish, outputs, stdout, result.write); err != nil {
		return usageError(stderr, "cannot publish environment comparison")
	}

	return result.Code
}

func namedTargets(paths map[string]string) []scout.Target {
	ids := sortedRootIDs(paths, nil)

	targets := make([]scout.Target, 0, len(ids))
	for _, id := range ids {
		targets = append(targets, scout.Path(paths[id]))
	}

	return targets
}

func sortedRootIDs(a, b map[string]string) []string {
	seen := map[string]bool{}
	for id := range a {
		seen[id] = true
	}

	for id := range b {
		seen[id] = true
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	return ids
}

func compareEnvironment(ctx context.Context, scanner *scout.Scanner, gate *policy.Gate, before, after envsnapshot.Snapshot, old, current map[string]string, options scout.CompareOptions) (environmentComparison, error) {
	result := environmentComparison{Schema: "scout.environment-comparison/v1", Before: before.Digest, After: after.Digest, Decision: report.Allow, Roots: []environmentRootChange{}}

	for _, id := range sortedRootIDs(old, current) {
		previous, candidate := old[id], current[id]
		change := "unchanged"

		var run report.Run

		switch {
		case previous == "":
			change = "added"
			run, _ = scanner.Scan(ctx, scout.Path(candidate))
		case candidate == "":
			change = "removed"
			run, _ = scanner.Scan(ctx, scout.Path(previous))
		default:
			run, _ = scanner.Compare(ctx, scout.Path(previous), scout.Path(candidate), options)
		}

		prepared, err := report.Prepare(report.NewDocument(run, gate.Evaluate(run, time.Now().UTC())))
		if err != nil {
			return result, errors.New("environment comparison did not produce a valid report")
		}

		if change == "unchanged" && rootDigest(before, id) != rootDigest(after, id) {
			change = "modified"
		}

		if change == "removed" {
			// Findings in removed content are historical evidence, not candidate blockers.
			if prepared.State() != report.RunComplete {
				result.Code = 2
			}
		} else {
			result.addDecision(prepared)
		}

		result.Roots = append(result.Roots, environmentRootChange{ID: id, Change: change, Report: prepared.Snapshot(), Directories: directoryChanges(before, after, id)})
		if change != "unchanged" {
			if result.Decision == report.Allow {
				result.Decision = report.Review
			}

			result.Code = max(1, result.Code)
		}
	}

	var err error

	result.PreviousEnvironment, err = scanSnapshotEnvironment(ctx, scanner, gate, old)
	if err != nil {
		return result, err
	}

	result.Environment, err = scanSnapshotEnvironment(ctx, scanner, gate, current)
	if err != nil {
		return result, err
	}

	if result.Environment != nil {
		prepared, prepErr := report.Prepare(*result.Environment)
		if prepErr != nil {
			return result, prepErr
		}

		result.addDecision(prepared)
	}

	result.Relationships = compareRelationships(result.PreviousEnvironment, result.Environment, old, current, options.MaxChanges)
	if result.Relationships.Completeness != report.Complete {
		result.Code = 2
		if result.Decision == report.Allow {
			result.Decision = report.Review
		}
	}

	return result, nil
}

func (r *environmentComparison) addDecision(p report.PreparedDocument) {
	r.Code = max(r.Code, policy.PreparedCode(p))
	if p.Decision() == report.Block || r.Decision == report.Allow && p.Decision() == report.Review {
		r.Decision = p.Decision()
	}
}

func (r environmentComparison) write(w io.Writer, format report.Format) error {
	if format == report.JSON {
		return json.NewEncoder(w).Encode(r)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "Environment changes: decision=%s; exit=%d.\n\n", r.Decision, r.Code)
	fmt.Fprintln(&b, relationshipSummary(r.Relationships))
	b.WriteString("\n")
	fmt.Fprintf(&b, "Saved content: %s\nCurrent content: %s\n\n", r.Before, r.After)

	if r.Code == 2 {
		b.WriteString("Coverage is incomplete. Unobserved findings do not prove remediation.\n\n")
	}

	r.writeRootSummary(&b, format)
	r.writeRelationshipSummary(&b, format)

	b.WriteString("Root identifiers are operator-selected boundaries; activation is not inferred. Both versions were rescanned with the current configuration.\n\n")

	for _, root := range r.Roots {
		if root.Change == "unchanged" && root.Report.Run.State == report.RunComplete && root.Report.Evaluation.Decision == report.Allow {
			continue
		}

		label := "evidence and policy"
		if root.Change == "removed" {
			label = "historical evidence only; removed from candidate"
		}

		fmt.Fprintf(&b, "Root %s — %s\n\n", strconv.QuoteToASCII(root.ID), label)

		if err := report.Write(&b, format, root.Report); err != nil {
			return err
		}
	}

	if r.Environment != nil && (r.Environment.Run.State != report.RunComplete || len(r.Environment.Run.Environment.Observations) > 0) {
		b.WriteString("Current environment — relationships and policy\n\n")

		if err := report.Write(&b, format, *r.Environment); err != nil {
			return err
		}
	}

	_, err := w.Write(b.Bytes())

	return err
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
		if depth > 64 || nodes > maxSnapshotJSONNodes {
			return errors.New("snapshot JSON structural limit")
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
					return errors.New("duplicate snapshot JSON key")
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
		return errors.New("trailing snapshot JSON")
	}

	return nil
}

func parseSnapshotRequest(mode string, args []string, stderr io.Writer) (request, string, map[string]string, error) {
	command := "scan"
	if mode == "compare" {
		command = "compare"
	}

	var (
		snapshotPath string
		candidate    string
		save         string
		roots        repeated
		empty        bool
		diff         bool
	)

	r, err := resolveRequest(command, args, stderr, func(fs *flag.FlagSet) {
		fs.BoolVar(&diff, "include-source-diff", false, "include bounded source excerpts in change reports; may contain secrets")
		fs.StringVar(&snapshotPath, "snapshot", "", "required environment snapshot path (create never replaces it)")
		fs.Var(&roots, "root", "named local root ID=PATH; repeat for the complete selected environment")
		fs.BoolVar(&empty, "empty", false, "explicitly compare against an empty environment")

		if mode == "compare" {
			fs.StringVar(&candidate, "candidate", "", "compare with a second saved environment snapshot")
			fs.StringVar(&save, "save-candidate", "", "save the checked current bytes to a new snapshot file")
		}
	})
	if err != nil {
		return r, "", nil, err
	}

	if snapshotPath == "" || len(r.targets) != 0 || r.input != "" || r.name != "" || r.followExternal || r.grants.Download || r.revision != "" || r.sha256 != "" {
		return r, "", nil, errors.New("snapshot requires --snapshot and named local --root inputs; external traversal and downloads are unsupported")
	}

	inputs, err := parseSnapshotRoots(&r, roots)
	if err != nil {
		return r, "", nil, err
	}

	if len(inputs) > scout.MaxScanTargets || len(inputs) == 0 && mode != "compare" || empty && (mode != "compare" || len(inputs) != 0) {
		return r, "", nil, errors.New("select 1..32 named roots for creation; compare can reuse the saved selection")
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
	run, scanErr := scanner.ScanEnvironment(ctx, namedTargets(currentPaths))
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

func validateSnapshotOutputs(mode string, outputs []destination) error {
	for _, out := range outputs {
		if mode == "compare" && out.format == report.SARIF {
			return errors.New("snapshot comparison supports text, markdown and json")
		}
	}

	return nil
}

func rootDigest(s envsnapshot.Snapshot, id string) string {
	for _, r := range s.Roots {
		if r.ID == id {
			return r.ContentDigest()
		}
	}

	return ""
}

func directoryChanges(before, after envsnapshot.Snapshot, id string) []environmentDirectoryChange {
	directories := func(s envsnapshot.Snapshot) map[string]string {
		paths := map[string]string{}

		for _, root := range s.Roots {
			if root.ID == id {
				for _, entry := range root.Entries {
					if entry.Directory {
						paths[entry.Path] = "directory"
					}
				}
			}
		}

		return paths
	}
	old, current := directories(before), directories(after)

	var changes []environmentDirectoryChange

	for _, path := range sortedRootIDs(old, current) {
		if old[path] == current[path] {
			continue
		}

		change := "added"
		if current[path] == "" {
			change = "removed"
		}

		changes = append(changes, environmentDirectoryChange{Path: path, Change: change})
	}

	return changes
}

// Quote source-owned paths as Markdown code spans, including embedded backticks.
func quoteSnapshotPath(value string, format report.Format) string {
	escaped := strconv.QuoteToASCII(value)
	if format != report.Markdown {
		return escaped
	}

	delimiter := "`"
	for strings.Contains(escaped, delimiter) {
		delimiter += "`"
	}

	return delimiter + escaped + delimiter
}

func scanSnapshotEnvironment(ctx context.Context, scanner *scout.Scanner, gate *policy.Gate, paths map[string]string) (*report.Document, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	run, _ := scanner.ScanEnvironment(ctx, namedTargets(paths))

	prepared, err := report.Prepare(report.NewDocument(run, gate.Evaluate(run, time.Now().UTC())))
	if err != nil {
		return nil, errors.New("environment analysis did not produce a valid report")
	}

	document := prepared.Snapshot()

	return &document, nil
}

func evidenceRoot(doc *report.Document, id string, roots []environmentRootChange, previous bool) string {
	ids := []string{}

	for _, root := range roots {
		if previous && root.Change != "added" || !previous && root.Change != "removed" {
			ids = append(ids, root.ID)
		}
	}

	if doc != nil {
		for _, target := range doc.Run.Targets {
			if target.ID == id {
				if target.Index < len(ids) {
					return ids[target.Index]
				}

				return target.ID
			}
		}
	}

	return id
}

func (r environmentComparison) writeRootSummary(b *bytes.Buffer, format report.Format) {
	for _, root := range r.Roots {
		fmt.Fprintf(b, "Root %s: %s", strconv.QuoteToASCII(root.ID), root.Change)

		source := root.AfterPath
		if source == "" {
			source = root.BeforePath
		}

		fmt.Fprintf(b, "; source %s", quoteSnapshotPath(source, format))

		if d := root.Report.Run.Comparison; d != nil {
			fmt.Fprintf(b, "; %d file changes, %d component changes, %d dependency changes, %d new findings", d.Counts.FileChanges, d.Counts.ComponentChanges, d.Counts.DependencyChanges, d.Counts.IntroducedFindings)
		}

		b.WriteString(".\n\n")

		for _, content := range root.Content {
			fmt.Fprintf(b, "%s: %s (%d -> %d bytes). %s", quoteSnapshotPath(content.Path, format), content.Change, content.BeforeBytes, content.AfterBytes, content.Explanation)

			if content.Text {
				fmt.Fprintf(b, " Changed line ranges contain %d removed and %d added lines.", content.RemovedLines, content.AddedLines)
			}

			b.WriteString("\n\n")

			if content.Excerpt != "" {
				writeSourceExcerpt(b, content.Excerpt, format)
			}

			if content.DiffOmitted {
				b.WriteString("Source excerpt omitted or truncated by the text/size limits. See the coverage diagnostics for analysis status.\n\n")
			}
		}

		for _, directory := range root.Directories {
			fmt.Fprintf(b, "Directory %s: %s.\n\n", quoteSnapshotPath(directory.Path, format), directory.Change)
		}
	}
}

func (r environmentComparison) writeRelationshipSummary(b *bytes.Buffer, format report.Format) {
	for _, change := range r.Relationships.Changes {
		if change.Change == "persistent" {
			continue
		}

		fmt.Fprintf(b, "Relationship %s: %s. %s\n\n", change.Kind, change.Change, relationshipExplanation(change.Kind))

		observation := change.After
		if observation == nil {
			observation = change.Before
		}

		doc := r.Environment
		if change.After == nil {
			doc = r.PreviousEnvironment
		}

		for _, ref := range observation.Evidence {
			fmt.Fprintf(b, "Evidence: %s, %s, bytes %d..%d.\n\n", quoteSnapshotPath(evidenceRoot(doc, ref.TargetID, r.Roots, change.After == nil), format), quoteSnapshotPath(ref.Source.Path, format), ref.Source.ByteStart, ref.Source.ByteEnd)
		}
	}
}
