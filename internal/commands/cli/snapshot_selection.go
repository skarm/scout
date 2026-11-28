package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/skarm/scout/internal/capture/envsnapshot"
	"github.com/skarm/scout/internal/discovery"
)

// Discovery arguments contain the resolved operator context, never executable commands.
// The inventory is informational; publication protection is rebuilt on each discovery.
type checkpointDiscovery struct {
	Arguments    []string                `json:"arguments"`
	Inventory    discovery.Snapshot      `json:"inventory"`
	RootBindings []discovery.RootBinding `json:"root_bindings,omitempty"`
}

type snapshotSelection struct {
	checkpoint environmentCheckpoint
	inputs     map[string]string
	selection  *checkpointDiscovery
	candidate  *envsnapshot.Snapshot
}

func resolveSnapshotSelection(ctx context.Context, mode, path string, r *request, inputs map[string]string, selection *checkpointDiscovery) (snapshotSelection, error) {
	out := snapshotSelection{inputs: inputs, selection: selection}
	if mode != "compare" {
		return out, nil
	}

	var err error

	out.checkpoint, err = readEnvironmentCheckpoint(path, r.localInputs())
	if err != nil {
		return out, fmt.Errorf("reference snapshot: %w", err)
	}

	if r.snapshotCandidate != "" {
		err := out.selectArchivedCandidate(r)
		return out, err
	}

	// Explicit roots and --empty override saved discovery; no ambient context is merged.
	if len(inputs) == 0 && !r.snapshotEmpty {
		if saved := out.checkpoint.Discovery; saved != nil {
			a, err := restoreDiscovery(saved.Arguments)
			if err != nil {
				return out, err
			}

			inventory, err := completeDiscovery(ctx, &a, saved.RootBindings)
			if err != nil {
				return out, err
			}

			r.useDiscoveryHarness(a.options.Agent)
			r.publicationInputs = append(r.publicationInputs, inventory.ProtectedInputs()...)
			inventory.Targets = replayedDiscoveryTargets(inventory)

			out.inputs, err = discoveredRoots(inventory.Targets)
			if err != nil {
				return out, err
			}

			out.selection = &checkpointDiscovery{Arguments: saved.Arguments, Inventory: inventory, RootBindings: saved.RootBindings}
		} else {
			out.inputs, err = savedRoots(out.checkpoint.Snapshot)
			if err != nil {
				return out, err
			}
		}

		r.targets = nil
		for _, id := range slices.Sorted(maps.Keys(out.inputs)) {
			r.targets = append(r.targets, out.inputs[id])
		}
	}

	for _, root := range out.checkpoint.Snapshot.Roots {
		r.publicationInputs = append(r.publicationInputs, root.Source)
	}

	for _, input := range r.protectedInputs() {
		if err = trustedInputBoundary(path, input); err != nil {
			return out, err
		}
	}

	return out, nil
}

func (s *snapshotSelection) selectArchivedCandidate(r *request) error {
	candidate, err := readEnvironmentCheckpoint(r.snapshotCandidate, nil)
	if err != nil {
		return fmt.Errorf("candidate snapshot: %w", err)
	}

	// Archived source paths are metadata. Only the explicitly supplied
	// checkpoint files are inputs in this mode.
	s.candidate = &candidate.Snapshot

	if host := capturedDiscoveryHarness(s.checkpoint); host != "" && host == capturedDiscoveryHarness(candidate) {
		r.useDiscoveryHarness(host)
	}

	r.publicationInputs = append(r.publicationInputs, r.snapshotCandidate)

	return nil
}

func capturedDiscoveryHarness(checkpoint environmentCheckpoint) string {
	if checkpoint.Discovery == nil || len(checkpoint.Inspection.Run.Targets) == 0 {
		return ""
	}

	targets := checkpoint.Inspection.Run.Targets
	host := targets[0].Analysis.Components.RequestedHost

	for _, target := range targets[1:] {
		if target.Analysis.Components.RequestedHost != host {
			return ""
		}
	}

	return host
}

func replayedDiscoveryTargets(inventory discovery.Snapshot) []string {
	if inventory.Selection == nil || len(inventory.Selection.IncludePaths) == 0 {
		return inventory.Targets
	}

	// A selected include can name a missing child of a discovered container.
	// During replay, its absence is a removal. Other paths still go through capture.
	return slices.DeleteFunc(inventory.Targets, func(path string) bool {
		if !slices.Contains(inventory.Selection.IncludePaths, path) {
			return false
		}

		_, err := os.Lstat(path)

		return errors.Is(err, os.ErrNotExist)
	})
}

func savedRoots(s envsnapshot.Snapshot) (map[string]string, error) {
	inputs := map[string]string{}

	for _, root := range s.Roots {
		if !filepath.IsAbs(root.Source) {
			return nil, errors.New("saved source paths must be absolute")
		}

		info, err := os.Lstat(root.Source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			return nil, errors.New("cannot inspect saved source path")
		}

		resolved, err := filepath.EvalSymlinks(root.Source)
		if err != nil {
			return nil, errors.New("cannot resolve saved source path")
		}

		if info.Mode()&os.ModeSymlink != 0 || resolved != root.Source {
			return nil, errors.New("saved source path became a symbolic link; choose an explicit --root to follow a new target")
		}

		inputs[root.ID] = root.Source
	}

	return inputs, nil
}

func discoveredRoots(paths []string) (map[string]string, error) {
	const (
		rootIDHexChars = 24
		rootIDPrefix   = "root-"
	)

	if len(paths) > envsnapshot.MaxRoots {
		return nil, fmt.Errorf("discovery yielded more than %d roots; narrow with --kind, --include-path or --exclude-path", envsnapshot.MaxRoots)
	}

	inputs := map[string]string{}

	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}

		sum := sha256.Sum256([]byte(absolute))

		id := rootIDPrefix + hex.EncodeToString(sum[:])[:rootIDHexChars]
		if _, exists := inputs[id]; exists {
			return nil, errors.New("duplicate discovered root")
		}

		inputs[id] = absolute
	}

	return inputs, nil
}

func snapshotDiscovered(ctx context.Context, a discoveryArguments, inventory discovery.Snapshot, bindings []discovery.RootBinding, stdout, stderr io.Writer) int {
	if a.options.Agent == discovery.AllAgents || len(a.options.Projects) > 1 {
		return usageError(stderr, "environment snapshot requires one --agent and at most one --project")
	}

	inputs, err := discoveredRoots(inventory.Targets)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if len(inputs) == 0 {
		return usageError(stderr, "no components discovered; select an environment with local components")
	}

	r, path, roots, err := parseSnapshotRequest("create", a.scanArgs, stderr, a.snapshot, inputs)
	if err != nil {
		return requestError(err, stderr)
	}

	r.publicationInputs = inventory.ProtectedInputs()
	r.useDiscoveryHarness(a.options.Agent)

	plan, err := savedDiscoveryArguments(a)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	return executeEnvironmentSnapshot(ctx, "create", r, path, roots, &checkpointDiscovery{Arguments: plan, Inventory: inventory, RootBindings: bindings}, stdout, stderr)
}

func (a *discoveryArguments) pinRoots(saved []discovery.RootBinding) ([]discovery.RootBinding, error) {
	return a.options.PinRoots(saved, append(slices.Clone(a.includePaths), a.excludePaths...)...)
}

func completeDiscovery(ctx context.Context, a *discoveryArguments, bindings []discovery.RootBinding) (discovery.Snapshot, error) {
	if bindings != nil {
		if _, err := a.pinRoots(bindings); err != nil {
			return discovery.Snapshot{}, err
		}
	}

	call, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	inventory, err := discovery.Discover(call, a.options)
	if err != nil || !inventory.Complete {
		return inventory, errors.New("discovery incomplete; snapshot comparison refused")
	}

	selected, err := discovery.Select(call, inventory, discovery.Filters{Kinds: a.kinds, IncludePaths: a.includePaths, ExcludePaths: a.excludePaths})
	if err != nil || !selected.Complete {
		return selected, errors.New("discovery selection incomplete; snapshot comparison refused")
	}

	return selected, nil
}

func savedDiscoveryArguments(a discoveryArguments) ([]string, error) {
	args := []string{
		"--" + flagAgent, a.options.Agent,
		"--" + flagSystem + "=" + strconv.FormatBool(a.options.System),
		"--" + flagTimeout, a.timeout.String(),
		"--" + flagMaxEntries, strconv.Itoa(a.options.MaxEntries),
		"--" + flagMaxDepth, strconv.Itoa(a.options.MaxDepth),
		"--" + flagMaxBytes, strconv.FormatInt(a.options.MaxBytes, 10),
	}

	appendPath := func(flag, path string) error {
		if path == "" {
			return nil
		}

		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}

		args = append(args, flag, absolute)

		return nil
	}
	if err := appendPath("--"+flagHome, a.options.Home); err != nil {
		return nil, err
	}

	for _, override := range a.options.HomeOverrides() {
		if override.Agent != a.options.Agent {
			continue
		}

		if err := appendPath("--"+override.Flag, *override.Path); err != nil {
			return nil, err
		}
	}

	if len(a.options.Projects) == 0 {
		args = append(args, "--"+flagNoProject)
	}

	for _, path := range a.options.Projects {
		if err := appendPath("--"+flagProject, path); err != nil {
			return nil, err
		}
	}

	for _, path := range a.includePaths {
		if err := appendPath("--"+flagIncludePath, path); err != nil {
			return nil, err
		}
	}

	for _, path := range a.excludePaths {
		if err := appendPath("--"+flagExcludePath, path); err != nil {
			return nil, err
		}
	}

	for _, kind := range a.kinds {
		args = append(args, "--"+flagKind, kind)
	}

	return args, nil
}

func restoreDiscovery(args []string) (discoveryArguments, error) {
	const maxSavedDiscoveryArguments = 256
	if len(args) > maxSavedDiscoveryArguments {
		return discoveryArguments{}, errors.New("saved discovery arguments exceed limit")
	}

	a, err := parseDiscoveryArguments(args, io.Discard)
	if err != nil || !discovery.ValidAgent(a.options.Agent) || a.options.Agent == discovery.AllAgents || len(a.options.Projects) > 1 ||
		(!a.noProject && len(a.projects) == 0) || a.scan || a.snapshot != "" || a.explicitOutput || len(a.scanArgs) != 0 || !a.explicitHome {
		return a, errors.New("invalid saved discovery context")
	}

	paths := []string{a.options.Home}
	for _, override := range a.options.HomeOverrides() {
		paths = append(paths, *override.Path)
	}

	paths = append(paths, a.options.Projects...)
	paths = append(paths, a.includePaths...)

	paths = append(paths, a.excludePaths...)
	for _, path := range paths {
		if path != "" && !filepath.IsAbs(path) {
			return a, errors.New("saved discovery paths must be absolute")
		}
	}

	return a, nil
}
