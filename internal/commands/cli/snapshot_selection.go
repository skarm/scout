package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	Arguments []string           `json:"arguments"`
	Inventory discovery.Snapshot `json:"inventory"`
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
		candidate, err := readEnvironmentCheckpoint(r.snapshotCandidate, nil)
		if err != nil {
			return out, fmt.Errorf("candidate snapshot: %w", err)
		}

		// Archived source paths are metadata. Only the explicitly supplied
		// checkpoint files are inputs in this mode.
		out.candidate = &candidate.Snapshot

		r.publicationInputs = append(r.publicationInputs, r.snapshotCandidate)

		return out, nil
	}

	// Explicit roots and --empty override saved discovery; no ambient context is merged.
	if len(inputs) == 0 && !r.snapshotEmpty {
		if out.checkpoint.Discovery != nil {
			a, err := restoreDiscovery(out.checkpoint.Discovery.Arguments)
			if err != nil {
				return out, err
			}

			inventory, err := completeDiscovery(ctx, a)
			if err != nil {
				return out, err
			}

			r.publicationInputs = append(r.publicationInputs, inventory.ProtectedInputs()...)
			inventory.Targets = replayedDiscoveryTargets(inventory)

			out.inputs, err = discoveredRoots(inventory.Targets)
			if err != nil {
				return out, err
			}

			out.selection = &checkpointDiscovery{Arguments: out.checkpoint.Discovery.Arguments, Inventory: inventory}
		} else {
			out.inputs, err = savedRoots(out.checkpoint.Snapshot)
			if err != nil {
				return out, err
			}
		}

		r.targets = nil
		for _, id := range sortedRootIDs(out.inputs, nil) {
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
	if len(paths) > 32 {
		return nil, errors.New("discovery yielded more than 32 roots; narrow with --kind, --include-path or --exclude-path")
	}

	inputs := map[string]string{}

	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}

		sum := sha256.Sum256([]byte(absolute))

		id := "root-" + hex.EncodeToString(sum[:])[:24]
		if _, exists := inputs[id]; exists {
			return nil, errors.New("duplicate discovered root")
		}

		inputs[id] = absolute
	}

	return inputs, nil
}

func snapshotDiscovered(ctx context.Context, a discoveryArguments, inventory discovery.Snapshot, stdout, stderr io.Writer) int {
	if a.options.Agent == "all" || len(a.options.Projects) > 1 {
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

	plan, err := savedDiscoveryArguments(a)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	return executeEnvironmentSnapshot(ctx, "create", r, path, roots, &checkpointDiscovery{Arguments: plan, Inventory: inventory}, stdout, stderr)
}

func completeDiscovery(ctx context.Context, a discoveryArguments) (discovery.Snapshot, error) {
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
	args := []string{"--agent", a.options.Agent, "--system=" + strconv.FormatBool(a.options.System), "--timeout", a.timeout.String(), "--max-entries", strconv.Itoa(a.options.MaxEntries), "--max-depth", strconv.Itoa(a.options.MaxDepth), "--max-bytes", strconv.FormatInt(a.options.MaxBytes, 10)}

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
	for _, entry := range []struct{ flag, path string }{{"--home", a.options.Home}, {"--codex-home", a.options.CodexHome}, {"--claude-home", a.options.ClaudeHome}} {
		if err := appendPath(entry.flag, entry.path); err != nil {
			return nil, err
		}
	}

	if len(a.options.Projects) == 0 {
		args = append(args, "--no-project")
	}

	for _, path := range a.options.Projects {
		if err := appendPath("--project", path); err != nil {
			return nil, err
		}
	}

	for _, path := range a.includePaths {
		if err := appendPath("--include-path", path); err != nil {
			return nil, err
		}
	}

	for _, path := range a.excludePaths {
		if err := appendPath("--exclude-path", path); err != nil {
			return nil, err
		}
	}

	for _, kind := range a.kinds {
		args = append(args, "--kind", kind)
	}

	return args, nil
}

func restoreDiscovery(args []string) (discoveryArguments, error) {
	if len(args) > 256 {
		return discoveryArguments{}, errors.New("saved discovery arguments exceed limit")
	}

	a, err := parseDiscoveryArguments(args, io.Discard)
	if err != nil || a.options.Agent == "all" || len(a.options.Projects) > 1 || a.scan || a.snapshot != "" || a.explicitOutput || len(a.scanArgs) != 0 || !a.explicitHome {
		return a, errors.New("invalid saved discovery context")
	}

	for _, path := range append([]string{a.options.Home, a.options.CodexHome, a.options.ClaudeHome}, a.options.Projects...) {
		if path != "" && !filepath.IsAbs(path) {
			return a, errors.New("saved discovery paths must be absolute")
		}
	}

	return a, nil
}
