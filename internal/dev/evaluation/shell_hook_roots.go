package evaluation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/skarm/scout/report"
)

const MaxShellHookRootsBytes = 64 << 10

// ShellHookRoots applies a trusted launch assumption to selected cases only.
type ShellHookRoots struct {
	report.ShellHookRoot
	Cases []string `json:"cases"`
}

func ParseShellHookRoots(data []byte) (ShellHookRoots, error) {
	var roots ShellHookRoots
	if len(data) > MaxShellHookRootsBytes {
		return roots, errors.New("shell hook roots exceed byte budget")
	}

	if err := validateJSONFields(data, []string{"host", "path", "lc_all", "cases"}, false); err != nil {
		return roots, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&roots); err != nil || decoder.Decode(new(any)) != io.EOF {
		return roots, errors.New("invalid shell hook root assumptions")
	}

	return roots, roots.Validate()
}

func (o Options) shellHookRootCases(c Corpus, basePlan report.InspectionPlan) (map[string]bool, error) {
	roots, scanner := o.ShellHookRoots, o.ShellHookRootScanner
	if roots == nil && scanner == nil {
		return nil, nil
	}

	if !o.ShellHooks || roots == nil || scanner == nil || len(roots.Cases) == 0 {
		return nil, errors.New("shell hook root assumptions require a scanner and selected shell_hooks cases")
	}

	plan := scanner.InspectionPlan()
	if err := validateOfflinePlan(plan); err != nil {
		return nil, err
	}

	if err := roots.Validate(); err != nil || plan.ShellHookRoot != roots.ShellHookRoot {
		return nil, errors.New("configured scanner does not match the shell hook root assumption")
	}

	basePlan.ShellHookRoot = roots.ShellHookRoot
	if !reflect.DeepEqual(plan, basePlan) {
		return nil, errors.New("shell hook root assumptions require the same inspection plan for all cases")
	}

	eligible := map[string]bool{}

	for _, tc := range c.Cases {
		if tc.Category == "shell_hooks" && (o.Split == "" || tc.Split == o.Split) {
			eligible[tc.ID] = true
		}
	}

	selected := make(map[string]bool, len(roots.Cases))
	for _, id := range roots.Cases {
		if selected[id] || !eligible[id] {
			return nil, fmt.Errorf("duplicate or unselected shell_hooks case in root assumptions: %q", id)
		}

		selected[id] = true
	}

	return selected, nil
}
