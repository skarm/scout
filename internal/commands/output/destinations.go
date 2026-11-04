package output

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var errDestinationAlias = errors.New("report destinations must be distinct on the destination filesystem")

// ValidateAll resolves report destinations and rejects names that alias on the
// destination filesystem, even if they do not exist yet. Empty paths represent
// stdout. Private, disposable sibling directories probe the filesystem's actual
// name comparison, including case folding and Unicode normalization; report
// destinations themselves are never created or changed.
func ValidateAll(destinations, localInputs []string) ([]string, error) {
	resolved := make([]string, len(destinations))
	seen := make(map[string]bool, len(destinations))

	var groups []destinationGroup

	for i, name := range destinations {
		if name == "" {
			continue
		}

		path, err := Validate(name, localInputs)
		if err != nil {
			return nil, err
		}

		if seen[path] {
			return nil, errors.New("report destinations must be distinct")
		}

		seen[path] = true

		resolved[i] = path
		if err := groupDestination(&groups, path); err != nil {
			return nil, err
		}
	}

	for _, group := range groups {
		if len(group.names) > 1 {
			if err := distinctNames(group); err != nil {
				return nil, err
			}
		}
	}

	return resolved, nil
}

type destinationGroup struct {
	parent string
	info   os.FileInfo
	names  []string
}

func groupDestination(groups *[]destinationGroup, name string) error {
	parent := filepath.Dir(name)

	info, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("inspect report directory: %w", err)
	}

	for i := range *groups {
		if os.SameFile((*groups)[i].info, info) {
			(*groups)[i].names = append((*groups)[i].names, filepath.Base(name))
			return nil
		}
	}

	*groups = append(*groups, destinationGroup{parent: parent, info: info, names: []string{filepath.Base(name)}})

	return nil
}

func distinctNames(group destinationGroup) (err error) {
	directory, err := os.MkdirTemp(group.parent, ".scout-destinations-*")
	if err != nil {
		return fmt.Errorf("check report destination names: %w", err)
	}
	defer func() { err = errors.Join(err, os.RemoveAll(directory)) }()

	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("open private destination probe: %w", err)
	}

	defer func() { err = errors.Join(err, root.Close()) }()

	for _, name := range group.names {
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, os.ErrExist) {
			return errDestinationAlias
		}

		if err != nil {
			return fmt.Errorf("check report destination name: %w", err)
		}

		if err := file.Close(); err != nil {
			return err
		}
	}

	return nil
}
