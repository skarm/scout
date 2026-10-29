// Package archiveutil validates archive structure without extracting to disk.
package archiveutil

import (
	"errors"
	"io/fs"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Namespace catches duplicate paths, case-fold collisions, and file/directory
// prefix conflicts before any archive payload is accepted.
type Namespace struct {
	nodes    map[string]pathNode
	MaxNodes int
	bytes    int
}
type pathNode struct {
	spelling  string
	directory bool
	explicit  bool
}

// ValidatePath applies one conservative path policy on every OS. ZIP names are
// rejected, never cleaned into a different path. Backslashes and Windows device
// names are rejected even on Linux. Unicode normalization is NOT implemented.
func ValidatePath(name string, maxBytes, maxDepth int) error {
	if len(name) > maxBytes || !utf8.ValidString(name) || !fs.ValidPath(name) || name == "." {
		return errors.New("invalid or overlong relative path")
	}

	if err := validatePathCharacters(name); err != nil {
		return err
	}

	parts := strings.Split(name, "/")
	if len(parts) > maxDepth {
		return errors.New("path depth limit exceeded")
	}

	for _, part := range parts {
		if err := validatePathComponent(part); err != nil {
			return err
		}
	}

	return nil
}

func (i *Namespace) Add(name string, directory bool) error {
	if i.nodes == nil {
		i.nodes = make(map[string]pathNode)
	}

	parts := strings.Split(name, "/")
	for n := range parts {
		prefix := strings.Join(parts[:n+1], "/")
		key := foldPath(prefix)
		last := n == len(parts)-1
		dir := !last || directory

		if err := i.addNode(prefix, key, dir, last); err != nil {
			return err
		}
	}

	return nil
}

func (i *Namespace) addNode(prefix, key string, directory, explicit bool) error {
	previous, exists := i.nodes[key]
	if exists {
		if previous.spelling != prefix {
			return errors.New("case-fold path collision")
		}

		if !previous.directory || !directory {
			return errors.New("duplicate path or file/directory conflict")
		}

		if explicit && previous.explicit {
			return errors.New("duplicate directory entry")
		}
	} else {
		if err := i.allocateNode(prefix, key); err != nil {
			return err
		}

		previous = pathNode{spelling: prefix, directory: directory}
	}

	if explicit {
		previous.explicit = true
	}

	i.nodes[key] = previous

	return nil
}

func (i *Namespace) allocateNode(prefix, key string) error {
	// Parent directories consume the same bounded namespace metadata inventory.
	if (i.MaxNodes > 0 && len(i.nodes) >= i.MaxNodes) || i.bytes+len(prefix)+len(key) > 8<<20 {
		return errors.New("expanded namespace metadata budget exceeded")
	}

	i.bytes += len(prefix) + len(key)

	return nil
}

func reservedDevice(base string) bool {
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}

	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		tail := base[3:]
		return len(tail) == 1 && tail[0] >= '1' && tail[0] <= '9' || tail == "¹" || tail == "²" || tail == "³"
	}

	return false
}

func validatePathCharacters(name string) error {
	if strings.ContainsAny(name, `\:<>"|?*`) {
		return errors.New("nonportable path character")
	}

	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return errors.New("control or format character in path")
		}
	}

	return nil
}

func validatePathComponent(part string) error {
	if strings.TrimRight(part, " .") != part || strings.HasPrefix(part, " ") {
		return errors.New("ambiguous path component")
	}

	base, _, _ := strings.Cut(strings.ToUpper(part), ".")
	if reservedDevice(base) {
		return errors.New("reserved device name")
	}

	return nil
}

func foldPath(s string) string {
	return strings.Map(func(r rune) rune {
		minimumRune := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minimumRune {
				minimumRune = next
			}
		}

		return minimumRune
	}, s)
}
