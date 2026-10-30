package cli

import (
	"errors"
	"strings"

	"github.com/skarm/scout"
)

// checkSelection is a complete optional-check selection, not a patch to the
// configured checks. Set validates the entire list before replacing its value.
type checkSelection struct {
	value    scout.Checks
	assigned bool
}

func allStaticChecks() scout.Checks {
	return scout.Checks{Python: true, YAML: true, TOML: true, YARA: true, Patterns: true}
}

func (s *checkSelection) String() string {
	var names []string

	for _, check := range []struct {
		name    string
		enabled bool
	}{{"python", s.value.Python}, {"yaml", s.value.YAML}, {"toml", s.value.TOML}, {"yara", s.value.YARA}, {"patterns", s.value.Patterns}} {
		if check.enabled {
			names = append(names, check.name)
		}
	}

	if len(names) == 0 {
		return "none"
	}

	return strings.Join(names, ",")
}

func (s *checkSelection) Set(value string) error {
	if s.assigned {
		return errors.New("checks must be supplied only once")
	}

	var selected scout.Checks

	fields := map[string]*bool{
		"python": &selected.Python, "yaml": &selected.YAML, "toml": &selected.TOML,
		"yara": &selected.YARA, "patterns": &selected.Patterns,
	}

	if value != "none" {
		for name := range strings.SplitSeq(value, ",") {
			field := fields[strings.TrimSpace(name)]
			if field == nil || *field {
				return errors.New("checks requires unique names from python,yaml,toml,yara,patterns, or none alone")
			}

			*field = true
		}
	}

	s.value, s.assigned = selected, true

	return nil
}
