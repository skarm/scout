package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
)

type subjects map[string][]location

type testSkip struct {
	subject, condition string
	workflow           bool
}

type inventory struct {
	tests, controls    subjects
	skips              map[testSkip][]location
	buildTags          map[string][]taggedTests
	commands           map[commandKey][]testCommand
	gates              map[gateKey][]bound
	workflows          map[string]workflowCoverage
	testNameSeparators *strings.Replacer
}

type taggedTests struct {
	expression string
	location
}

func newInventory() inventory {
	return inventory{
		tests: subjects{}, controls: subjects{}, skips: map[testSkip][]location{},
		buildTags: map[string][]taggedTests{}, commands: map[commandKey][]testCommand{}, gates: map[gateKey][]bound{},
		workflows: map[string]workflowCoverage{}, testNameSeparators: strings.NewReplacer("-", "", "_", "", " ", ""),
	}
}

func (i inventory) read(read blobReader, blob, name string) error {
	switch {
	case strings.HasSuffix(name, "_test.go"):
		data, err := read(blob)
		if err != nil {
			return err
		}

		return i.readGoTests(name, data)
	case controlCorpus(name):
		data, err := read(blob)
		if err != nil {
			return err
		}

		return i.readControls(name, data)
	case name == "Makefile" || path.Dir(name) == ".github/workflows" && (path.Ext(name) == ".yml" || path.Ext(name) == ".yaml"):
		data, err := read(blob)
		if err != nil {
			return err
		}

		if name == "Makefile" {
			return i.readMakefile(name, string(data))
		}

		return i.readWorkflow(name, data)
	}

	return nil
}

func controlCorpus(name string) bool {
	switch name {
	case "testdata/security-corpus/cases.json", "testdata/security-corpus/packages.json",
		"testdata/knowledge-runtime/cases.json", "testdata/production-replay/cases.json":
		return true
	default:
		return false
	}
}

func (i inventory) readControls(name string, contents []byte) error {
	var corpus struct{ Cases []json.RawMessage }
	if err := json.Unmarshal(contents, &corpus); err != nil {
		return fmt.Errorf("read %q: %w", name, err)
	}

	cursor, line := 0, 1

	for _, raw := range corpus.Cases {
		var c struct {
			ID, Label       string
			StaticForbidden string   `json:"static_forbidden"`
			ForbiddenRules  []string `json:"forbidden_rules"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("read case in %q: %w", name, err)
		}

		offset := bytes.Index(contents[cursor:], raw)
		if offset < 0 {
			return fmt.Errorf("cannot locate case in %q", name)
		}

		start := cursor + offset
		line += bytes.Count(contents[cursor:start], []byte{'\n'})

		if c.Label == "benign" {
			key := name + "\x00" + c.ID
			i.controls[key] = append(i.controls[key], location{name, line})
		}

		if c.StaticForbidden != "" {
			c.ForbiddenRules = append(c.ForbiddenRules, c.StaticForbidden)
		}

		for _, rule := range c.ForbiddenRules {
			key := name + "\x00" + c.ID + " forbids " + rule
			i.controls[key] = append(i.controls[key], location{name, line})
		}

		line += bytes.Count(raw, []byte{'\n'})
		cursor = start + len(raw)
	}

	return nil
}

func compareInventories(before, after inventory) []warning {
	var warnings []warning

	warnings = appendMissing(warnings, before.controls, after.controls, "Negative control removed",
		"Negative control %q was removed or relabelled.")

	warnings = appendMissing(warnings, before.tests, after.tests, "Test removed from run",
		"Go test or named subtest %q was removed or renamed.")
	for key, locations := range after.skips {
		if !key.workflow && len(before.tests[key.subject]) == 0 && len(before.controls[key.subject]) == 0 {
			continue
		}

		count := len(before.skips[key])
		if count < len(locations) {
			test := subjectName(key.subject)
			for _, loc := range locations[count:] {
				warnings = append(warnings, warning{loc, false, "Test can now be skipped", fmt.Sprintf("%q adds a skip or changes its guard.", test)})
			}
		}
	}

	warnings = append(warnings, changedBuildSelection(before.buildTags, after.buildTags)...)

	for name, coverage := range before.workflows {
		if coverage.runsChecks && coverage.triggerLine != 0 && after.workflows[name].triggerLine == 0 {
			loc := location{name, coverage.triggerLine}
			warnings = append(warnings, warning{loc, true, "PR test trigger removed", "This workflow no longer declares a pull_request trigger."})
		}
	}

	warnings = append(warnings, weakenedBounds(before.gates, after.gates)...)

	return append(warnings, removedCommands(before.commands, after.commands)...)
}

func changedBuildSelection(before, after map[string][]taggedTests) []warning {
	var warnings []warning

	seen := map[warning]bool{}

	for test, selections := range after {
		prior := before[test]
		if len(prior) == 0 {
			continue
		}

		for _, next := range selections {
			if next.expression == "" || slices.ContainsFunc(prior, func(old taggedTests) bool { return old.expression == next.expression }) {
				continue
			}

			item := warning{
				next.location, false, "Go test build selection changed",
				fmt.Sprintf("Build selection now includes %q. Check which test variants still include this file.", next.expression),
			}
			if !seen[item] {
				warnings = append(warnings, item)
				seen[item] = true
			}
		}
	}

	return warnings
}

func appendMissing(warnings []warning, before, after subjects, category, message string) []warning {
	for key, locations := range before {
		count := len(after[key])
		if count < len(locations) {
			for _, loc := range locations[count:] {
				warnings = append(warnings, warning{loc, true, category, fmt.Sprintf(message, subjectName(key))})
			}
		}
	}

	return warnings
}

func subjectName(key string) string {
	_, name, _ := strings.Cut(key, "\x00")
	return name
}
