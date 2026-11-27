package main

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

type gateKey struct {
	path, scope, metric string
	minimum             bool
}

type bound struct {
	location
	value  float64
	strict bool
}

type commandKey struct{ path, scope string }

func (i inventory) addBound(key gateKey, candidate bound) {
	i.gates[key] = append(i.gates[key], candidate)
}

func looser(newBound, oldBound bound, minimum bool) bool {
	if newBound.value == oldBound.value {
		return !newBound.strict && oldBound.strict
	}

	if minimum {
		return newBound.value < oldBound.value
	}

	return newBound.value > oldBound.value
}

func weakenedBounds(before, after map[gateKey][]bound) []warning {
	var warnings []warning

	for key, existing := range before {
		prior := strongestFirst(existing, key.minimum)
		next := strongestFirst(after[key], key.minimum)

		for index, old := range prior {
			switch {
			case index >= len(next):
				warnings = append(warnings, warning{
					old.location, true, "Quality threshold removed",
					fmt.Sprintf("Removed %s %s.", key.metric, old.describe(key.minimum)),
				})
			case looser(next[index], old, key.minimum):
				warnings = append(warnings, warning{
					next[index].location, false, "Quality threshold weakened",
					fmt.Sprintf("%s changed from %s to %s.", key.metric, old.describe(key.minimum), next[index].describe(key.minimum)),
				})
			}
		}
	}

	return warnings
}

func strongestFirst(bounds []bound, minimum bool) []bound {
	ordered := slices.Clone(bounds)
	slices.SortStableFunc(ordered, func(a, b bound) int {
		switch {
		case looser(a, b, minimum):
			return 1
		case looser(b, a, minimum):
			return -1
		default:
			return 0
		}
	})

	return ordered
}

func (b bound) describe(minimum bool) string {
	operator := "<"
	if minimum {
		operator = ">"
	}

	if !b.strict {
		operator += "="
	}

	return fmt.Sprintf("%s %g", operator, b.value)
}

type testCommand struct {
	location
	kind, tags, dir  string
	race             bool
	targets, filters []string
}

func parseTestCommand(loc location, kind string, args []shellWord) (testCommand, bool) {
	cmd := testCommand{location: loc, kind: kind}

	var goOptions goTestOptions

	for index := 0; index < len(args); index++ {
		arg := args[index]

		name, value, inline := strings.Cut(arg.text, "=")
		if kind == "go" && goOptions.apply(&cmd, name, value, inline, args, &index) {
			continue
		}

		if kind == "node" && cmd.applyNodeOption(name, value, inline, args, &index) {
			continue
		}

		flag := testSelection(name, kind)
		if flag == "" {
			if kind != "go" && arg.literal || kind == "go" && !goOptions.binaryArgs {
				cmd.addArgument(arg.text)
			}

			continue
		}

		value = optionValue(value, inline, args, &index)
		if flag == "-tags" {
			cmd.tags = value
		} else {
			if kind == "go" {
				clearGoFilter(&cmd, flag)
			}

			if value != "" {
				cmd.filters = append(cmd.filters, flag+"="+value)
			}
		}
	}

	if goOptions.compileOnly || goOptions.dryRun || goOptions.listOnly || len(cmd.targets) == 0 && kind == "make" {
		return testCommand{}, false
	}

	if len(cmd.targets) == 0 {
		cmd.targets = []string{"."}
	}

	slices.Sort(cmd.filters)

	return cmd, true
}

type goTestOptions struct {
	compileOnly, dryRun, listOnly, binaryArgs bool
}

func (options *goTestOptions) apply(cmd *testCommand, name, value string, inline bool, args []shellWord, index *int) bool {
	flag := strings.TrimPrefix(strings.TrimLeft(name, "-"), "test.")
	if name == flag {
		return false
	}

	switch flag {
	case "args":
		options.binaryArgs = true
	case "short":
		clearGoFilter(cmd, "-short")

		if value != "false" && value != "0" {
			cmd.filters = append(cmd.filters, "-short")
		}
	case "race":
		cmd.race = value != "false" && value != "0"
	case "c":
		options.compileOnly = value != "false" && value != "0"
	case "n":
		options.dryRun = value != "false" && value != "0"
	case "list", "C", "exec":
		value = optionValue(value, inline, args, index)

		switch flag {
		case "list":
			options.listOnly = value != ""
		case "C":
			dir := path.Clean(value)
			if dir != "." {
				cmd.dir = dir
			}
		case "exec":
			clearGoFilter(cmd, "-exec")
			cmd.filters = append(cmd.filters, "-exec="+value)
		}
	default:
		if !goFlagTakesValue(flag) {
			return false
		}

		_ = optionValue(value, inline, args, index)
	}

	return true
}

func optionValue(value string, inline bool, args []shellWord, index *int) string {
	if !inline && *index+1 < len(args) {
		(*index)++
		return args[*index].text
	}

	return value
}

func clearGoFilter(cmd *testCommand, flag string) {
	cmd.filters = slices.DeleteFunc(cmd.filters, func(filter string) bool {
		return filter == flag || strings.HasPrefix(filter, flag+"=")
	})
}

func goFlagTakesValue(flag string) bool {
	switch flag {
	case "asmflags", "bench", "benchtime", "blockprofile", "blockprofilerate", "buildmode", "compiler",
		"count", "covermode", "coverpkg", "coverprofile", "cpu", "cpuprofile", "fuzz", "fuzztime",
		"fuzzminimizetime", "gccgoflags", "gcflags", "installsuffix", "ldflags", "memprofile",
		"memprofilerate", "mod", "modfile", "mutexprofile", "mutexprofilefraction", "o", "outputdir",
		"overlay", "p", "parallel", "pkgdir", "pgo", "shuffle", "timeout", "toolexec", "trace", "vet":
		return true
	default:
		return false
	}
}

func testSelection(name, kind string) string {
	if kind == "node" && (name == "--test-name-pattern" || name == "--test-skip-pattern" || name == "--test-shard") {
		return name
	}

	if kind == "go" && strings.HasPrefix(name, "-") {
		flag := strings.TrimPrefix(strings.TrimLeft(name, "-"), "test.")
		switch flag {
		case "run", "skip", "tags":
			return "-" + flag
		}
	}

	return ""
}

func (cmd *testCommand) applyNodeOption(name, value string, inline bool, args []shellWord, index *int) bool {
	switch name {
	case "--test-only", "--no-test-only":
		cmd.filters = slices.DeleteFunc(cmd.filters, func(filter string) bool { return filter == "--test-only" })
		if name == "--test-only" && value != "false" {
			cmd.filters = append(cmd.filters, name)
		}
	case "--conditions", "--import", "--require", "-r", "--test-concurrency", "--test-reporter", "--test-reporter-destination", "--test-timeout":
		_ = optionValue(value, inline, args, index)
	default:
		return false
	}

	return true
}

func (cmd *testCommand) addArgument(arg string) {
	switch cmd.kind {
	case "make":
		switch arg {
		case "test", "test-core", "race", "acceptance", "host-test":
			cmd.targets = append(cmd.targets, arg)
		}
	case "go":
		if arg != "" && !strings.HasPrefix(arg, "-") {
			cmd.targets = append(cmd.targets, arg)
		}
	case "node":
		if !strings.HasPrefix(arg, "-") {
			cmd.targets = append(cmd.targets, arg)
		}
	}
}

func removedCommands(before, after map[commandKey][]testCommand) []warning {
	var warnings []warning

	for key, commands := range before {
		for _, old := range commands {
			for _, target := range old.targets {
				if !coversCommand(after[key], old, target) {
					warnings = append(warnings, warning{
						old.location, true, "Test run removed or narrowed",
						fmt.Sprintf("%s test selection for %q in %q (directory %q, tags %q, race %t, filters %q) is missing or restricted.", old.kind, target, key.scope, old.dir, old.tags, old.race, old.filters),
					})
				}
			}
		}
	}

	return warnings
}

func coversCommand(candidates []testCommand, old testCommand, target string) bool {
	for _, next := range candidates {
		if old.kind != next.kind || old.dir != next.dir || old.tags != next.tags || old.race != next.race || !filtersCover(next.filters, old.filters) {
			continue
		}

		for _, candidate := range next.targets {
			if candidate == target || old.kind == "go" && goPatternCovers(candidate, target) {
				return true
			}
		}
	}

	return false
}

func filtersCover(next, old []string) bool {
	return !slices.ContainsFunc(next, func(filter string) bool { return !slices.Contains(old, filter) })
}

func goPatternCovers(pattern, target string) bool {
	root, ok := strings.CutSuffix(pattern, "/...")
	return ok && (target == root || strings.HasPrefix(target, root+"/"))
}
