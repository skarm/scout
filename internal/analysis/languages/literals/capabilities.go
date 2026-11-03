package literals

import (
	"path"
	"slices"
	"strconv"
	"strings"
)

// InfrastructureMutation recognizes selected modifying CLI verbs in an already
// resolved argv. It never parses shell text or treats a tool's name as an action.
// Unknown/global options outside this small grammar do not shift operands.
func InfrastructureMutation(argv []string) bool {
	if len(argv) < 2 {
		return false
	}

	tool := strings.TrimSuffix(path.Base(strings.ReplaceAll(argv[0], `\`, "/")), ".exe")

	args := argv[1:]
	for i := 0; i < len(args) && i < 32; i++ {
		arg := args[i]
		if arg == "" {
			return false
		}

		if !strings.HasPrefix(arg, "-") {
			return infrastructureVerb(tool, args[i:])
		}

		flag, _, inline := strings.Cut(arg, "=")
		if !infrastructureOption(tool, flag) {
			return false
		}

		if !inline {
			i++
			if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				return false
			}
		}
	}

	return false
}

func infrastructureOption(tool, flag string) bool {
	switch tool {
	case "kubectl", "helm":
		return flag == "--namespace" || flag == "-n" || flag == "--kubeconfig" || flag == "--context" && tool == "kubectl" || flag == "--kube-context" && tool == "helm"
	case "terraform":
		return flag == "-chdir"
	case "docker":
		return flag == "--context" || flag == "-c" || flag == "--host" || flag == "-H" || flag == "--config"
	default:
		return false
	}
}

func infrastructureVerb(tool string, args []string) bool {
	verb := args[0]
	if infrastructureHelp(tool, args) || infrastructureReadOnly(tool, args) {
		return false
	}

	switch tool {
	case "kubectl":
		return slices.Contains([]string{"apply", "create", "delete", "replace", "patch", "edit", "scale", "label", "annotate", "set", "drain", "cordon", "uncordon", "taint"}, verb) || verb == "rollout" && len(args) > 1 && args[1] == "restart"
	case "terraform":
		return slices.Contains([]string{"apply", "destroy", "import", "taint", "untaint"}, verb)
	case "helm":
		return slices.Contains([]string{"install", "upgrade", "uninstall", "rollback"}, verb)
	case "docker":
		return slices.Contains([]string{"run", "create", "start", "stop", "restart", "rm", "kill", "update"}, verb)
	default:
		return false
	}
}

func infrastructureHelp(tool string, args []string) bool {
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return false
		}

		if infrastructureNextIsValue(tool, arg) {
			i++
			continue
		}

		if infrastructureHelpFlag(tool, arg) {
			return tool != "docker" || args[0] != "run" && args[0] != "create" || dockerHelpBeforeImage(args[1:])
		}
	}

	return false
}

func dockerHelpBeforeImage(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if infrastructureTrueFlag(arg, "--help") {
			return true
		}

		if arg == "--" || arg != "" && !strings.HasPrefix(arg, "-") {
			return false // Remaining operands belong to the container program.
		}

		flag, _, inline := strings.Cut(arg, "=")
		switch flag {
		case "-h", "--hostname", "--name", "-e", "--env", "-v", "--volume", "-p", "--publish", "--entrypoint", "--network", "-w", "--workdir", "-u", "--user", "--mount", "-l", "--label":
			if !inline {
				i++
			}
		case "-d", "--detach", "-i", "--interactive", "-t", "--tty", "--rm", "--help":
		default:
			return true // Unknown option roles cannot establish an image boundary.
		}
	}

	return true
}

func infrastructureReadOnly(tool string, args []string) bool {
	if tool != "kubectl" && tool != "helm" {
		return false
	}

	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}

		if infrastructureNextIsValue(tool, arg) {
			i++
			continue
		}

		if arg == "--dry-run" || arg == "--dry-run=client" || arg == "--dry-run=server" || arg == "--dry-run=true" {
			return true
		}

		if tool == "kubectl" && (infrastructureTrueFlag(arg, "--list") || infrastructureTrueFlag(arg, "--local")) {
			return true
		}
	}

	return false
}

func infrastructureTrueFlag(arg, flag string) bool {
	name, value, explicit := strings.Cut(arg, "=")
	if name != flag {
		return false
	}

	if !explicit {
		return true
	}

	enabled, err := strconv.ParseBool(value)

	return err == nil && enabled
}

func infrastructureHelpFlag(tool, arg string) bool {
	if infrastructureTrueFlag(arg, "--help") {
		return true
	}

	if tool == "terraform" {
		return arg == "-help" || arg == "-h"
	}

	if tool == "docker" || !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
		return false
	}

	flags, value, explicit := strings.Cut(arg[1:], "=")
	for i := range len(flags) {
		if flags[i] == 'h' {
			if !explicit || i+1 < len(flags) {
				return true
			}

			enabled, err := strconv.ParseBool(value)

			return err == nil && enabled
		}

		if tool == "kubectl" && (flags[i] == 'A' || flags[i] == 'R') || tool == "helm" && flags[i] == 'i' {
			continue
		}

		return false // A value-taking or unknown shorthand may own the rest.
	}

	return false
}

// Required option operands remain data even when they look like control flags.
// Pflag short clusters may end with a value-taking flag, e.g. kubectl -Rf FILE.
func infrastructureNextIsValue(tool, arg string) bool {
	if !strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
		return false
	}

	if tool == "terraform" || strings.HasPrefix(arg, "--") {
		return infrastructureValueOption(tool, arg)
	}

	for i := 1; i < len(arg); i++ {
		if infrastructureValueOption(tool, "-"+arg[i:i+1]) {
			return i+1 == len(arg)
		}
	}

	return false
}

func infrastructureValueOption(tool, flag string) bool {
	if infrastructureOption(tool, flag) {
		return true
	}

	switch tool {
	case "kubectl":
		return slices.Contains([]string{"-f", "--filename", "-k", "--kustomize", "-p", "--patch", "--patch-file", "-o", "--output", "-l", "--selector", "--field-selector", "--resource-version", "--field-manager", "--timeout"}, flag)
	case "helm":
		return slices.Contains([]string{"-f", "--values", "--set", "--set-string", "--set-file", "--set-json", "--timeout", "--version", "--description", "--post-renderer", "--kube-token", "--username", "--password", "--repo", "--keyring"}, flag)
	case "terraform":
		return slices.Contains([]string{"-var", "-var-file", "-state", "-state-out", "-backup", "-target", "-replace", "-parallelism", "-lock-timeout"}, flag)
	default:
		return false
	}
}
