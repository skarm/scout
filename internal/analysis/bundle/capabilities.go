package bundle

import (
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/report"
)

// These observations use the same resolved bindings and original source spans
// as bundle flow analysis. They never change ordinary per-target findings.
func (b *bundleAnalysis) observeCallCapabilities(p *bundleProgram, n *bundleNode, callee bundleValue, args []bundleValue, ref report.SourceRef) {
	if b.surface == nil {
		return
	}

	name := callee.name
	if capabilityExecution(p.language, name) {
		b.surfaceFact("command_execution", "", p.file, ref)

		if literals.InfrastructureMutation(capabilityArgv(p, n, name, args)) {
			b.surfaceFact("infrastructure_mutation", "", p.file, ref)
		}
	}

	if capabilityFileWrite(p, n, name, args) {
		b.surfaceFact("file_write", "", p.file, ref)
	}

	if p.language == language.Python && name == "input" {
		b.surfaceFact("untrusted_input", "", p.file, ref)
	}

	if capabilityExternalInput(p.language, name) {
		b.surfaceFact("untrusted_input", "", p.file, ref)
	}
}

func capabilityExternalInput(lang, name string) bool {
	if _, ok := bundleNetwork(name); !ok {
		return false
	}

	switch lang {
	case language.Go:
		return name == "net/http.Get" || name == "net/http.Post" || name == "net/http.PostForm"
	case language.JavaScript, language.TypeScript:
		return name == "fetch" || name == "globalThis.fetch" || name == "axios" || strings.HasPrefix(name, "axios.") || name == "http.get" || name == "https.get"
	case language.Python:
		return strings.HasPrefix(name, "requests.") || strings.HasPrefix(name, "httpx.") || name == "urllib.request.urlopen"
	default:
		return false
	}
}

func capabilityExecution(lang, name string) bool {
	switch lang {
	case language.Go:
		return name == "os/exec.Command" || name == "os/exec.CommandContext"
	case language.JavaScript, language.TypeScript:
		return slices.Contains([]string{"eval", "globalThis.eval", "Function", "child_process.exec", "child_process.execSync", "child_process.spawn", "child_process.spawnSync", "child_process.execFile", "child_process.execFileSync", "vm.runInNewContext", "vm.runInThisContext"}, name)
	case language.Python:
		return slices.Contains([]string{"eval", "exec", "os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput"}, name)
	default:
		return false
	}
}

func capabilityFileWrite(p *bundleProgram, n *bundleNode, name string, args []bundleValue) bool {
	switch p.language {
	case language.Go:
		return slices.Contains([]string{"os.WriteFile", "io/ioutil.WriteFile", "os.Create", "os.Mkdir", "os.MkdirAll", "os.Remove", "os.RemoveAll", "os.Rename", "os.Truncate", "os.Chmod", "os.Chown", "os.Symlink", "os.Link"}, name)
	case language.JavaScript, language.TypeScript:
		for _, prefix := range []string{"fs.", "fs.promises.", "fs/promises."} {
			if method, ok := strings.CutPrefix(name, prefix); ok && slices.Contains([]string{"writeFile", "writeFileSync", "appendFile", "appendFileSync", "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "mkdir", "mkdirSync", "rename", "renameSync", "copyFile", "copyFileSync", "truncate", "truncateSync", "chmod", "chmodSync", "chown", "chownSync", "symlink", "symlinkSync", "link", "linkSync", "createWriteStream"}, method) {
				return true
			}
		}
	case language.Python:
		if name == "open" || name == "io.open" || name == "builtins.open" {
			mode, _, ok := capabilityArgument(n, args, 1, "mode")
			return ok && mode.known && capabilityWriteMode(mode.text)
		}

		return slices.Contains([]string{"os.remove", "os.unlink", "os.rename", "os.replace", "os.mkdir", "os.makedirs", "os.rmdir", "os.chmod", "os.chown", "os.symlink", "os.link", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move", "shutil.rmtree"}, name)
	}

	return false
}

func capabilityWriteMode(mode string) bool {
	base := strings.Trim(mode, "bt+")

	return len(base) == 1 && strings.ContainsAny(base, "rwax") && strings.HasPrefix(mode, base) &&
		strings.ContainsAny(mode, "wax+") && strings.Count(mode, "+") <= 1 && strings.Count(mode, "b")+strings.Count(mode, "t") <= 1
}

func capabilityArgument(n *bundleNode, args []bundleValue, position int, keyword string) (bundleValue, int, bool) {
	index := -1

	for i := range args {
		key := ""
		if i < len(n.argumentNames) {
			key = n.argumentNames[i]
		}

		if key == "*" {
			return bundleValue{}, -1, false
		}

		if key == keyword || i == position && key == "" {
			if index >= 0 {
				return bundleValue{}, -1, false
			}

			index = i
		}
	}

	if index < 0 {
		return bundleValue{}, -1, false
	}

	return args[index], index, true
}

func capabilityArgv(p *bundleProgram, n *bundleNode, name string, args []bundleValue) []string {
	if len(args) == 0 {
		return nil
	}

	switch p.language {
	case language.Python:
		if !strings.HasPrefix(name, "subprocess.") {
			return nil
		}

		// shell=True changes list argv into shell positional parameters;
		// executable can replace the actual program independently of argv[0].
		// Keep the command capability, but do not infer infrastructure verbs.
		if slices.Contains(n.argumentNames, "shell") || slices.Contains(n.argumentNames, "executable") {
			return nil
		}

		for i, key := range n.argumentNames {
			if i > 0 && key == "" {
				return nil
			}
		}

		value, index, ok := capabilityArgument(n, args, 0, "args")
		if !ok || len(value.items) == 0 || !capabilityInlineArray(n, index) {
			return nil
		}

		args = value.items
	case language.JavaScript, language.TypeScript:
		if name != "child_process.spawn" && name != "child_process.spawnSync" && name != "child_process.execFile" && name != "child_process.execFileSync" {
			return nil
		}

		if len(args) > 1 {
			if !capabilityInlineArray(n, 1) {
				return nil
			}

			args = append([]bundleValue{args[0]}, args[1].items...)
		}
	case language.Go:
		if name == "os/exec.CommandContext" {
			args = args[1:]
		}
	default:
		return nil
	}

	argv := make([]string, len(args))
	for i, arg := range args {
		if arg.known {
			argv[i] = arg.text
		}
	}

	return argv
}

func capabilityInlineArray(n *bundleNode, index int) bool {
	return index >= 0 && index+1 < len(n.children) && n.children[index+1] != nil && n.children[index+1].kind == nodeArray
}
