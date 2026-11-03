package shell

import (
	"strings"

	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

func (a *shellWalk) capability(kind string, span source.Span) {
	if a.observeCapability != nil {
		a.observeCapability(kind, span)
	}
}

func (a *shellWalk) commandCapabilities(c *shellsyntax.Command, name string, args []shellValue, input shellValue) {
	if a.observeCapability == nil {
		return
	}

	argv := make([]string, len(args)+1)
	argv[0] = name

	for i, arg := range args {
		if arg.known {
			argv[i+1] = arg.text
		}
	}

	if literals.InfrastructureMutation(argv) {
		a.capability("infrastructure_mutation", c.Span)
	}

	switch name {
	case "eval", "source", ".":
		if shellBuiltinCodeOperand(args) {
			a.capability("command_execution", c.Span)
		}
	case "exec":
		if shellExecCommand(args) {
			a.capability("command_execution", c.Span)
		}
	case "sh", "bash", "dash", "zsh", "ksh":
		code, stdin := shellExecution(args)
		if code >= 0 || stdin || shellScriptFile(args).known {
			a.capability("command_execution", c.Span)
		}
	case "python", "python3", "node", "nodejs", "tsx", "ts-node", "perl", "ruby":
		if len(args) > 0 && args[0].known && (args[0].text == "-c" || args[0].text == "-e" || args[0].text == "--eval" || !strings.HasPrefix(args[0].text, "-")) {
			a.capability("command_execution", c.Span)
		}
	case "rm", "rmdir", "mkdir", "touch", "cp", "mv", "install", "chmod", "chown", "tee":
		if shellFileHelp(argv[1:]) {
			return
		}

		if shellFileOperand(args) {
			a.capability("file_write", c.Span)
		}
	case "read":
		if len(args) > 0 && args[0].known && args[0].text == "--help" {
			return
		}

		if !input.fixedInput || !shellReadStdin(args) {
			a.capability("untrusted_input", c.Span)
		}
	}
}

func shellBuiltinCodeOperand(args []shellValue) bool {
	if len(args) == 0 || args[0].known && args[0].text == "--help" {
		return false
	}

	return !args[0].known || args[0].text != "--" || len(args) > 1
}

func shellExecCommand(args []shellValue) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !arg.known || !strings.HasPrefix(arg.text, "-") || arg.text == "-" {
			return true
		}

		if arg.text == "--" {
			return i+1 < len(args)
		}

		flags := arg.text[1:]
		for j := 0; j < len(flags); j++ {
			switch flags[j] {
			case 'c', 'l':
			case 'a':
				if j+1 == len(flags) {
					i++
				}

				j = len(flags) // Remaining bytes are argv[0], not more flags.
			default:
				return false
			}
		}
	}

	return false
}

func shellFileOperand(args []shellValue) bool {
	ended := false
	for _, arg := range args {
		if ended {
			return true // The operand may be dynamic or start with a dash.
		}

		if arg.known && arg.text == "--" {
			ended = true
		} else if arg.known && arg.text != "" && !strings.HasPrefix(arg.text, "-") {
			return true
		}
	}

	return false
}

func shellReadStdin(args []shellValue) bool {
	for _, arg := range args {
		if !arg.known {
			return false
		}

		if arg.text == "--" {
			return true
		}

		if strings.HasPrefix(arg.text, "-") && arg.text != "-r" {
			return false // Other read options may select a different descriptor.
		}
	}

	return true
}

func shellFixedInputRedirect(redirect *shellsyntax.Redirect) bool {
	word := redirect.Target
	switch redirect.Op {
	case "<<", "<<-":
		word = redirect.Body
	case "<<<":
	default:
		return false
	}

	if word == nil || word.Expands {
		return false
	}

	for _, part := range word.Parts {
		if part.Kind != "literal" {
			return false
		}
	}

	return true
}

func shellFileHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}

		if arg == "--help" || arg == "--version" {
			return true
		}
	}

	return false
}

func (a *shellWalk) curlCapabilities(request curlRequest, span source.Span) {
	if a.observeCapability == nil || !request.valid || !request.remote {
		return
	}

	a.capability("untrusted_input", span)

	for _, target := range request.outputs {
		if target.known && target.text != "-" {
			a.fileCapability(">", target, span)
		}
	}
}

func (a *shellWalk) fileCapability(op string, target shellValue, span source.Span) {
	if a.observeCapability != nil && shellWritesFile(op, target) {
		a.capability("file_write", span)
	}
}

func shellWritesFile(op string, value shellValue) bool {
	if op == ">&" {
		if !value.known || value.text == "-" || strings.Trim(value.text, "0123456789") == "" {
			return false
		}
	}

	if value.known && (value.text == "/dev/null" || value.text == "/dev/stdout" || value.text == "/dev/stderr" || strings.HasPrefix(value.text, "/dev/fd/")) {
		return false
	}

	return true
}
