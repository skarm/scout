package shell

import (
	"errors"
	"net/url"
	"path"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

var errShellFileBudget = errors.New("shell file provenance budget exceeded")

func (s *shellState) fileKey(v shellValue) string {
	if !v.known || v.text == "" || v.text == "-" {
		return ""
	}

	if path.IsAbs(v.text) {
		return path.Clean(v.text)
	}

	if s.cwd == "" {
		return ""
	}

	if path.IsAbs(s.cwd) {
		return path.Join(s.cwd, v.text)
	}

	return path.Join("@relative", s.cwd, v.text)
}

func (s *shellState) fileOrigin(v shellValue) *shellOrigin { return s.files[s.fileKey(v)] }

func (a *shellWalk) changeDirectory(s *shellState, args []shellValue) {
	if len(args) == 1 && args[0].known && s.cwd != "" {
		s.cwd = path.Join(s.cwd, args[0].text)
		if path.IsAbs(args[0].text) {
			s.cwd = path.Clean(args[0].text)
		}

		return
	}

	s.cwd = ""
	if len(s.files) > 0 {
		a.gap = errors.New("downloaded file directory is unresolved")
	}
}

func (a *shellWalk) writeFile(s *shellState, target shellValue, origin *shellOrigin) {
	key := s.fileKey(target)
	if key == "" {
		if origin != nil && (!target.known || target.text != "-") {
			a.gap = errors.New("downloaded file destination is unresolved")
		}

		return
	}

	if origin == nil {
		if !s.mayWrite {
			delete(s.files, key)
		}

		return
	}

	if len(s.files) >= MaxShellBindings && s.files[key] == nil {
		a.err = errShellFileBudget
		return
	}

	s.files[key] = origin
}

func (a *shellWalk) writeRedirected(c *shellsyntax.Command, s *shellState, out shellValue) {
	for _, r := range c.Redirects {
		spec := shellRedirects[r.Op]
		if !spec.output || !spec.applies(r.FD) {
			continue
		}

		target := a.word(r.Target, s)
		// Appending known local bytes cannot erase a downloaded prefix.
		if r.Op == ">>" && out.download == nil {
			continue
		}

		a.writeFile(s, target, a.via(out.download, r.Span))
	}
}

func (a *shellWalk) copyFile(s *shellState, args []shellValue, move bool) {
	args = stripShellDoubleDash(args)
	if len(args) != 2 || !args[0].known || strings.HasPrefix(args[0].text, "-") {
		return
	}

	if s.fileKey(args[0]) == s.fileKey(args[1]) {
		return
	}

	a.writeFile(s, args[1], s.fileOrigin(args[0]))

	if move {
		a.writeFile(s, args[0], nil)
	}
}

func (a *shellWalk) fileExecution(c *shellsyntax.Command, s *shellState, name string, args []shellValue) {
	var file shellValue

	switch name {
	case "sh", "bash", "dash", "zsh", "ksh":
		file = shellScriptFile(args)
	case "source", ".":
		if len(args) > 0 {
			file = args[0]
		}
	case "python", "python3", "python2", "node", "nodejs", "tsx", "ts-node", "perl", "ruby":
		if len(args) > 0 && args[0].known && !strings.HasPrefix(args[0].text, "-") {
			file = args[0]
		}
	default:
		// The invocation basename is a candidate; retain the original path.
		for _, w := range c.Words {
			v := a.word(w, s)
			if v.known && path.Base(v.text) == name {
				file = v
				break
			}
		}
	}

	if origin := s.fileOrigin(file); origin != nil {
		a.emit(ruleSH001, c.Span, origin)
	}
}

func shellScriptFile(args []shellValue) shellValue {
	state := shellExecutionState{}

	for i := range args {
		v := args[i]
		switch classifyShellExecution(v) {
		case shellExecutionInvalid:
			return shellValue{}
		case shellExecutionEnd:
			if i+1 < len(args) && !state.noexec && !state.stdin {
				return args[i+1]
			}

			return shellValue{}
		case shellExecutionSkip:
			continue
		case shellExecutionShort:
			command, valid := state.commandIndex(args, i)
			if !valid || command >= 0 {
				return shellValue{}
			}
		default:
			if !state.noexec && !state.stdin {
				return v
			}

			return shellValue{}
		}
	}

	return shellValue{}
}

// Download-to-file needs one known URL and one known destination. Unsupported
// wget flags do not shift operands or invent filesystem facts.
func wgetFile(args []shellValue) (string, bool) {
	target, remote, urls := "", "", 0

	for i := 0; i < len(args); i++ {
		v := args[i]
		if !v.known {
			return "", false
		}

		switch wgetOption(v) {
		case wgetInvalid:
			return "", false
		case wgetSkip:
		case wgetOutput:
			i++
			if i >= len(args) || !args[i].known {
				return "", false
			}

			target = args[i].text
		case wgetInlineOutput:
			target = strings.TrimPrefix(v.text, "--output-document=")
		case wgetShort:
			var valid bool

			target, i, valid = wgetFileShort(v.text[1:], args, i, target)
			if !valid {
				return "", false
			}
		default:
			urls++

			if httpURL(v.text) {
				remote = v.text
			}
		}
	}

	if urls != 1 || remote == "" || target == "-" {
		return "", false
	}

	if target == "" {
		u, err := url.Parse(remote)
		if err != nil || strings.HasSuffix(u.Path, "/") {
			return "", false
		}

		target = path.Base(u.Path)
	}

	return target, target != "" && target != "."
}

func wgetFileShort(flags string, args []shellValue, i int, target string) (string, int, bool) {
	for j := 0; j < len(flags); j++ {
		if flags[j] == 'O' {
			if j+1 < len(flags) {
				target = flags[j+1:]
			} else {
				i++
				if i >= len(args) || !args[i].known {
					return "", i, false
				}

				target = args[i].text
			}

			break
		}

		if !strings.ContainsRune("qnv", rune(flags[j])) {
			return "", i, false
		}
	}

	return target, i, true
}
