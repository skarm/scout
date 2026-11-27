package shell

import (
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

const maxCloudDirectionBytes = 4096

// CloudDownloadExempt only discounts an E5 occurrence covered by a complete
// literal shell command. Earlier commands can redefine the launcher or change
// the destination, so only a small inert preamble is admitted.
func CloudDownloadExempt(doc document.File, match check.Match) bool {
	for _, unit := range doc.Units() {
		if match.Start < unit.Span.Start || match.End > unit.Span.End || match.End-unit.Span.Start > maxCloudDirectionBytes {
			continue
		}

		parsed, ok := unit.Tree.(parse.ShellTree)
		if ok && parsed.ExecutionError == nil && parsed.Tree != nil && !parsed.Tree.OmittedExecution &&
			safeCloudShebang(unit.View.Text()) && shellCloudDownload(unit, parsed.Tree, match) {
			return true
		}
	}

	return false
}

func safeCloudShebang(text string) bool {
	if !strings.HasPrefix(text, "#!") {
		return true
	}

	line, _, _ := strings.Cut(text[2:], "\n")

	args := strings.Fields(line)
	if len(args) == 0 {
		return false
	}

	switch args[0] {
	case "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash":
		return len(args) == 1
	case "/usr/bin/env", "/bin/env":
		return len(args) == 2 && slices.Contains([]string{"sh", "bash", "zsh", "dash"}, args[1])
	default:
		return false
	}
}

func shellCloudDownload(unit document.Unit, tree *shellsyntax.File, match check.Match) bool {
	changedDir := false

	for _, statement := range tree.Statements {
		words, span, ok := cloudLiteralStatement(unit.View, statement)
		if !ok || span.End-unit.Span.Start > maxCloudDirectionBytes {
			return false
		}

		if span.Start <= match.Start && match.End <= span.End {
			return span.Start == match.Start && isCloudDownload(words, changedDir)
		}

		if span.End > match.Start {
			return false
		}

		switch {
		case len(words) == 2 && words[0] == "cd" && localCloudPath(words[1]):
			changedDir = true
		case slices.Equal(words, []string{"set", "-o", "pipefail"}):
		case len(words) == 2 && words[0] == "set" && safeCloudSet(words[1]):
		default:
			return false
		}
	}

	return false
}

func cloudLiteralStatement(view source.View, s *shellsyntax.Statement) ([]string, source.Span, bool) {
	if len(s.Commands) != 1 || s.Negated || s.Background || s.Next != "" && s.Next != "newline" {
		return nil, source.Span{}, false
	}

	command := s.Commands[0]
	if len(command.Words) == 0 || len(command.Assignments)+len(command.Redirects) != 0 ||
		command.FunctionBody != nil || command.Subshell != nil || command.Group != nil || command.Prelude != nil || len(command.Alternatives) != 0 {
		return nil, source.Span{}, false
	}

	span, err := view.Original(command.Span)
	if err != nil {
		return nil, source.Span{}, false
	}

	words := make([]string, 0, len(command.Words))
	for _, word := range command.Words {
		text, known := word.Literal()
		if !known || text == "" || strings.ContainsAny(text, "\r\n") {
			return nil, source.Span{}, false
		}

		words = append(words, text)
	}

	return words, span, true
}

func safeCloudSet(value string) bool {
	flags, ok := strings.CutPrefix(value, "-")
	return ok && flags != "" && !strings.ContainsFunc(flags, func(r rune) bool { return r != 'e' && r != 'f' && r != 'u' })
}

func isCloudDownload(words []string, changedDir bool) bool {
	scheme, args, allowedFlags := cloudCommand(words)
	if scheme == "" {
		return false
	}

	var operands []string

	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
		} else if !slices.Contains(allowedFlags, arg) {
			return false
		}
	}

	if len(operands) != 2 || !localCloudPath(operands[1]) || changedDir && !strings.HasPrefix(operands[1], "/") {
		return false
	}

	remote, ok := strings.CutPrefix(operands[0], scheme)
	bucket, _, _ := strings.Cut(remote, "/")

	return ok && bucket != "" && len(bucket) <= 63 && !strings.ContainsFunc(bucket, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.'
	}) && cloudPathText(remote)
}

func cloudCommand(words []string) (scheme string, args, flags []string) {
	switch {
	case len(words) >= 3 && words[0] == "aws" && words[1] == "s3":
		flags := []string{"--quiet", "--no-progress", "--only-show-errors"}

		switch words[2] {
		case "cp":
			return "s3://", words[3:], append(flags, "--recursive")
		case "sync":
			return "s3://", words[3:], flags
		}
	case len(words) >= 2 && words[0] == "gsutil" && (words[1] == "cp" || words[1] == "rsync"):
		return "gs://", words[2:], []string{"-r"}
	}

	return "", nil, nil
}

func localCloudPath(path string) bool {
	return path != "" && !strings.HasPrefix(path, "-") && cloudPathText(path)
}

func cloudPathText(path string) bool {
	return !strings.ContainsFunc(path, func(r rune) bool {
		return r < ' ' || r > '~' || strings.ContainsRune(":\\\x60$%!*?[]{}~;&|<>#()", r)
	})
}
