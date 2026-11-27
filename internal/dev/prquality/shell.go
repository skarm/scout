package main

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type shellWord struct {
	text    string
	literal bool
	line    int
}

func (i inventory) readShell(key commandKey, firstLine int, script, directory string) (bool, error) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(script), key.path)
	if err != nil {
		return false, fmt.Errorf("parse shell in %s at line %d: %w", key.path, firstLine, err)
	}

	hasTests := false

	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}

		args := make([]shellWord, 0, len(call.Args))
		for _, arg := range call.Args {
			text, literal := shellText(script, arg.Parts, false)
			args = append(args, shellWord{text, literal, firstLine + int(arg.Pos().Line()) - 1})
		}

		hasTests = i.readCall(key, directory, unwrapGo(args)) || hasTests

		return true
	})

	return hasTests, nil
}

func shellText(script string, parts []syntax.WordPart, quoted bool) (string, bool) {
	var text strings.Builder

	literal := true

	for _, part := range parts {
		switch value := part.(type) {
		case *syntax.Lit:
			writeShellLiteral(&text, value.Value, quoted)
		case *syntax.SglQuoted:
			text.WriteString(value.Value)
			literal = literal && !value.Dollar
		case *syntax.DblQuoted:
			nested, ok := shellText(script, value.Parts, true)
			text.WriteString(nested)

			literal = literal && ok && !value.Dollar
		default:
			text.WriteString(script[part.Pos().Offset():part.End().Offset()])

			literal = false
		}
	}

	return text.String(), literal
}

func writeShellLiteral(out *strings.Builder, value string, quoted bool) {
	for index := 0; index < len(value); index++ {
		ch := value[index]
		if ch == '\\' && index+1 < len(value) && (!quoted || strings.ContainsRune("$`\\\"\n", rune(value[index+1]))) {
			index++

			ch = value[index]
			if ch == '\n' {
				continue
			}
		}

		out.WriteByte(ch)
	}
}

func unwrapGo(args []shellWord) []shellWord {
	if args[0].text == "scout-native" {
		return args[1:]
	}

	if len(args) > 2 && path.Base(args[0].text) == "go" && args[1].text == "run" {
		for index, arg := range args[2:] {
			if arg.text == "./internal/dev/builddeps" {
				tail := args[index+3:]
				if len(tail) > 0 && tail[0].text == "--" {
					tail = tail[1:]
				}

				return tail
			}
		}
	}

	return args
}

func (i inventory) readCall(key commandKey, directory string, words []shellWord) bool {
	if len(words) == 0 {
		return false
	}

	kind := path.Base(words[0].text)

	args := words[1:]
	if kind == "jq" {
		return i.readJQ(key, args)
	}

	if kind == "scout-dev" && len(args) > 0 && args[0].text == "evaluate" {
		i.readEvaluationFlags(key, args[1:])
		return true
	}

	switch kind {
	case "go":
		var ok bool

		args, ok = goTestArgs(args)
		if !ok {
			return false
		}
	case "node":
		index := slices.IndexFunc(args, func(arg shellWord) bool { return arg.text == "--test" })
		if index == -1 {
			return false
		}

		args = slices.Delete(args, index, index+1)
	case "make":
	default:
		return false
	}

	cmd, ok := parseTestCommand(location{key.path, words[0].line}, kind, directory, args)
	if ok {
		i.commands[key] = append(i.commands[key], cmd)
	}

	return ok
}

func goTestArgs(args []shellWord) ([]shellWord, bool) {
	if len(args) == 0 {
		return nil, false
	}

	if args[0].text == "test" {
		return args[1:], true
	}

	switch {
	case len(args) >= 3 && args[0].text == "-C" && args[2].text == "test":
		return slices.Concat(args[:2], args[3:]), true
	case len(args) >= 2 && strings.HasPrefix(args[0].text, "-C=") && args[1].text == "test":
		return slices.Concat(args[:1], args[2:]), true
	default:
		return nil, false
	}
}

func asciiLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

func asciiDigit(r rune) bool { return r >= '0' && r <= '9' }
