// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Bounded shell-token projection for declared hook arguments.

package shell

import (
	"context"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var symbolicHomePrefixes = map[string]bool{"": true, "@": true}

// UploadArgv projects one declared command without resolving names or executing it.
func UploadArgv(ctx context.Context, command string, sensitiveFile func(string) bool) ([]string, bool) {
	argv := make([]string, 0)

	tree, e := shellsyntax.Parse(ctx, command)
	if e != nil || len(tree.Statements) != 1 {
		return nil, false
	}

	stmt := tree.Statements[0]
	if len(stmt.Commands) != 1 {
		return nil, false
	}

	c := stmt.Commands[0]
	if len(c.Assignments) > 0 || len(c.Redirects) > 0 || c.Subshell != nil {
		return nil, false
	}

	for _, word := range c.Words {
		s, ok := hookUploadWord(word, sensitiveFile)
		if !ok {
			return nil, false
		}

		argv = append(argv, s)
	}

	return argv, true
}

// An abstract HOME anchor models the package's declared home-relative operand;
// it does not read the scanner's environment or evaluate arbitrary expansion.
func hookUploadWord(word *shellsyntax.Word, sensitiveFile func(string) bool) (string, bool) {
	if v, ok := word.Literal(); ok {
		return v, true
	}

	var b strings.Builder

	home := false

	for _, p := range word.Parts {
		switch p.Kind {
		case "literal":
			b.WriteString(p.Text)
		case "parameter":
			if p.Text != "HOME" || !symbolicHomePrefixes[b.String()] {
				return "", false
			}

			home = true

			b.WriteString("/home/scout-symbolic-home")
		default:
			return "", false
		}
	}

	v := b.String()

	return v, home && sensitiveFile(strings.TrimPrefix(v, "@"))
}
