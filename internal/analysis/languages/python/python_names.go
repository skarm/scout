// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified bounded, non-executing Python analysis.

package python

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/frontend"
)

//nolint:gochecknoglobals // Read-only Python semantic classification tables are shared by scans.
var pyNamedConstructors = map[string]string{
	"pathlib.Path":                  "pathlib.Path",
	"socket.socket":                 "socket.socket",
	"requests.Session":              "requests.Session",
	"httpx.Client":                  "httpx.Client",
	"httpx.AsyncClient":             "httpx.AsyncClient",
	"urllib.request.build_opener":   "urllib.request.OpenerDirector",
	"urllib.request.OpenerDirector": "urllib.request.OpenerDirector",
}

// dictionaryCall exposes only the recognized reflection grammar; all callers
// resolve the same object and first key without reimplementing its shape.
func dictionaryCall(n *frontend.Node) (*frontend.Node, *frontend.Node) {
	fn := n.Child(frontend.Func)

	args := n.List(frontend.Args)
	if fn == nil || fn.Kind() != frontend.Attribute || !pyDictionaryRead(fn.String(frontend.Attr)) || len(args) == 0 {
		return nil, nil
	}

	return fn.Child(frontend.FieldValue), args[0]
}

// nestedSource projects source shape using identities captured when those
// exact call nodes were evaluated. It never resolves names or repeats effects.
func (w *pyWalker) nestedSource(n *frontend.Node, depth int) bool {
	if n == nil || depth > 32 || !w.charge(depth) {
		return false
	}

	if n.Kind() == frontend.Call && w.chainCalls[n] {
		return true
	}

	for _, child := range n.Children() {
		if w.nestedSource(child, depth+1) {
			return true
		}
	}

	return false
}

func canonPy(n string) string {
	n = strings.TrimPrefix(n, "builtins.")
	for _, prefix := range []string{"requests.Session.", "httpx.Client.", "httpx.AsyncClient."} {
		if after, ok := strings.CutPrefix(n, prefix); ok {
			n = strings.Split(prefix, ".")[0] + "." + after
		}
	}

	if n == "urllib.request.OpenerDirector.open" {
		return "urllib.request.urlopen"
	}

	return n
}

func pyNestedSourceName(name string) bool {
	if name == "compile" || name == "__import__" {
		return true
	}

	for _, prefix := range []string{"subprocess.", "os.", "base64.", "codecs.", "marshal.", "urllib.", "requests.", "httpx."} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}
