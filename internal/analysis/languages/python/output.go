// SPDX-License-Identifier: Apache-2.0

package python

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/frontend"
)

//nolint:gochecknoglobals // Read-only Python semantic classification tables are shared by scans.
var pythonOutputNames = map[string]bool{
	"response":   true,
	"output":     true,
	"result":     true,
	"answer":     true,
	"completion": true,
	"reply":      true,
	"generated":  true,
}

type pythonOutputSearch struct{ count int }

func pythonOutputArgument(name string, call *frontend.Node) bool {
	arguments := call.List(frontend.Args)
	if len(arguments) > 1 {
		arguments = arguments[:1]
	}

	allowed := pythonOutputKeywords(name)

	for _, k := range call.List(frontend.Keywords) {
		if strings.HasPrefix(name, "subprocess.") && allowed[k.String(frontend.FieldArg)] {
			arguments = append(arguments, k.Child(frontend.FieldValue))
		}
	}

	search := pythonOutputSearch{}
	for _, a := range arguments {
		if search.hasName(a, 0) {
			return true
		}
	}

	return false
}

func (s *pythonOutputSearch) hasName(n *frontend.Node, depth int) bool {
	s.count++
	if n == nil || depth > 32 || s.count > 8192 {
		return false
	}

	if n.Kind() == frontend.Name && pythonOutputNames[n.String(frontend.ID)] {
		return true
	}

	for _, c := range n.Children() {
		if s.hasName(c, depth+1) {
			return true
		}
	}

	return false
}

func pythonOutputKeywords(name string) map[string]bool {
	switch name {
	case "subprocess.getoutput", "subprocess.getstatusoutput":
		return map[string]bool{"cmd": true}
	case "subprocess.run", "subprocess.check_output":
		return map[string]bool{"args": true, "executable": true, "input": true}
	default:
		return map[string]bool{"args": true, "executable": true}
	}
}
