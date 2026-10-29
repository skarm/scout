//go:build !coreonly && cgo

package signatures

import (
	"regexp"
	"strings"
)

const (
	pythonSocketPattern       = "$py_sock"
	pythonShellAliasPattern   = "$py_shell_alias"
	pythonSocketStreamPattern = "$py_redir_object"
)

// These finite source spellings refine YARA candidates, without importing or
// executing Python. They do not resolve arbitrary Python scopes or expressions.
var (
	pythonAliasedImport = regexp.MustCompile(`\bimport[ \t]+([A-Za-z_][A-Za-z0-9_.]{0,127})[ \t]+as[ \t]+([A-Za-z_][A-Za-z0-9_]{0,63})\b`)
	pythonAssignment    = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]{0,63})[ \t]*=[ \t]*[^= \t]`)
	pythonSocketBinding = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]{0,63})[ \t]*=[ \t]*socket\.socket\([^\r\n)]{0,200}\bSOCK_STREAM\b[^\r\n)]{0,200}\)`)
	pythonSocketConnect = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]{0,63})[ \t]*\.connect[ \t]*\(`)
)

func (s nativeSource) pythonShellAlias(span Span) bool {
	receiver, _, _ := strings.Cut(s.text[span.Start:span.End], ".")
	window := s.text[max(0, span.Start-4096):span.Start]

	if strings.HasSuffix(strings.TrimRight(window, " \t\r\n"), ".") {
		return false
	}

	module, imported := "", -1

	for _, match := range pythonAliasedImport.FindAllStringSubmatchIndex(window, -1) {
		if window[match[4]:match[5]] == receiver {
			module, imported = window[match[2]:match[3]], match[0]
		}
	}

	return module == "subprocess" && imported > lastPythonAssignment(window, receiver)
}

func (s nativeSource) pythonSocketStream(span Span) bool {
	_, value, _ := strings.Cut(s.text[span.Start:span.End], "=")
	name := strings.TrimSpace(strings.TrimRight(value, ",)"))
	window := s.text[max(0, span.Start-4096):span.Start]
	assigned := lastPythonAssignment(window, name)

	for _, binding := range pythonSocketBinding.FindAllStringSubmatchIndex(window, -1) {
		if binding[0] == assigned && window[binding[2]:binding[3]] == name {
			return connectedPythonSocket(window[binding[1]:], name)
		}
	}

	return false
}

func lastPythonAssignment(text, name string) int {
	last := -1

	for _, match := range pythonAssignment.FindAllStringSubmatchIndex(text, -1) {
		if text[match[2]:match[3]] == name {
			last = match[0]
		}
	}

	return last
}

func connectedPythonSocket(text, name string) bool {
	for _, match := range pythonSocketConnect.FindAllStringSubmatchIndex(text, -1) {
		if text[match[2]:match[3]] == name {
			return true
		}
	}

	return false
}
