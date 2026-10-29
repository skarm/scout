// Package language identifies candidate languages, not trusted file types or
// implemented analysis capabilities. Detection never suppresses byte checks.
package language

import (
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/report"
)

// Normalize also accepts conventional Markdown fence aliases. Unknown labels
// remain unknown, rather than becoming arbitrary output fields or parser names.
//
//nolint:gochecknoglobals // Read-only language alias metadata shared by document classification.
var aliases = map[string]string{
	"go":                  Go,
	"golang":              Go,
	"py":                  Python,
	"python":              Python,
	"python2":             Python,
	"python3":             Python,
	"sh":                  Shell,
	"bash":                Shell,
	"dash":                Shell,
	"zsh":                 Shell,
	"ksh":                 Shell,
	"shell":               Shell,
	"shellscript":         Shell,
	"js":                  JavaScript,
	"javascript":          JavaScript,
	"node":                JavaScript,
	"nodejs":              JavaScript,
	"jsx":                 JavaScript,
	"ts":                  TypeScript,
	"typescript":          TypeScript,
	"tsx":                 TypeScript,
	"ps1":                 PowerShell,
	"powershell":          PowerShell,
	"pwsh":                PowerShell,
	"bat":                 batch,
	"batch":               batch,
	"cmd":                 batch,
	"rb":                  Ruby,
	"ruby":                Ruby,
	"pl":                  Perl,
	"perl":                Perl,
	"php":                 PHP,
	"lua":                 Lua,
	"rs":                  Rust,
	"rust":                Rust,
	"c":                   C,
	"h":                   C,
	"cpp":                 CPP,
	"c++":                 CPP,
	"cxx":                 CPP,
	"cc":                  CPP,
	"hpp":                 CPP,
	"hxx":                 CPP,
	"cs":                  cSharp,
	"csharp":              cSharp,
	"c#":                  cSharp,
	"java":                Java,
	"kt":                  kotlin,
	"kts":                 kotlin,
	"kotlin":              kotlin,
	"swift":               swift,
	"r":                   r,
	"sql":                 SQL,
	"json":                JSON,
	"jsonl":               JSON,
	"ndjson":              JSON,
	"jsonc":               JSON,
	"json5":               JSON,
	"yaml":                YAML,
	"yml":                 YAML,
	"toml":                TOML,
	"xml":                 xml,
	"svg":                 xml,
	"html":                html,
	"htm":                 html,
	"ini":                 INI,
	"cfg":                 INI,
	"env":                 INI,
	"hcl":                 hcl,
	"tf":                  hcl,
	"tfvars":              hcl,
	"dockerfile":          dockerfile,
	"containerfile":       dockerfile,
	"makefile":            makefile,
	"make":                makefile,
	"gomod":               GoMod,
	"dependency-manifest": DependencyManifest,
	"md":                  Markdown,
	"markdown":            Markdown,
	"mdown":               Markdown,
	"txt":                 Text,
	"text":                Text,
	"plaintext":           Text,
	"output":              Text,
	"rst":                 Text,
	"csv":                 Text,
	"tsv":                 Text,
}

//nolint:gochecknoglobals // Read-only language alias metadata shared by document classification.
var extensionAliases = map[string]string{
	"mjs":   "js",
	"cjs":   "js",
	"mts":   "ts",
	"cts":   "ts",
	"pyw":   "py",
	"pyi":   "py",
	"psm1":  "ps1",
	"psd1":  "ps1",
	"phtml": PHP,
	"php3":  PHP,
	"php4":  PHP,
	"php5":  PHP,
	"php7":  PHP,
	"php8":  PHP,
	"rake":  Ruby,
}

//nolint:gochecknoglobals // Read-only language alias metadata shared by document classification.
var basenameLanguages = map[string]string{
	"dockerfile":       dockerfile,
	"containerfile":    dockerfile,
	"makefile":         makefile,
	"gnumakefile":      makefile,
	"gemfile":          Ruby,
	"rakefile":         Ruby,
	".bashrc":          Shell,
	".bash_profile":    Shell,
	".zshrc":           Shell,
	".profile":         Shell,
	".env":             INI,
	"go.mod":           GoMod,
	"uv.lock":          TOML,
	"poetry.lock":      TOML,
	"pipfile":          TOML,
	"cargo.lock":       TOML,
	"go.sum":           DependencyManifest,
	"requirements.txt": DependencyManifest,
	"pipfile.lock":     DependencyManifest,
	"readme":           Markdown,
	"license":          Text,
	"licence":          Text,
	"copying":          Text,
	"notice":           Text,
}

// Hint contains only scanner-owned labels; source excerpts are never echoed.
type Hint = report.LanguageHint

func Normalize(s string) string {
	if id, ok := aliases[strings.ToLower(s)]; ok {
		return id
	}

	return Unknown
}

func Structured(id string) bool {
	return id != Unknown && id != Text && id != Markdown
}

// Detect preserves conflicting candidates instead of trusting one declaration.
// Content heuristics are intentionally narrow; this is not language recognition.
func Detect(name, data string) []Hint {
	var out []Hint

	add := func(id, basis string) {
		if id != Unknown {
			out = append(out, Hint{Language: id, Basis: basis})
		}
	}
	base := strings.ToLower(path.Base(name))

	ext := strings.TrimPrefix(strings.ToLower(path.Ext(base)), ".")
	if alias, ok := extensionAliases[ext]; ok {
		ext = alias
	}

	add(Normalize(ext), "extension")

	if id, ok := basenameLanguages[base]; ok {
		add(id, "basename")
	}

	prefix := data
	if len(prefix) > 512 {
		prefix = prefix[:512]
	}

	prefix = strings.TrimPrefix(prefix, "\ufeff")
	if hint, ok := shebangHint(prefix); ok {
		add(hint.Language, hint.Basis)
	}

	out = append(out, prefixHints(prefix)...)

	return out
}

func shebangHint(prefix string) (Hint, bool) {
	if !strings.HasPrefix(prefix, "#!") {
		return Hint{}, false
	}

	line, _, _ := strings.Cut(prefix[2:], "\n")
	fields := strings.Fields(line)
	// Only fixed tokens are recognized; options and assignments are never executed.
	for _, field := range fields {
		if strings.HasPrefix(field, "-") || strings.Contains(field, "=") {
			continue
		}

		exe := path.Base(field)
		if exe == "uv" {
			return Hint{Language: Python, Basis: "uv-shebang"}, slices.Contains(fields, "run")
		}

		if exe == "env" {
			continue
		}

		id := Normalize(exe)
		if strings.HasPrefix(exe, "python2.") || strings.HasPrefix(exe, "python3.") {
			id = Python
		}

		if Structured(id) {
			return Hint{Language: id, Basis: "shebang"}, true
		}
	}

	return Hint{}, false
}

func prefixHints(prefix string) []Hint {
	var out []Hint

	add := func(id, basis string) { out = append(out, Hint{Language: id, Basis: basis}) }
	trimmed := strings.TrimSpace(prefix)
	// JSON can be renamed or embedded in an otherwise unrecognized file. This
	// is only a candidate; syntax and duplicate keys are checked by the backend.
	if len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') {
		next := strings.TrimSpace(trimmed[1:])
		if strings.HasPrefix(next, "\"") || strings.HasPrefix(next, "{") {
			add(JSON, "content-prefix")
		}
	}

	if strings.HasPrefix(trimmed, "<?php") {
		add(PHP, "content-prefix")
	}
	// A renamed Go file can still reach the Go parser. This is only a candidate:
	// the parser will reject false positives and preserve incomplete coverage.
	if strings.HasPrefix(trimmed, "package ") {
		line, _, _ := strings.Cut(trimmed, "\n")
		if !strings.Contains(line, ";") {
			add(Go, "content-prefix")
		}
	}

	return out
}
